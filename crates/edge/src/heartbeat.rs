//! Edge → Control-Plane heartbeat client + grace-period state machine.
//!
//! On a configurable interval (default 24 h), the edge POSTs its hardware
//! fingerprint to `<cp_url>/api/v1/licenses/{id}/heartbeat`. A successful
//! response refreshes the local `last_seen_at`; on failure, the value is
//! left as is and the grace-period clock keeps ticking.
//!
//! The status decision is intentionally pulled out into [`compute_status`]
//! — a pure function over `(last_seen_at_ms, now_ms, grace_period_days)`
//! — so it can be exercised with a stubbed clock in tests without
//! spinning up an HTTP server.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseStatus {
    /// Within the grace window — all features available.
    Healthy,
    /// Grace window has expired without a successful heartbeat.
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LicenseHealthState {
    /// Server-recorded `last_seen` (unix ms). 0 / absent means "never
    /// heartbeated since this state file was created".
    #[serde(default)]
    pub last_seen_at: i64,
    /// Surrogate id returned by the Control Plane at activation time.
    /// Used as the path component on subsequent heartbeats. None when no
    /// activation has happened yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_license_id: Option<i64>,
    /// Hex-encoded heartbeat bearer secret returned at activation. The
    /// edge presents this as `Authorization: Bearer <token>` on every
    /// heartbeat. `None` means a legacy activation (pre-bearer-gate)
    /// — `spawn` will skip heartbeating in that case and the operator
    /// must re-run `admin activate` to re-issue.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_token: Option<String>,
}

/// Pure decision: is the license currently in the grace window or past it?
pub fn compute_status(last_seen_at_ms: i64, now_ms: i64, grace_period_days: u32) -> LicenseStatus {
    if last_seen_at_ms <= 0 {
        return LicenseStatus::Degraded;
    }
    let grace_ms = i64::from(grace_period_days).saturating_mul(86_400_000);
    if now_ms.saturating_sub(last_seen_at_ms) <= grace_ms {
        LicenseStatus::Healthy
    } else {
        LicenseStatus::Degraded
    }
}

#[derive(Debug, Serialize)]
struct HeartbeatRequest<'a> {
    hardware_fingerprint: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct HeartbeatResponse {
    pub last_seen: i64,
    pub expires_at: i64,
}

pub async fn post_heartbeat(
    cp_url: &str,
    issued_license_id: i64,
    hardware_fingerprint: &str,
    heartbeat_token: &str,
) -> anyhow::Result<HeartbeatResponse> {
    let url = format!(
        "{}/api/v1/licenses/{issued_license_id}/heartbeat",
        cp_url.trim_end_matches('/')
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
        .context("building heartbeat client")?;
    let resp = client
        .post(&url)
        .bearer_auth(heartbeat_token)
        .json(&HeartbeatRequest {
            hardware_fingerprint,
        })
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("heartbeat returned {status}: {body}");
    }
    let parsed: HeartbeatResponse = resp.json().await.context("parsing heartbeat response")?;
    Ok(parsed)
}

/// Persisted state, atomically written to `<license_path>.state.json`.
pub fn state_path_for(license_path: &Path) -> PathBuf {
    let mut name = std::ffi::OsString::from(
        license_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("license")),
    );
    name.push(".state.json");
    license_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(name)
}

pub fn load_state(path: &Path) -> anyhow::Result<LicenseHealthState> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).context("parsing license state")?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(LicenseHealthState::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

pub fn save_state(path: &Path, state: &LicenseHealthState) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec_pretty(state).context("serialising license state")?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp_name = std::ffi::OsString::from(
        path.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("state")),
    );
    tmp_name.push(format!(".tmp.{}", std::process::id()));
    let tmp = dir.join(tmp_name);
    std::fs::write(&tmp, &bytes).with_context(|| format!("writing {}", tmp.display()))?;
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} -> {}", tmp.display(), path.display()))?;
    Ok(())
}

/// Shared health view consumed by the runtime (and surfaced on /healthz
/// in a follow-up PR if needed).
#[derive(Debug, Clone)]
pub struct HealthHandle {
    inner: Arc<RwLock<LicenseHealthState>>,
    grace_period_days: u32,
}

impl HealthHandle {
    pub fn new(initial: LicenseHealthState, grace_period_days: u32) -> Self {
        Self {
            inner: Arc::new(RwLock::new(initial)),
            grace_period_days,
        }
    }

    pub async fn status(&self) -> LicenseStatus {
        let s = self.inner.read().await;
        compute_status(s.last_seen_at, now_ms(), self.grace_period_days)
    }

    pub async fn snapshot(&self) -> LicenseHealthState {
        self.inner.read().await.clone()
    }

    pub async fn record_success(&self, last_seen: i64) {
        self.inner.write().await.last_seen_at = last_seen;
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Spawn a background heartbeat loop. `interval` is the gap between
/// successive POSTs; the first tick fires immediately.
pub fn spawn(
    cp_url: String,
    issued_license_id: i64,
    fingerprint: String,
    heartbeat_token: String,
    interval: Duration,
    state_path: PathBuf,
    handle: HealthHandle,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            match post_heartbeat(&cp_url, issued_license_id, &fingerprint, &heartbeat_token).await {
                Ok(resp) => {
                    handle.record_success(resp.last_seen).await;
                    let snap = handle.snapshot().await;
                    if let Err(e) = save_state(&state_path, &snap) {
                        tracing::error!(error = ?e, path = %state_path.display(), "persisting heartbeat state");
                    } else {
                        tracing::debug!(last_seen = resp.last_seen, "heartbeat ok");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "heartbeat failed; grace clock keeps ticking");
                }
            }
        }
    })
}
