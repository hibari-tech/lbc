//! Control-Plane activation client.
//!
//! Posts the configured license key + branch identity + hardware
//! fingerprint to `<cp_url>/api/v1/licenses/activate` and returns the
//! signed license. Pure HTTP/JSON; no token is required for activation
//! (the cleartext key is the credential).

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use shared::license::SignedLicense;

#[derive(Debug, Serialize)]
pub struct ActivateRequest<'a> {
    pub license_key: &'a str,
    pub branch_name: &'a str,
    pub hardware_fingerprint: &'a str,
    /// Canonical-JSON of the multi-component fingerprint map. The
    /// Control Plane stores this for tolerant heartbeat matching;
    /// see `shared::fingerprint::compare_tolerant`. May be `""`
    /// on legacy edges, in which case the CP falls back to digest
    /// byte-compare.
    pub hardware_components: &'a str,
}

#[derive(Debug, Deserialize)]
pub struct ActivateResponse {
    pub issued_license_id: i64,
    pub branch_id: i64,
    pub license: SignedLicense,
    /// Hex-encoded heartbeat bearer secret. Returned once at
    /// activation; must be persisted by the caller and presented on
    /// every heartbeat. Losing it forces re-activation.
    pub heartbeat_token: String,
}

/// Send an activation request and return the parsed response. Caller is
/// responsible for persisting `response.license` and writing the
/// `branch_id` into local state if needed.
pub async fn activate(
    cp_url: &str,
    license_key: &str,
    branch_name: &str,
    hardware_fingerprint: &str,
    hardware_components: &str,
) -> anyhow::Result<ActivateResponse> {
    let url = format!("{}/api/v1/licenses/activate", cp_url.trim_end_matches('/'));
    let body = ActivateRequest {
        license_key,
        branch_name,
        hardware_fingerprint,
        hardware_components,
    };
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .context("building http client")?;
    let resp = client
        .post(&url)
        .json(&body)
        .send()
        .await
        .with_context(|| format!("POST {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        let text = resp.text().await.unwrap_or_default();
        anyhow::bail!("control plane returned {status}: {text}");
    }
    let parsed: ActivateResponse = resp.json().await.context("parsing activate response")?;
    Ok(parsed)
}
