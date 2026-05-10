//! HTTP action dispatch with SSRF guard.
//!
//! Before issuing the request, [`check_target`] verifies:
//!
//! * The URL is parseable and uses `http` or `https` (no `file://`,
//!   `data:`, `gopher://`, etc.).
//! * The target host resolves to a public IP — unless
//!   `ActionsConfig::allow_private_targets` is set. Private,
//!   loopback, link-local, multicast, and unspecified ranges are all
//!   refused; that includes the cloud-metadata endpoint
//!   `169.254.169.254`.
//!
//! Note: a TOCTOU window exists between resolution here and the
//! actual connect inside reqwest. For Phase 1 the system resolver is
//! consulted both times so the answer is consistent in practice; a
//! pinned-IP custom resolver is a follow-up if a real exploit
//! scenario surfaces.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use reqwest::Method;

use super::{ActionRequest, ActionResult, ActionsConfig};

const MAX_RESPONSE_BYTES: usize = 16 * 1024;

pub async fn execute(action: &ActionRequest, cfg: &ActionsConfig) -> ActionResult {
    let start = Instant::now();

    if let Err(reason) = check_target(&action.target, cfg.allow_private_targets).await {
        return ActionResult {
            ok: false,
            status: 0,
            response: format!("blocked: {reason}"),
            latency_ms: elapsed_ms(start),
        };
    }

    let method = action.method.as_deref().unwrap_or("POST").to_uppercase();
    let parsed_method = match Method::from_bytes(method.as_bytes()) {
        Ok(m) => m,
        Err(_) => {
            return ActionResult {
                ok: false,
                status: 0,
                response: format!("invalid HTTP method: {method}"),
                latency_ms: elapsed_ms(start),
            };
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return ActionResult {
                ok: false,
                status: 0,
                response: format!("client build failed: {e}"),
                latency_ms: elapsed_ms(start),
            };
        }
    };

    let mut req = client.request(parsed_method, &action.target);
    for (k, v) in &action.headers {
        req = req.header(k, v);
    }
    if let Some(body) = &action.body {
        req = req.json(body);
    }

    match req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            let truncated = if text.len() > MAX_RESPONSE_BYTES {
                let mut t = text;
                t.truncate(MAX_RESPONSE_BYTES);
                t.push_str("…[truncated]");
                t
            } else {
                text
            };
            ActionResult {
                ok: status.is_success(),
                status: status.as_u16(),
                response: truncated,
                latency_ms: elapsed_ms(start),
            }
        }
        Err(e) => ActionResult {
            ok: false,
            status: 0,
            response: format!("transport error: {e}"),
            latency_ms: elapsed_ms(start),
        },
    }
}

/// Validate `url` for outbound dispatch. Returns the rejection reason
/// as a string, or `Ok(())` if the URL is safe to request.
pub(crate) async fn check_target(url: &str, allow_private: bool) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        s => return Err(format!("scheme `{s}` not allowed (http/https only)")),
    }
    if allow_private {
        return Ok(());
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| "URL missing host".to_string())?;
    let port = parsed.port_or_known_default().unwrap_or(80);

    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_blocked(ip) {
            return Err(format!(
                "target IP {ip} is blocked (private/loopback/link-local)"
            ));
        }
        return Ok(());
    }

    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("resolving {host}: {e}"))?;
    for addr in addrs {
        if is_blocked(addr.ip()) {
            return Err(format!(
                "target {host} resolves to blocked IP {}",
                addr.ip()
            ));
        }
    }
    Ok(())
}

fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
            // 169.254.169.254 = cloud metadata; covered by is_link_local
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // unique-local fc00::/7 — Ipv6Addr::is_unique_local is unstable
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // link-local fe80::/10 — Ipv6Addr::is_unicast_link_local is unstable
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

fn elapsed_ms(start: Instant) -> i64 {
    i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX)
}
