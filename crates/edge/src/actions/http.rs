//! HTTP action dispatch with SSRF guard.
//!
//! Before issuing the request, [`resolve_and_pin`] verifies:
//!
//! * The URL is parseable and uses `http` or `https` (no `file://`,
//!   `data:`, `gopher://`, etc.).
//! * The target host resolves to a public IP — unless
//!   `ActionsConfig::allow_private_targets` is set. Private,
//!   loopback, link-local, multicast, and unspecified ranges are all
//!   refused; that includes the cloud-metadata endpoint
//!   `169.254.169.254`.
//!
//! Closing the DNS-rebinding TOCTOU: when the target is a hostname,
//! `resolve_and_pin` resolves it once, validates every returned
//! address, and the addresses are passed straight to
//! `reqwest::ClientBuilder::resolve_to_addrs` so the connect step
//! dials exactly those IPs without re-consulting the resolver. A
//! racing rebind that returns a public IP for the validation lookup
//! and a private one for the connect can no longer slip through.
//! TLS SNI / cert validation still use the URL's hostname, so HTTPS
//! cert pinning is unaffected.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use reqwest::Method;

use super::{ActionRequest, ActionResult, ActionsConfig};

const MAX_RESPONSE_BYTES: usize = 16 * 1024;

pub async fn execute(action: &ActionRequest, cfg: &ActionsConfig) -> ActionResult {
    let start = Instant::now();

    let pinned = match resolve_and_pin(&action.target, cfg.allow_private_targets).await {
        Ok(p) => p,
        Err(reason) => {
            return ActionResult {
                ok: false,
                status: 0,
                response: format!("blocked: {reason}"),
                latency_ms: elapsed_ms(start),
            };
        }
    };

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

    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(15));
    if let Some((host, addrs)) = &pinned {
        // Pin the validated addresses into the client so reqwest's
        // connect step skips system DNS and uses these exact IPs.
        // This is the TOCTOU close.
        builder = builder.resolve_to_addrs(host, addrs);
    }
    let client = match builder.build() {
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

/// Validate `url` for outbound dispatch and return the resolved
/// `(host, addrs)` to pin into reqwest. `None` means no pinning is
/// needed — either the target is already a literal IP (nothing to
/// resolve) or `allow_private` is on (dev opt-in, gate skipped).
///
/// Returns the rejection reason as a string on failure.
pub(crate) async fn resolve_and_pin(
    url: &str,
    allow_private: bool,
) -> Result<Option<(String, Vec<SocketAddr>)>, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| format!("invalid URL: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        s => return Err(format!("scheme `{s}` not allowed (http/https only)")),
    }
    if allow_private {
        return Ok(None);
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
        return Ok(None);
    }

    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("resolving {host}: {e}"))?
        .collect();
    if addrs.is_empty() {
        return Err(format!("{host} resolved to no addresses"));
    }
    for addr in &addrs {
        if is_blocked(addr.ip()) {
            return Err(format!(
                "target {host} resolves to blocked IP {}",
                addr.ip()
            ));
        }
    }
    Ok(Some((host.to_string(), addrs)))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build a literal `SocketAddr` for assertion comparisons.
    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[tokio::test]
    async fn rejects_non_http_scheme() {
        let err = resolve_and_pin("file:///etc/passwd", false)
            .await
            .unwrap_err();
        assert!(err.contains("scheme"), "got {err:?}");
    }

    #[tokio::test]
    async fn allow_private_skips_pinning_entirely() {
        // With the gate disabled the function returns None regardless
        // of target — the operator opted into private targets.
        assert!(resolve_and_pin("http://127.0.0.1/", true)
            .await
            .unwrap()
            .is_none());
        assert!(resolve_and_pin("http://example.com/", true)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn literal_public_ip_passes_without_pinning() {
        // No DNS to pin for a literal IP — None is the correct shape.
        let pinned = resolve_and_pin("http://1.1.1.1/", false).await.unwrap();
        assert!(pinned.is_none());
    }

    #[tokio::test]
    async fn literal_loopback_is_blocked() {
        let err = resolve_and_pin("http://127.0.0.1/", false)
            .await
            .unwrap_err();
        assert!(err.contains("blocked"), "got {err:?}");
    }

    #[tokio::test]
    async fn literal_link_local_metadata_is_blocked() {
        let err = resolve_and_pin("http://169.254.169.254/", false)
            .await
            .unwrap_err();
        assert!(err.contains("blocked"), "got {err:?}");
    }

    #[tokio::test]
    async fn hostname_resolving_to_loopback_is_blocked() {
        // `localhost` is the one hostname that's reliably present
        // and resolves to loopback on every CI environment we care
        // about. After resolution, every returned addr is checked.
        let err = resolve_and_pin("http://localhost:1234/", false)
            .await
            .unwrap_err();
        assert!(err.contains("blocked"), "got {err:?}");
    }

    #[tokio::test]
    async fn pinning_carries_the_validated_addrs_into_reqwest() {
        // Hand-craft a pinning entry and prove that reqwest's
        // resolve_to_addrs actually overrides DNS: we dial an
        // unresolvable hostname, but pin it to 127.0.0.1, and a
        // loopback listener accepts the connection. This is the
        // exact mechanism execute() uses to close the TOCTOU.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let host = "pinned.example.invalid";
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Read whatever the client sends so the connect path
            // completes — we don't care about the contents.
            use tokio::io::AsyncReadExt as _;
            let mut buf = [0u8; 64];
            let _ = sock.read(&mut buf).await;
            // Minimal HTTP 200 so reqwest doesn't time out the
            // response parse.
            use tokio::io::AsyncWriteExt as _;
            let _ = sock
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        });

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .resolve_to_addrs(host, &[sa(&format!("127.0.0.1:{}", addr.port()))])
            .build()
            .unwrap();
        let resp = client
            .get(format!("http://{host}:{}/", addr.port()))
            .send()
            .await
            .expect("pinned connect");
        assert_eq!(resp.status(), 200);
        server.await.unwrap();
    }
}
