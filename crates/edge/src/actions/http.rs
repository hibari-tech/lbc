//! HTTP action dispatch.
//!
//! Trust note: rules are admin-authored (Manager+) so the URL is
//! coming from a reasonably trusted source. Even so, treat outbound
//! HTTP from a script as a potential SSRF vector against internal
//! services. **Phase 1 does not enforce a URL allow-list or block
//! private-IP destinations** — that's a TOFIX entry tagged
//! `actions-ssrf-guard`.

use std::time::{Duration, Instant};

use reqwest::Method;

use super::{ActionRequest, ActionResult};

const MAX_RESPONSE_BYTES: usize = 16 * 1024;

pub async fn execute(action: &ActionRequest) -> ActionResult {
    let start = Instant::now();

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

fn elapsed_ms(start: Instant) -> i64 {
    i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX)
}
