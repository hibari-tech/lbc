//! HTTP Basic gate for the `/admin/*` routes.
//!
//! Phase-0 stopgap before OIDC (spec §4.9 / TOFIX). When the
//! configured `password_hash` is empty the middleware short-circuits
//! `next.run` immediately, so dev workflows keep working without
//! credentials — `lib::serve` logs a loud warn at boot in that
//! case. With a hash configured, every `/admin/*` request must
//! carry `Authorization: Basic <base64(user:pass)>`. The username
//! is compared in constant time; the password is verified with
//! argon2 against the stored PHC string.
//!
//! Missing / malformed / wrong-credential responses all collapse to
//! `401 Unauthorized` with a `WWW-Authenticate: Basic realm="..."`
//! header so a browser surfaces the credentials prompt.

use argon2::password_hash::{Encoding, PasswordHash, PasswordVerifier};
use argon2::Argon2;
use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderValue, Request, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use crate::config::AdminAuthConfig;

#[derive(Clone, Debug)]
pub struct AdminGate {
    pub username: String,
    pub password_hash: String,
    pub realm: String,
}

impl AdminGate {
    pub fn from_config(cfg: &AdminAuthConfig) -> Self {
        Self {
            username: cfg.username.clone(),
            password_hash: cfg.password_hash.clone(),
            realm: cfg.realm.clone(),
        }
    }

    pub fn enabled(&self) -> bool {
        !self.password_hash.is_empty()
    }
}

pub async fn require_basic(
    State(gate): State<AdminGate>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if !gate.enabled() {
        return next.run(req).await;
    }

    if check(&gate, req.headers().get(header::AUTHORIZATION)) {
        return next.run(req).await;
    }

    unauthorized(&gate.realm)
}

fn check(gate: &AdminGate, header_val: Option<&HeaderValue>) -> bool {
    let Some(raw) = header_val.and_then(|h| h.to_str().ok()) else {
        return false;
    };
    let Some(b64) = raw.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = B64.decode(b64.trim()) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&decoded) else {
        return false;
    };
    let Some((user, pass)) = text.split_once(':') else {
        return false;
    };
    if !constant_time_eq(user.as_bytes(), gate.username.as_bytes()) {
        return false;
    }
    let Ok(parsed) = PasswordHash::parse(&gate.password_hash, Encoding::B64) else {
        return false;
    };
    Argon2::default()
        .verify_password(pass.as_bytes(), &parsed)
        .is_ok()
}

fn unauthorized(realm: &str) -> Response {
    let mut resp = Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .body(Body::from("unauthorized"))
        .expect("static response");
    let header = format!("Basic realm=\"{}\"", realm.replace('"', "'"));
    if let Ok(value) = HeaderValue::from_str(&header) {
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, value);
    }
    resp
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::SaltString;
    use argon2::PasswordHasher;

    fn hash(pw: &str) -> String {
        let salt = SaltString::from_b64("c2FsdHNhbHRzYWx0c2FsdA").unwrap();
        Argon2::default()
            .hash_password(pw.as_bytes(), &salt)
            .unwrap()
            .to_string()
    }

    fn gate(user: &str, pw: &str) -> AdminGate {
        AdminGate {
            username: user.into(),
            password_hash: hash(pw),
            realm: "test".into(),
        }
    }

    fn header(user: &str, pw: &str) -> HeaderValue {
        let raw = format!("Basic {}", B64.encode(format!("{user}:{pw}")));
        HeaderValue::from_str(&raw).unwrap()
    }

    #[test]
    fn accepts_correct_credentials() {
        let g = gate("admin", "swordfish");
        assert!(check(&g, Some(&header("admin", "swordfish"))));
    }

    #[test]
    fn rejects_wrong_password() {
        let g = gate("admin", "swordfish");
        assert!(!check(&g, Some(&header("admin", "guess"))));
    }

    #[test]
    fn rejects_wrong_username() {
        let g = gate("admin", "swordfish");
        assert!(!check(&g, Some(&header("eve", "swordfish"))));
    }

    #[test]
    fn rejects_missing_header() {
        let g = gate("admin", "swordfish");
        assert!(!check(&g, None));
    }

    #[test]
    fn rejects_wrong_scheme() {
        let g = gate("admin", "swordfish");
        let h = HeaderValue::from_static("Bearer abc");
        assert!(!check(&g, Some(&h)));
    }

    #[test]
    fn rejects_malformed_base64() {
        let g = gate("admin", "swordfish");
        let h = HeaderValue::from_static("Basic !!!not-b64!!!");
        assert!(!check(&g, Some(&h)));
    }

    #[test]
    fn rejects_no_colon_in_decoded() {
        let g = gate("admin", "swordfish");
        let raw = format!("Basic {}", B64.encode("nopassword"));
        let h = HeaderValue::from_str(&raw).unwrap();
        assert!(!check(&g, Some(&h)));
    }
}
