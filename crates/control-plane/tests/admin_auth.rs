//! HTTP Basic gate on `/admin/*` routes.
//!
//! Covers the four behaviours of the gate:
//!
//! * **Disabled mode** (empty `password_hash`) passes every
//!   request through — preserves the Phase-0 dev workflow.
//! * **Enabled mode** rejects unauthenticated requests with
//!   `401 Unauthorized` and a `WWW-Authenticate: Basic realm=...`
//!   header so browsers surface the credentials prompt.
//! * Wrong username, wrong password, malformed `Authorization`,
//!   and wrong auth-scheme all collapse to the same 401.
//! * Correct `Basic <base64(user:pass)>` is allowed through —
//!   we verify by checking the body matches the index page.
//!
//! The unit-level branch coverage (each `check()` return path)
//! lives next to the implementation in `admin_auth.rs#tests`. This
//! file pins the *integration* contract: that the middleware is
//! actually wired onto every `/admin/*` route and not just
//! `/admin/` itself.

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{header, Request, StatusCode};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use tower::ServiceExt as _;

use common::{seed_account_and_key, test_app, test_app_with_admin_auth};

const USER: &str = "ops";
const PASSWORD: &str = "swordfish-42";

fn basic(user: &str, pw: &str) -> String {
    format!("Basic {}", B64.encode(format!("{user}:{pw}")))
}

fn get_with_auth(uri: &str, auth: Option<&str>) -> Request<Body> {
    let mut b = Request::builder().uri(uri);
    if let Some(value) = auth {
        b = b.header(header::AUTHORIZATION, value);
    }
    b.body(Body::empty()).unwrap()
}

async fn body_text(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn disabled_gate_passes_through() {
    // test_app() uses an empty password_hash — Phase-0 dev default.
    let app = test_app().await;
    let resp = app
        .router
        .clone()
        .oneshot(get_with_auth("/admin", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn enabled_gate_rejects_missing_auth() {
    let app = test_app_with_admin_auth(USER, PASSWORD).await;
    let resp = app
        .router
        .clone()
        .oneshot(get_with_auth("/admin", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let www = resp
        .headers()
        .get(header::WWW_AUTHENTICATE)
        .expect("WWW-Authenticate must be set on 401")
        .to_str()
        .unwrap();
    assert!(
        www.starts_with("Basic realm="),
        "expected Basic challenge, got {www:?}"
    );
}

#[tokio::test]
async fn enabled_gate_allows_correct_credentials() {
    let app = test_app_with_admin_auth(USER, PASSWORD).await;
    let auth = basic(USER, PASSWORD);
    let resp = app
        .router
        .clone()
        .oneshot(get_with_auth("/admin", Some(&auth)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(body.contains("LBC Control Plane"));
}

#[tokio::test]
async fn enabled_gate_rejects_wrong_password() {
    let app = test_app_with_admin_auth(USER, PASSWORD).await;
    let auth = basic(USER, "guess");
    let resp = app
        .router
        .clone()
        .oneshot(get_with_auth("/admin", Some(&auth)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enabled_gate_rejects_wrong_username() {
    let app = test_app_with_admin_auth(USER, PASSWORD).await;
    let auth = basic("eve", PASSWORD);
    let resp = app
        .router
        .clone()
        .oneshot(get_with_auth("/admin", Some(&auth)))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enabled_gate_rejects_wrong_scheme() {
    let app = test_app_with_admin_auth(USER, PASSWORD).await;
    let resp = app
        .router
        .clone()
        .oneshot(get_with_auth("/admin", Some("Bearer abc123")))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn enabled_gate_protects_subroutes() {
    // The middleware must run on every nested route, not just
    // `/admin/`. We seed an account so /admin/accounts has a real
    // row to render once allowed through.
    let app = test_app_with_admin_auth(USER, PASSWORD).await;
    seed_account_and_key(&app.db, "acme", "pro", 1).await;

    for path in [
        "/admin",
        "/admin/accounts",
        "/admin/accounts/new",
        "/admin/branches",
        "/admin/licenses",
    ] {
        let resp = app
            .router
            .clone()
            .oneshot(get_with_auth(path, None))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{path} must be gated"
        );
    }
}

#[tokio::test]
async fn enabled_gate_does_not_affect_public_routes() {
    // Public Phase-0 endpoints (heartbeat, /healthz, /api/v1/*)
    // must keep their pre-gate behaviour. We test /healthz and the
    // top-level healthz at the root.
    let app = test_app_with_admin_auth(USER, PASSWORD).await;
    for path in ["/healthz", "/api/v1/healthz"] {
        let resp = app
            .router
            .clone()
            .oneshot(get_with_auth(path, None))
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "{path} must remain public when admin gate is on"
        );
    }
}
