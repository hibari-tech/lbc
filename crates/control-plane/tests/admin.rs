//! Admin web integration tests.

mod common;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use shared::license::SignedLicense;
use sqlx::Row;
use tower::ServiceExt as _;

use common::{seed_account_and_key, test_app};

async fn body_text(resp: axum::response::Response) -> String {
    let bytes = to_bytes(resp.into_body(), 256 * 1024).await.expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf8")
}

fn get(uri: &str) -> Request<Body> {
    Request::builder().uri(uri).body(Body::empty()).unwrap()
}

fn form_post(uri: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body.to_string()))
        .unwrap()
}

#[tokio::test]
async fn admin_index_renders() {
    let app = test_app().await;
    let resp = app.router.clone().oneshot(get("/admin")).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(body.contains("LBC Control Plane"));
    assert!(body.contains("/admin/accounts"));
    assert!(body.contains("/admin/branches"));
    assert!(body.contains("/admin/licenses"));
}

#[tokio::test]
async fn admin_accounts_lists_seeded_rows() {
    let app = test_app().await;
    seed_account_and_key(&app.db, "acme", "pro", 3).await;
    let resp = app
        .router
        .clone()
        .oneshot(get("/admin/accounts"))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(body.contains("acme"));
    assert!(body.contains("pro"));
}

#[tokio::test]
async fn admin_create_account_mints_unique_key() {
    let app = test_app().await;
    let resp = app
        .router
        .clone()
        .oneshot(form_post(
            "/admin/accounts",
            "name=hibari&email=ops%40example.com&tier=pro&branches=2",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    assert!(body.contains("Save this license key"));
    // Two new mints should produce distinct keys (cleartext only shown once,
    // but we can verify the DB hash differs by minting twice and comparing).
    let resp2 = app
        .router
        .clone()
        .oneshot(form_post(
            "/admin/accounts",
            "name=second&email=ops2%40example.com&tier=starter&branches=1",
        ))
        .await
        .unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let hashes: Vec<Vec<u8>> = sqlx::query("SELECT key_hash FROM license_key ORDER BY id")
        .fetch_all(app.db.pool())
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.try_get::<Vec<u8>, _>("key_hash").unwrap())
        .collect();
    assert_eq!(hashes.len(), 2);
    assert_ne!(hashes[0], hashes[1], "minted keys must be distinct");
}

#[tokio::test]
async fn admin_minted_key_can_actually_activate() {
    let app = test_app().await;
    let resp = app
        .router
        .clone()
        .oneshot(form_post(
            "/admin/accounts",
            "name=loop&email=l%40e&tier=pro&branches=1",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_text(resp).await;
    let key = body
        .split("<code>")
        .nth(1)
        .and_then(|s| s.split("</code>").next())
        .expect("key in response")
        .to_string();
    assert!(key.starts_with("LBC-"));

    let activate = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/licenses/activate")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"license_key":"{key}","branch_name":"store","hardware_fingerprint":"FP"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(activate.status(), StatusCode::OK);
    let json_text = body_text(activate).await;
    let json: serde_json::Value = serde_json::from_str(&json_text).unwrap();
    let signed: SignedLicense = serde_json::from_value(json["license"].clone()).unwrap();
    let pubkey = app.signer.public_key_bytes();
    signed.verify(&pubkey).expect("signature verifies");
}

#[tokio::test]
async fn admin_revoke_redirects_and_marks_revoked() {
    let app = test_app().await;
    let key = seed_account_and_key(&app.db, "rev-co", "pro", 1).await;
    // Activate to create an issued_license row.
    let activate = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/licenses/activate")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"license_key":"{key}","branch_name":"s","hardware_fingerprint":"FP"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(activate.status(), StatusCode::OK);
    let json: serde_json::Value = serde_json::from_str(&body_text(activate).await).unwrap();
    let id = json["issued_license_id"].as_i64().unwrap();

    let resp = app
        .router
        .clone()
        .oneshot(form_post(&format!("/admin/licenses/{id}/revoke"), ""))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get("location")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, "/admin/licenses");

    let revoked_at: Option<i64> =
        sqlx::query_scalar("SELECT revoked_at FROM issued_license WHERE id = ?")
            .bind(id)
            .fetch_one(app.db.pool())
            .await
            .unwrap();
    assert!(revoked_at.is_some());
}

#[tokio::test]
async fn admin_revoke_unknown_id_returns_404() {
    let app = test_app().await;
    let resp = app
        .router
        .clone()
        .oneshot(form_post("/admin/licenses/9999/revoke", ""))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn admin_branches_lists_after_activation() {
    let app = test_app().await;
    let key = seed_account_and_key(&app.db, "br", "pro", 1).await;
    let _ = app
        .router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/licenses/activate")
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"license_key":"{key}","branch_name":"east-store","hardware_fingerprint":"FP-EAST"}}"#
                )))
                .unwrap(),
        )
        .await
        .unwrap();
    let resp = app
        .router
        .clone()
        .oneshot(get("/admin/branches"))
        .await
        .unwrap();
    let body = body_text(resp).await;
    assert!(body.contains("east-store"));
    assert!(body.contains("FP-EAST"));
}

#[tokio::test]
async fn admin_html_escapes_user_input() {
    let app = test_app().await;
    let resp = app
        .router
        .clone()
        .oneshot(form_post(
            "/admin/accounts",
            "name=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&email=x%40y&tier=pro&branches=1",
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let listing = app
        .router
        .clone()
        .oneshot(get("/admin/accounts"))
        .await
        .unwrap();
    let body = body_text(listing).await;
    assert!(
        !body.contains("<script>"),
        "raw <script> tag must not appear unescaped"
    );
    assert!(body.contains("&lt;script&gt;"));
}
