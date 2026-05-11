//! Per-account brute-force gate on `POST /api/v1/auth/login`.
//!
//! Confirms the four state transitions of the gate:
//!
//! * **Counter increments** on each failure.
//! * **Success resets** the counter and clears any lock.
//! * **Lock engages** once consecutive failures hit the configured
//!   threshold — even a correct password is rejected while locked.
//! * **Lock expires** naturally; valid credentials succeed after the
//!   window passes.
//!
//! Plus negative cases: disabled gate (`max_failed_attempts = 0`),
//! per-account isolation, unknown emails not tracked.

mod common;

use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use edge::auth::Role;
use edge::http::LoginRateLimit;
use tower::ServiceExt as _;

use common::test_app_with;

const EMAIL: &str = "alice@example.com";
const PASSWORD: &str = "correct horse";

async fn attempt(router: axum::Router, email: &str, password: &str) -> StatusCode {
    let body = serde_json::json!({ "email": email, "password": password }).to_string();
    let resp = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    resp.status()
}

#[tokio::test]
async fn lockout_engages_after_threshold_and_rejects_valid_password() {
    let app = test_app_with(LoginRateLimit {
        max_failed_attempts: 3,
        lockout_secs: 60,
    })
    .await;
    edge::admin::seed_user(&app.db, EMAIL, PASSWORD, Role::Admin)
        .await
        .unwrap();

    for _ in 0..3 {
        assert_eq!(
            attempt(app.router.clone(), EMAIL, "nope").await,
            StatusCode::UNAUTHORIZED
        );
    }
    // Threshold hit — valid creds now refused.
    assert_eq!(
        attempt(app.router.clone(), EMAIL, PASSWORD).await,
        StatusCode::UNAUTHORIZED,
        "valid password must be rejected while account is locked"
    );

    let until: Option<i64> = sqlx::query_scalar("SELECT locked_until_ms FROM user WHERE email = ?")
        .bind(EMAIL)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert!(
        until.is_some(),
        "locked_until_ms must be set after threshold"
    );
}

#[tokio::test]
async fn success_resets_failure_counter() {
    let app = test_app_with(LoginRateLimit {
        max_failed_attempts: 5,
        lockout_secs: 60,
    })
    .await;
    edge::admin::seed_user(&app.db, EMAIL, PASSWORD, Role::Admin)
        .await
        .unwrap();

    // 4 fails (below threshold), then succeed, then 4 more fails — must
    // not lock since the counter resets.
    for _ in 0..4 {
        assert_eq!(
            attempt(app.router.clone(), EMAIL, "nope").await,
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        attempt(app.router.clone(), EMAIL, PASSWORD).await,
        StatusCode::OK
    );
    for _ in 0..4 {
        assert_eq!(
            attempt(app.router.clone(), EMAIL, "nope").await,
            StatusCode::UNAUTHORIZED
        );
    }
    // Still able to log in with the right password.
    assert_eq!(
        attempt(app.router.clone(), EMAIL, PASSWORD).await,
        StatusCode::OK
    );
    let count: i64 = sqlx::query_scalar("SELECT failed_login_count FROM user WHERE email = ?")
        .bind(EMAIL)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0, "successful login must zero the counter");
}

#[tokio::test]
async fn lock_expires_after_window() {
    let app = test_app_with(LoginRateLimit {
        max_failed_attempts: 2,
        // 1 s window so the test finishes in well under a second of wall
        // time waiting; the gate uses unix-ms math so sub-second is fine.
        lockout_secs: 1,
    })
    .await;
    edge::admin::seed_user(&app.db, EMAIL, PASSWORD, Role::Admin)
        .await
        .unwrap();

    for _ in 0..2 {
        attempt(app.router.clone(), EMAIL, "nope").await;
    }
    assert_eq!(
        attempt(app.router.clone(), EMAIL, PASSWORD).await,
        StatusCode::UNAUTHORIZED,
        "must be locked immediately after threshold"
    );

    tokio::time::sleep(Duration::from_millis(1_100)).await;

    assert_eq!(
        attempt(app.router.clone(), EMAIL, PASSWORD).await,
        StatusCode::OK,
        "lock must lift after lockout_secs elapses"
    );
    let until: Option<i64> = sqlx::query_scalar("SELECT locked_until_ms FROM user WHERE email = ?")
        .bind(EMAIL)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert!(until.is_none(), "lock must be cleared on successful login");
}

#[tokio::test]
async fn disabled_gate_never_locks() {
    let app = test_app_with(LoginRateLimit {
        max_failed_attempts: 0, // disabled
        lockout_secs: 60,
    })
    .await;
    edge::admin::seed_user(&app.db, EMAIL, PASSWORD, Role::Admin)
        .await
        .unwrap();

    for _ in 0..10 {
        assert_eq!(
            attempt(app.router.clone(), EMAIL, "nope").await,
            StatusCode::UNAUTHORIZED
        );
    }
    // Still works after a flood of failures.
    assert_eq!(
        attempt(app.router.clone(), EMAIL, PASSWORD).await,
        StatusCode::OK
    );
    let count: i64 = sqlx::query_scalar("SELECT failed_login_count FROM user WHERE email = ?")
        .bind(EMAIL)
        .fetch_one(app.db.pool())
        .await
        .unwrap();
    assert_eq!(count, 0, "disabled gate must not touch the counter");
}

#[tokio::test]
async fn lockout_is_per_account() {
    let app = test_app_with(LoginRateLimit {
        max_failed_attempts: 2,
        lockout_secs: 60,
    })
    .await;
    edge::admin::seed_user(&app.db, EMAIL, PASSWORD, Role::Admin)
        .await
        .unwrap();
    edge::admin::seed_user(&app.db, "bob@example.com", "pw", Role::Manager)
        .await
        .unwrap();

    for _ in 0..2 {
        attempt(app.router.clone(), EMAIL, "nope").await;
    }
    // Alice locked.
    assert_eq!(
        attempt(app.router.clone(), EMAIL, PASSWORD).await,
        StatusCode::UNAUTHORIZED
    );
    // Bob unaffected.
    assert_eq!(
        attempt(app.router.clone(), "bob@example.com", "pw").await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn unknown_emails_are_not_tracked() {
    let app = test_app_with(LoginRateLimit {
        max_failed_attempts: 2,
        lockout_secs: 60,
    })
    .await;
    edge::admin::seed_user(&app.db, EMAIL, PASSWORD, Role::Admin)
        .await
        .unwrap();

    // Flood with an email that doesn't exist — must stay 401 forever
    // without burning a counter on a real account.
    for _ in 0..20 {
        assert_eq!(
            attempt(app.router.clone(), "ghost@example.com", "nope").await,
            StatusCode::UNAUTHORIZED
        );
    }
    // Real account is still good.
    assert_eq!(
        attempt(app.router.clone(), EMAIL, PASSWORD).await,
        StatusCode::OK
    );
}
