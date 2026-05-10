//! Shared test harness — builds a stateful router over a tempfile DB.

use axum::Router;
use edge::auth::JwtSecret;
use edge::http::AppState;
use edge::storage::Db;
use tempfile::TempDir;

pub const TEST_JWT_SECRET: &str = "test-secret-test-secret-test-secret-1234";
pub const TEST_TTL_SECS: u64 = 3600;

pub struct TestApp {
    pub _tmp: TempDir,
    pub db: Db,
    pub router: Router,
    pub jwt_secret: JwtSecret,
}

pub async fn test_app() -> TestApp {
    let tmp = TempDir::new().expect("tempdir");
    let db = edge::storage::open(&tmp.path().join("test.db"))
        .await
        .expect("open db");
    let jwt_secret = JwtSecret::from_string(TEST_JWT_SECRET);
    let state = AppState {
        db: db.clone(),
        jwt_secret: jwt_secret.clone(),
        session_ttl_secs: TEST_TTL_SECS,
    };
    let router = edge::http::router(state);
    TestApp {
        _tmp: tmp,
        db,
        router,
        jwt_secret,
    }
}
