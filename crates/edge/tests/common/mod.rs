//! Shared test harness — builds a stateful router over a tempfile DB.

use axum::Router;
use edge::actions::ActionsConfig;
use edge::auth::JwtSecret;
use edge::http::{AppState, LoginRateLimit};
use edge::rules::RuleEngine;
use edge::storage::Db;
use tempfile::TempDir;

pub const TEST_JWT_SECRET: &str = "test-secret-test-secret-test-secret-1234";
pub const TEST_TTL_SECS: u64 = 3600;

// Each test binary uses a different subset of these fields; allow dead_code
// to keep the harness shape uniform across tests.
#[allow(dead_code)]
pub struct TestApp {
    pub _tmp: TempDir,
    pub db: Db,
    pub router: Router,
    pub jwt_secret: JwtSecret,
}

#[allow(dead_code)]
pub async fn test_app() -> TestApp {
    test_app_with(LoginRateLimit::default()).await
}

#[allow(dead_code)]
pub async fn test_app_with(login_rate_limit: LoginRateLimit) -> TestApp {
    let tmp = TempDir::new().expect("tempdir");
    let db = edge::storage::open(&tmp.path().join("test.db"))
        .await
        .expect("open db");
    let jwt_secret = JwtSecret::from_string(TEST_JWT_SECRET);
    let state = AppState {
        db: db.clone(),
        jwt_secret: jwt_secret.clone(),
        session_ttl_secs: TEST_TTL_SECS,
        rule_engine: RuleEngine::new(),
        // Tests post to in-process echo servers on 127.0.0.1; allow private.
        // Production defaults to false via Config::default().
        actions_cfg: ActionsConfig {
            allow_private_targets: true,
            ..Default::default()
        },
        login_rate_limit,
    };
    let router = edge::http::router(state);
    TestApp {
        _tmp: tmp,
        db,
        router,
        jwt_secret,
    }
}
