//! Test harness for Control Plane integration tests.

use axum::Router;
use control_plane::http::{AdminGate, AppState};
use control_plane::signing::LicenseSigner;
use control_plane::storage::Db;
use tempfile::TempDir;

#[allow(dead_code)]
pub struct TestApp {
    pub _tmp: TempDir,
    pub db: Db,
    pub router: Router,
    pub signer: LicenseSigner,
    pub admin_gate: AdminGate,
}

pub async fn test_app() -> TestApp {
    // Default: admin gate disabled. Most tests assert the
    // *behaviour* of admin routes, not the auth gate; the gate has
    // its own integration tests via `test_app_with_admin_auth`.
    test_app_with_admin_gate(AdminGate {
        username: "admin".into(),
        password_hash: String::new(),
        realm: "lbc-admin".into(),
    })
    .await
}

#[allow(dead_code)]
pub async fn test_app_with_admin_auth(username: &str, password: &str) -> TestApp {
    use argon2::password_hash::SaltString;
    use argon2::{Argon2, PasswordHasher};
    // Fixed salt for test determinism — irrelevant to security
    // since the harness tempdir is destroyed after each test.
    let salt = SaltString::from_b64("c2FsdHNhbHRzYWx0c2FsdA").unwrap();
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    test_app_with_admin_gate(AdminGate {
        username: username.into(),
        password_hash: hash,
        realm: "lbc-admin".into(),
    })
    .await
}

async fn test_app_with_admin_gate(admin_gate: AdminGate) -> TestApp {
    let tmp = TempDir::new().expect("tempdir");
    let db = control_plane::storage::open(&tmp.path().join("cp.db"))
        .await
        .expect("open db");
    let signer = LicenseSigner::ephemeral();
    let state = AppState {
        db: db.clone(),
        signer: signer.clone(),
        admin_gate: admin_gate.clone(),
    };
    let router = control_plane::http::router(state);
    TestApp {
        _tmp: tmp,
        db,
        router,
        signer,
        admin_gate,
    }
}

/// Inserts an account + a license-key for that account, returning the cleartext key.
pub async fn seed_account_and_key(
    db: &Db,
    name: &str,
    tier: &str,
    allowed_branch_count: i64,
) -> String {
    let now = 1_000_000_000_000_i64;
    let account_id: i64 = sqlx::query_scalar(
        "INSERT INTO account (name, email, tier, created_at) VALUES (?, ?, ?, ?) RETURNING id",
    )
    .bind(name)
    .bind(format!("{name}@example.com"))
    .bind(tier)
    .bind(now)
    .fetch_one(db.pool())
    .await
    .expect("insert account");

    let key = format!("LBC-TEST-{name}-KEY");
    let key_hash = blake3::hash(key.as_bytes());
    sqlx::query(
        "INSERT INTO license_key (account_id, key_hash, tier, allowed_branch_count, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(account_id)
    .bind(key_hash.as_bytes().as_slice())
    .bind(tier)
    .bind(allowed_branch_count)
    .bind(0_i64)
    .bind(now)
    .execute(db.pool())
    .await
    .expect("insert license_key");
    key
}
