//! Integration tests for auth primitives + admin seeding.

use edge::auth::{password, token, JwtSecret, Role};
use tempfile::TempDir;

async fn fresh_db() -> (TempDir, edge::storage::Db) {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("test.db");
    let db = edge::storage::open(&path).await.expect("open db");
    (tmp, db)
}

#[test]
fn role_round_trip_through_string() {
    for role in [
        Role::Admin,
        Role::Manager,
        Role::Auditor,
        Role::Operator,
        Role::Installer,
        Role::Viewer,
    ] {
        let s = role.as_str();
        let parsed: Role = s.parse().expect("parse role");
        assert_eq!(role, parsed);
    }
}

#[test]
fn role_unknown_string_errors() {
    let err = "wizard".parse::<Role>().unwrap_err();
    assert!(err.to_string().contains("wizard"));
}

#[test]
fn role_privilege_ordering() {
    assert!(Role::Admin.has_at_least(Role::Manager));
    assert!(Role::Admin.has_at_least(Role::Viewer));
    assert!(Role::Manager.has_at_least(Role::Operator));
    assert!(!Role::Viewer.has_at_least(Role::Manager));
    assert!(!Role::Operator.has_at_least(Role::Admin));
    assert!(Role::Auditor.has_at_least(Role::Operator));
}

#[test]
fn password_hash_then_verify() {
    let phc = password::hash("correct horse battery staple").expect("hash");
    assert!(phc.starts_with("$argon2"), "PHC string format");
    assert!(password::verify("correct horse battery staple", &phc).expect("verify ok"));
    assert!(!password::verify("wrong password", &phc).expect("verify wrong"));
}

#[test]
fn password_hash_is_salted() {
    let a = password::hash("hunter2").expect("hash a");
    let b = password::hash("hunter2").expect("hash b");
    assert_ne!(a, b, "two hashes of the same password must differ");
    assert!(password::verify("hunter2", &a).unwrap());
    assert!(password::verify("hunter2", &b).unwrap());
}

#[test]
fn jwt_round_trip_carries_user_and_role() {
    let secret = JwtSecret::from_string("test-secret-32-bytes-min-test-secret");
    let token = token::issue(&secret, 42, Role::Manager, 60).expect("issue");
    let claims = token::verify(&secret, &token).expect("verify");
    assert_eq!(claims.sub, 42);
    assert_eq!(claims.role, Role::Manager);
    assert!(claims.exp > claims.iat);
}

#[test]
fn jwt_rejects_wrong_secret() {
    let s1 = JwtSecret::from_string("alpha-alpha-alpha-alpha-alpha-32!");
    let s2 = JwtSecret::from_string("beta-beta-beta-beta-beta-beta-32!");
    let token = token::issue(&s1, 1, Role::Admin, 60).expect("issue");
    assert!(
        token::verify(&s2, &token).is_err(),
        "different secret rejects"
    );
}

#[test]
fn jwt_rejects_tampered_payload() {
    let secret = JwtSecret::from_string("test-secret-test-secret-test-secret");
    let token = token::issue(&secret, 1, Role::Viewer, 60).expect("issue");
    let mut parts: Vec<&str> = token.split('.').collect();
    let bad_payload = "eyJzdWIiOjEsInJvbGUiOiJhZG1pbiIsImlhdCI6MCwiZXhwIjo5OTk5OTk5OTk5fQ";
    parts[1] = bad_payload;
    let bad = parts.join(".");
    assert!(token::verify(&secret, &bad).is_err());
}

#[tokio::test]
async fn admin_seed_creates_user_and_login_works() {
    let (_tmp, db) = fresh_db().await;
    let id = edge::admin::seed_user(&db, "admin@example.com", "s3cret-pw", Role::Admin)
        .await
        .expect("seed");
    let stored: (String, String) =
        sqlx::query_as("SELECT password_hash, role FROM user WHERE id = ?")
            .bind(id)
            .fetch_one(db.pool())
            .await
            .expect("fetch user");
    assert_eq!(stored.1, "admin");
    assert!(password::verify("s3cret-pw", &stored.0).expect("verify"));
    assert!(!password::verify("wrong", &stored.0).expect("verify wrong"));
}

#[tokio::test]
async fn admin_seed_rejects_duplicate_email() {
    let (_tmp, db) = fresh_db().await;
    edge::admin::seed_user(&db, "dup@example.com", "pw1", Role::Admin)
        .await
        .expect("first seed");
    let err = edge::admin::seed_user(&db, "dup@example.com", "pw2", Role::Manager)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already exists"));
}
