//! Integration tests for the edge storage layer.

use edge::storage::audit::AuditEntry;
use sqlx::Row;
use tempfile::TempDir;

async fn fresh_db() -> (TempDir, edge::storage::Db) {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("test.db");
    let db = edge::storage::open(&path).await.expect("open db");
    (tmp, db)
}

#[tokio::test]
async fn migrations_create_all_phase0_tables() {
    let (_tmp, db) = fresh_db().await;
    let rows = sqlx::query(
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(db.pool())
    .await
    .expect("query schema");
    let mut names: Vec<String> = rows
        .into_iter()
        .map(|r| r.try_get::<String, _>("name").expect("name column"))
        .filter(|n| !n.starts_with('_'))
        .collect();
    names.sort();
    let expected = [
        "action_log",
        "audit_log",
        "branch",
        "case",
        "case_exception",
        "device",
        "event",
        "evidence",
        "exception",
        "license",
        "rule",
        "rule_run",
        "user",
    ];
    let expected: Vec<String> = expected.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(names, expected, "phase 0 table set");
}

#[tokio::test]
async fn migrations_are_idempotent_across_reopen() {
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("test.db");
    let _first = edge::storage::open(&path).await.expect("first open");
    let second = edge::storage::open(&path).await.expect("second open");
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _migrations")
        .fetch_one(second.pool())
        .await
        .expect("count migrations");
    assert_eq!(rows, 2, "phase 0 migrations recorded once each");
}

#[tokio::test]
async fn wal_mode_is_active() {
    let (_tmp, db) = fresh_db().await;
    let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(db.pool())
        .await
        .expect("pragma");
    assert_eq!(mode.to_lowercase(), "wal");
}

#[tokio::test]
async fn audit_chain_links_rows_and_verifies() {
    let (_tmp, db) = fresh_db().await;
    let entries = [
        ("alice", "login", "session", None, Some(r#"{"ok":true}"#), 1),
        ("bob", "create", "device:42", None, Some(r#"{"id":42}"#), 2),
        ("alice", "delete", "rule:7", Some(r#"{"id":7}"#), None, 3),
    ];
    for (actor, action, entity, before, after, ts) in entries {
        db.audit_append(AuditEntry {
            actor,
            action,
            entity,
            before,
            after,
            ts_ms: ts,
        })
        .await
        .expect("append");
    }

    assert!(db.audit_verify_chain().await.expect("verify"));

    let rows = sqlx::query("SELECT id, prev_hash, hash FROM audit_log ORDER BY id ASC")
        .fetch_all(db.pool())
        .await
        .expect("read chain");
    assert_eq!(rows.len(), 3);
    let prev0: Option<Vec<u8>> = rows[0].try_get("prev_hash").unwrap();
    assert!(prev0.is_none(), "first row has no prev_hash");
    for window in rows.windows(2) {
        let prev_hash: Vec<u8> = window[0].try_get("hash").unwrap();
        let next_prev: Vec<u8> = window[1].try_get("prev_hash").unwrap();
        assert_eq!(prev_hash, next_prev, "next.prev_hash == previous.hash");
    }
}

#[tokio::test]
async fn audit_verify_detects_tampering() {
    let (_tmp, db) = fresh_db().await;
    db.audit_append(AuditEntry {
        actor: "alice",
        action: "login",
        entity: "session",
        before: None,
        after: None,
        ts_ms: 100,
    })
    .await
    .expect("append 1");
    db.audit_append(AuditEntry {
        actor: "alice",
        action: "logout",
        entity: "session",
        before: None,
        after: None,
        ts_ms: 200,
    })
    .await
    .expect("append 2");
    assert!(db.audit_verify_chain().await.expect("verify pre"));

    sqlx::query("UPDATE audit_log SET actor = 'eve' WHERE id = 1")
        .execute(db.pool())
        .await
        .expect("tamper");
    assert!(
        !db.audit_verify_chain().await.expect("verify post"),
        "tampered chain should fail verification"
    );
}
