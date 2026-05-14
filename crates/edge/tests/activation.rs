//! End-to-end activation: a Control Plane lib instance is spun up on a
//! random port; the edge activates against it and the resulting signed
//! license is verified with the CP's public key.

use std::time::Duration;

use control_plane::http::AppState as CpAppState;
use control_plane::signing::LicenseSigner;
use edge::auth::CpPublicKey;
use shared::license::Tier;
use tempfile::TempDir;

struct CpHarness {
    addr: std::net::SocketAddr,
    pubkey_hex: String,
    _tmp: TempDir,
    _shutdown: tokio::sync::oneshot::Sender<()>,
    _handle: tokio::task::JoinHandle<()>,
}

async fn spawn_cp() -> (CpHarness, control_plane::storage::Db) {
    let tmp = TempDir::new().expect("tempdir");
    let db = control_plane::storage::open(&tmp.path().join("cp.db"))
        .await
        .expect("open cp db");
    let signer = LicenseSigner::ephemeral();
    let pubkey_hex = signer.public_key_hex();
    let state = CpAppState {
        db: db.clone(),
        signer,
        // Phase-0 dev gate: disabled. The edge activation flow
        // never touches /admin so this can't matter for the tests
        // — but the struct field is required.
        admin_gate: control_plane::http::AdminGate {
            username: "admin".into(),
            password_hash: String::new(),
            realm: "lbc-admin".into(),
        },
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");
    let router = control_plane::http::router(state);
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, router)
            .with_graceful_shutdown(async {
                let _ = rx.await;
            })
            .await;
    });
    (
        CpHarness {
            addr,
            pubkey_hex,
            _tmp: tmp,
            _shutdown: tx,
            _handle: handle,
        },
        db,
    )
}

async fn seed_license_key(db: &control_plane::storage::Db, key: &str, allowed: i64) {
    let now = 1_000_000_000_000_i64;
    let account_id: i64 = sqlx::query_scalar(
        "INSERT INTO account (name, email, tier, created_at) VALUES (?, ?, ?, ?) RETURNING id",
    )
    .bind("test-customer")
    .bind("test@example.com")
    .bind("pro")
    .bind(now)
    .fetch_one(db.pool())
    .await
    .expect("insert account");
    let key_hash = blake3::hash(key.as_bytes());
    sqlx::query(
        "INSERT INTO license_key (account_id, key_hash, tier, allowed_branch_count, expires_at, created_at) \
         VALUES (?, ?, ?, ?, ?, ?)",
    )
    .bind(account_id)
    .bind(key_hash.as_bytes().as_slice())
    .bind("pro")
    .bind(allowed)
    .bind(0_i64)
    .bind(now)
    .execute(db.pool())
    .await
    .expect("insert license_key");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end_activation_round_trips() {
    let (cp, db) = spawn_cp().await;
    seed_license_key(&db, "TEST-KEY-001", 2).await;

    let cp_url = format!("http://{}", cp.addr);
    // Wait for the CP to accept connections — give the spawned task a tick.
    for _ in 0..20 {
        if reqwest::get(format!("{cp_url}/healthz")).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let fp = edge::fingerprint::compute();
    assert!(!fp.is_empty(), "fingerprint must be non-empty");

    let components = edge::fingerprint::canonical_json();
    let resp = edge::activate::activate(&cp_url, "TEST-KEY-001", "store-1", &fp, &components)
        .await
        .expect("activate");
    assert!(resp.issued_license_id > 0);

    // Edge can persist + reload + verify the license.
    let tmp_license = TempDir::new().expect("tempdir");
    let path = tmp_license.path().join("license.json");
    edge::license::save(&path, &resp.license).expect("save");

    let pubkey = CpPublicKey::from_hex(&cp.pubkey_hex).expect("pubkey");
    let loaded = edge::license::load_and_verify(&path, &pubkey)
        .expect("load")
        .expect("present");
    assert_eq!(loaded.payload.tier, Tier::Pro);
    assert_eq!(loaded.payload.hardware_fingerprint, fp);
    assert_eq!(loaded.payload.branch_id, resp.branch_id);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activation_with_unknown_key_surfaces_error() {
    let (cp, _db) = spawn_cp().await;
    let cp_url = format!("http://{}", cp.addr);
    for _ in 0..20 {
        if reqwest::get(format!("{cp_url}/healthz")).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let fp = edge::fingerprint::compute();
    let err = edge::activate::activate(
        &cp_url,
        "no-such-key",
        "store-1",
        &fp,
        &edge::fingerprint::canonical_json(),
    )
    .await
    .unwrap_err();
    assert!(
        format!("{err:#}").contains("400") || format!("{err:#}").contains("unknown"),
        "unexpected error: {err:#}"
    );
}

#[test]
fn license_load_returns_none_when_file_missing() {
    let tmp = TempDir::new().unwrap();
    let pubkey = CpPublicKey::from_hex(&"00".repeat(32)).unwrap();
    let result =
        edge::license::load_and_verify(&tmp.path().join("nope.json"), &pubkey).expect("load");
    assert!(result.is_none());
}

#[test]
fn license_load_rejects_tampered_file() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("license.json");
    std::fs::write(&path, br#"{"payload":{"customer_id":"x","tier":"pro","feature_flags":[],"branch_count":1,"branch_id":1,"hardware_fingerprint":"f","issued_at":1,"expiry":0,"grace_period_days":30},"signature":"00"}"#).unwrap();
    let pubkey = CpPublicKey::from_hex(&"00".repeat(32)).unwrap();
    let err = edge::license::load_and_verify(&path, &pubkey).unwrap_err();
    let msg = format!("{err:#}");
    assert!(
        msg.contains("verifying") || msg.contains("64 bytes") || msg.contains("signature"),
        "unexpected error: {msg}"
    );
}

#[test]
fn fingerprint_is_stable_across_calls() {
    let a = edge::fingerprint::compute();
    let b = edge::fingerprint::compute();
    assert_eq!(a, b);
    assert_eq!(a.len(), 64, "blake3 hex is 64 chars");
}

#[test]
fn cp_public_key_round_trips_hex() {
    let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let key = CpPublicKey::from_hex(hex).unwrap();
    assert_eq!(key.to_hex(), hex);
}

#[test]
fn cp_public_key_rejects_wrong_length() {
    assert!(CpPublicKey::from_hex("abcd").is_err());
}

// --- Heartbeat / grace-period --------------------------------------------

use edge::heartbeat::{compute_status, HealthHandle, LicenseHealthState, LicenseStatus};

#[test]
fn compute_status_is_healthy_within_grace() {
    let day_ms: i64 = 86_400_000;
    let now = 100 * day_ms;
    // Last seen 5 days ago, 30-day grace.
    assert_eq!(
        compute_status(now - 5 * day_ms, now, 30),
        LicenseStatus::Healthy
    );
}

#[test]
fn compute_status_degrades_after_grace() {
    let day_ms: i64 = 86_400_000;
    let now = 100 * day_ms;
    // Last seen 31 days ago, 30-day grace.
    assert_eq!(
        compute_status(now - 31 * day_ms, now, 30),
        LicenseStatus::Degraded
    );
}

#[test]
fn compute_status_with_zero_last_seen_is_degraded() {
    assert_eq!(compute_status(0, 1_000_000, 30), LicenseStatus::Degraded);
}

#[test]
fn compute_status_with_zero_grace_degrades_immediately() {
    let now = 1_000_000_i64;
    assert_eq!(compute_status(now - 1, now, 0), LicenseStatus::Degraded);
}

#[test]
fn license_health_state_round_trips_through_disk() {
    let tmp = TempDir::new().unwrap();
    let path = tmp.path().join("state.json");
    let original = LicenseHealthState {
        last_seen_at: 1_234_567_890,
        issued_license_id: Some(42),
        heartbeat_token: Some("deadbeef".repeat(8)),
    };
    edge::heartbeat::save_state(&path, &original).unwrap();
    let loaded = edge::heartbeat::load_state(&path).unwrap();
    assert_eq!(loaded.last_seen_at, original.last_seen_at);
    assert_eq!(loaded.issued_license_id, original.issued_license_id);
    assert_eq!(loaded.heartbeat_token, original.heartbeat_token);
}

#[test]
fn license_health_state_load_missing_returns_default() {
    let tmp = TempDir::new().unwrap();
    let s = edge::heartbeat::load_state(&tmp.path().join("nope.json")).unwrap();
    assert_eq!(s.last_seen_at, 0);
    assert!(s.issued_license_id.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn end_to_end_heartbeat_then_revoke_then_degraded() {
    let (cp, db) = spawn_cp().await;
    seed_license_key(&db, "TEST-HB-KEY", 1).await;
    let cp_url = format!("http://{}", cp.addr);
    for _ in 0..20 {
        if reqwest::get(format!("{cp_url}/healthz")).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let fp = edge::fingerprint::compute();

    // Activate.
    let components = edge::fingerprint::canonical_json();
    let resp = edge::activate::activate(&cp_url, "TEST-HB-KEY", "store-1", &fp, &components)
        .await
        .expect("activate");
    let issued_id = resp.issued_license_id;

    // Drive a single heartbeat directly (rather than spawning the periodic
    // task) so the test stays deterministic.
    let hb = edge::heartbeat::post_heartbeat(
        &cp_url,
        issued_id,
        &fp,
        Some(&components),
        &resp.heartbeat_token,
    )
    .await
    .expect("first heartbeat");
    assert!(hb.last_seen > 0);

    // Health handle starts healthy after a successful heartbeat.
    let handle = HealthHandle::new(
        LicenseHealthState {
            last_seen_at: hb.last_seen,
            issued_license_id: Some(issued_id),
            heartbeat_token: Some(resp.heartbeat_token.clone()),
        },
        30,
    );
    assert_eq!(handle.status().await, LicenseStatus::Healthy);

    // Revoke over the wire; subsequent heartbeats should fail with a Gone-style error.
    let revoke = reqwest::Client::new()
        .post(format!("{cp_url}/api/v1/licenses/{issued_id}/revoke"))
        .send()
        .await
        .expect("revoke");
    assert_eq!(revoke.status(), reqwest::StatusCode::NO_CONTENT);

    let post_revoke = edge::heartbeat::post_heartbeat(
        &cp_url,
        issued_id,
        &fp,
        Some(&components),
        &resp.heartbeat_token,
    )
    .await;
    assert!(
        post_revoke.is_err(),
        "heartbeat after revoke must fail; got {:?}",
        post_revoke
    );

    // Simulate the grace window expiring without further heartbeats by
    // checking compute_status with last_seen well in the past.
    let day_ms: i64 = 86_400_000;
    let stale_now = hb.last_seen + 31 * day_ms;
    assert_eq!(
        compute_status(hb.last_seen, stale_now, 30),
        LicenseStatus::Degraded,
        "after 31d without heartbeat, license should be degraded"
    );
}
