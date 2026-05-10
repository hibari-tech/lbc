//! End-to-end API tests for §0.6 PR B CRUD endpoints.

mod common;

use axum::body::{to_bytes, Body};
use axum::http::header::AUTHORIZATION;
use axum::http::{Request, StatusCode};
use edge::auth::token;
use edge::auth::Role;
use serde_json::{json, Value};
use tower::ServiceExt as _;

use common::{test_app, TestApp, TEST_TTL_SECS};

async fn body_json(resp: axum::response::Response) -> Value {
    let bytes = to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).expect("parse json")
}

async fn token_for(app: &TestApp, role: Role) -> String {
    let id = edge::admin::seed_user(&app.db, &format!("{role}@example.com"), "pw", role)
        .await
        .expect("seed");
    token::issue(
        &app.jwt_secret,
        id,
        role,
        i64::try_from(TEST_TTL_SECS).unwrap(),
    )
    .expect("issue")
}

fn req_json(method: &str, uri: &str, token: &str, body: Value) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

fn req(method: &str, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header(AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn devices_full_round_trip() {
    let app = test_app().await;
    let tok = token_for(&app, Role::Manager).await;

    let create = app
        .router
        .clone()
        .oneshot(req_json(
            "POST",
            "/api/v1/devices",
            &tok,
            json!({"kind":"camera","vendor":"acme","address":"http://10.0.0.1"}),
        ))
        .await
        .unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let created = body_json(create).await;
    let id = created["id"].as_i64().expect("id");
    assert_eq!(created["kind"], "camera");
    assert_eq!(created["status"], "unknown");

    let got = app
        .router
        .clone()
        .oneshot(req("GET", &format!("/api/v1/devices/{id}"), &tok))
        .await
        .unwrap();
    assert_eq!(got.status(), StatusCode::OK);
    assert_eq!(body_json(got).await["id"], id);

    let listed = app
        .router
        .clone()
        .oneshot(req("GET", "/api/v1/devices", &tok))
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    assert_eq!(body_json(listed).await.as_array().unwrap().len(), 1);

    let patched = app
        .router
        .clone()
        .oneshot(req_json(
            "PATCH",
            &format!("/api/v1/devices/{id}"),
            &tok,
            json!({"status":"online"}),
        ))
        .await
        .unwrap();
    assert_eq!(patched.status(), StatusCode::OK);
    let after_patch = body_json(patched).await;
    assert_eq!(after_patch["status"], "online");
    assert_eq!(after_patch["kind"], "camera");

    let deleted = app
        .router
        .clone()
        .oneshot(req("DELETE", &format!("/api/v1/devices/{id}"), &tok))
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::NO_CONTENT);

    let after_delete = app
        .router
        .clone()
        .oneshot(req("GET", &format!("/api/v1/devices/{id}"), &tok))
        .await
        .unwrap();
    assert_eq!(after_delete.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn devices_viewer_cannot_write_but_can_read() {
    let app = test_app().await;
    let viewer = token_for(&app, Role::Viewer).await;

    let denied = app
        .router
        .clone()
        .oneshot(req_json(
            "POST",
            "/api/v1/devices",
            &viewer,
            json!({"kind":"camera"}),
        ))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::FORBIDDEN);

    let listed = app
        .router
        .clone()
        .oneshot(req("GET", "/api/v1/devices", &viewer))
        .await
        .unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
}

#[tokio::test]
async fn devices_create_rejects_unknown_field() {
    let app = test_app().await;
    let tok = token_for(&app, Role::Manager).await;
    let resp = app
        .router
        .clone()
        .oneshot(req_json(
            "POST",
            "/api/v1/devices",
            &tok,
            json!({"kind":"camera","wat":"unknown"}),
        ))
        .await
        .unwrap();
    assert!(resp.status().is_client_error(), "got {}", resp.status());
}

#[tokio::test]
async fn rules_round_trip_and_unique_name() {
    let app = test_app().await;
    let tok = token_for(&app, Role::Manager).await;

    let r1 = app
        .router
        .clone()
        .oneshot(req_json(
            "POST",
            "/api/v1/rules",
            &tok,
            json!({"name":"after-hours","definition":{"trigger":"motion","when":"closed"}}),
        ))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::CREATED);
    let body = body_json(r1).await;
    assert_eq!(body["enabled"], true);
    assert_eq!(body["definition"]["trigger"], "motion");
    let id = body["id"].as_i64().unwrap();

    let dup = app
        .router
        .clone()
        .oneshot(req_json(
            "POST",
            "/api/v1/rules",
            &tok,
            json!({"name":"after-hours","definition":{}}),
        ))
        .await
        .unwrap();
    assert_eq!(dup.status(), StatusCode::CONFLICT);

    let patched = app
        .router
        .clone()
        .oneshot(req_json(
            "PATCH",
            &format!("/api/v1/rules/{id}"),
            &tok,
            json!({"enabled": false}),
        ))
        .await
        .unwrap();
    assert_eq!(patched.status(), StatusCode::OK);
    assert_eq!(body_json(patched).await["enabled"], false);
}

#[tokio::test]
async fn events_listing_paginates_and_filters_by_device() {
    let app = test_app().await;
    let tok = token_for(&app, Role::Viewer).await;

    sqlx::query(
        "INSERT INTO device (id, branch_id, kind, status, created_at) VALUES \
         (7, 1, 'camera', 'online', 0), (8, 1, 'camera', 'online', 0)",
    )
    .execute(app.db.pool())
    .await
    .expect("seed devices");
    sqlx::query(
        "INSERT INTO event (branch_id, device_id, kind, ts, payload, ingest_ts) VALUES \
         (1, 7, 'motion', 100, '{\"a\":1}', 100), \
         (1, 7, 'motion', 200, '{\"a\":2}', 200), \
         (1, 8, 'tamper', 300, '{\"a\":3}', 300)",
    )
    .execute(app.db.pool())
    .await
    .expect("seed events");

    let all = app
        .router
        .clone()
        .oneshot(req("GET", "/api/v1/events", &tok))
        .await
        .unwrap();
    assert_eq!(body_json(all).await.as_array().unwrap().len(), 3);

    let only7 = app
        .router
        .clone()
        .oneshot(req("GET", "/api/v1/events?device_id=7", &tok))
        .await
        .unwrap();
    let arr = body_json(only7).await;
    let arr = arr.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert!(arr.iter().all(|v| v["device_id"] == 7));

    let recent = app
        .router
        .clone()
        .oneshot(req("GET", "/api/v1/events?since=250", &tok))
        .await
        .unwrap();
    assert_eq!(body_json(recent).await.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn exceptions_listing_filters_by_status() {
    let app = test_app().await;
    let tok = token_for(&app, Role::Viewer).await;

    sqlx::query(
        "INSERT INTO exception (branch_id, kind, severity, ts, status, created_at, updated_at) VALUES \
         (1, 'no_sale', 'medium', 100, 'open', 100, 100), \
         (1, 'no_sale', 'medium', 200, 'confirmed', 200, 200)",
    )
    .execute(app.db.pool())
    .await
    .expect("seed");

    let open = app
        .router
        .clone()
        .oneshot(req("GET", "/api/v1/exceptions?status=open", &tok))
        .await
        .unwrap();
    let arr = body_json(open).await;
    let arr = arr.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["status"], "open");
}

#[tokio::test]
async fn unknown_id_returns_404_for_each_resource() {
    let app = test_app().await;
    let tok = token_for(&app, Role::Viewer).await;
    for uri in [
        "/api/v1/devices/9999",
        "/api/v1/rules/9999",
        "/api/v1/events/9999",
        "/api/v1/exceptions/9999",
    ] {
        let resp = app
            .router
            .clone()
            .oneshot(req("GET", uri, &tok))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "uri={uri}");
    }
}

#[tokio::test]
async fn protected_routes_reject_missing_token() {
    let app = test_app().await;
    for uri in [
        "/api/v1/devices",
        "/api/v1/rules",
        "/api/v1/events",
        "/api/v1/exceptions",
    ] {
        let resp = app
            .router
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "uri={uri}");
    }
}

#[tokio::test]
async fn openapi_lists_all_phase0_paths() {
    let app = test_app().await;
    let resp = app
        .router
        .clone()
        .oneshot(req(
            "GET",
            "/api/v1/openapi.json",
            "anything", // no auth required for openapi
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let json = body_json(resp).await;
    let paths = json["paths"].as_object().expect("paths");
    for required in [
        "/api/v1/auth/login",
        "/api/v1/auth/me",
        "/api/v1/devices",
        "/api/v1/devices/{id}",
        "/api/v1/rules",
        "/api/v1/rules/{id}",
        "/api/v1/events",
        "/api/v1/events/{id}",
        "/api/v1/exceptions",
        "/api/v1/exceptions/{id}",
    ] {
        assert!(paths.contains_key(required), "missing path {required}");
    }
}
