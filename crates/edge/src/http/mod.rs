//! HTTP layer for the edge node.
//!
//! Public entry point is [`router`], which turns an [`AppState`] into a
//! fully-wired axum router. Sub-modules host handlers grouped by resource;
//! none of them should be `pub` outside this directory — the only callers
//! are the router builder and the integration test harness.

pub mod error;
pub mod extractors;

pub(crate) mod auth;
pub(crate) mod devices;
pub(crate) mod events;
pub(crate) mod exceptions;
pub(crate) mod ingest;
pub(crate) mod meta;
pub(crate) mod openapi;
pub(crate) mod rules;

use axum::extract::FromRef;
use axum::routing::{get, post};
use axum::Router;

use crate::actions::ActionsConfig;
use crate::auth::JwtSecret;
use crate::rules::RuleEngine;
use crate::storage::Db;

/// Branch id every Phase-0 CRUD endpoint implicitly uses until license
/// activation in §0.9 mints real branches and rotates this constant out.
/// Grep for `DEFAULT_BRANCH_ID` when wiring real branch scoping.
pub(crate) const DEFAULT_BRANCH_ID: i64 = 1;

#[derive(Clone, FromRef)]
pub struct AppState {
    pub db: Db,
    pub jwt_secret: JwtSecret,
    pub session_ttl_secs: u64,
    pub rule_engine: RuleEngine,
    pub actions_cfg: ActionsConfig,
}

pub fn router(state: AppState) -> Router {
    let api_v1 = Router::<AppState>::new()
        .route("/healthz", get(meta::healthz))
        .route("/version", get(meta::version))
        .route("/openapi.json", get(meta::openapi_json))
        .route("/auth/login", post(auth::login))
        .route("/auth/me", get(auth::me))
        .route("/devices", get(devices::list).post(devices::create))
        .route(
            "/devices/{id}",
            get(devices::get)
                .patch(devices::patch)
                .delete(devices::delete),
        )
        .route("/rules", get(rules::list).post(rules::create))
        .route(
            "/rules/{id}",
            get(rules::get).patch(rules::patch).delete(rules::delete),
        )
        .route("/events", get(events::list))
        .route("/events/{id}", get(events::get))
        .route("/exceptions", get(exceptions::list))
        .route("/exceptions/{id}", get(exceptions::get))
        .route("/ingest/webhooks/{device_id}", post(ingest::webhook));

    Router::<AppState>::new()
        .route("/healthz", get(meta::healthz))
        .nest("/api/v1", api_v1)
        .with_state(state)
}
