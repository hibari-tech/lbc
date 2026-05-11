//! HTTP layer for the Control Plane.

pub mod admin_auth;
pub mod error;
pub mod licenses;

pub(crate) mod admin;
pub(crate) mod meta;
pub(crate) mod openapi;

use axum::middleware;
use axum::routing::{get, post};
use axum::Router;

use crate::signing::LicenseSigner;
use crate::storage::Db;

pub use admin_auth::AdminGate;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub signer: LicenseSigner,
    pub admin_gate: AdminGate,
}

pub fn router(state: AppState) -> Router {
    let api_v1 = Router::<AppState>::new()
        .route("/healthz", get(meta::healthz))
        .route("/version", get(meta::version))
        .route("/openapi.json", get(meta::openapi_json))
        .route("/licenses/activate", post(licenses::activate))
        .route("/licenses/{id}/heartbeat", post(licenses::heartbeat))
        .route("/licenses/{id}/revoke", post(licenses::revoke));

    let admin = Router::<AppState>::new()
        .route("/", get(admin::index))
        .route(
            "/accounts",
            get(admin::list_accounts).post(admin::create_account),
        )
        .route("/accounts/new", get(admin::new_account_form))
        .route("/branches", get(admin::list_branches))
        .route("/licenses", get(admin::list_licenses))
        .route("/licenses/{id}/revoke", post(admin::revoke_form))
        // The middleware uses the gate from AppState; we pass it
        // through `with_state` on the layer so handlers can keep
        // taking `State<AppState>` unchanged.
        .layer(middleware::from_fn_with_state(
            state.admin_gate.clone(),
            admin_auth::require_basic,
        ));

    Router::<AppState>::new()
        .route("/healthz", get(meta::healthz))
        .nest("/api/v1", api_v1)
        .nest("/admin", admin)
        .with_state(state)
}
