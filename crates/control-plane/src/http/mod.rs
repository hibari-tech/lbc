//! HTTP layer for the Control Plane.

pub mod error;
pub mod licenses;

pub(crate) mod meta;
pub(crate) mod openapi;

use axum::routing::{get, post};
use axum::Router;

use crate::signing::LicenseSigner;
use crate::storage::Db;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub signer: LicenseSigner,
}

pub fn router(state: AppState) -> Router {
    let api_v1 = Router::<AppState>::new()
        .route("/healthz", get(meta::healthz))
        .route("/version", get(meta::version))
        .route("/openapi.json", get(meta::openapi_json))
        .route("/licenses/activate", post(licenses::activate))
        .route("/licenses/{id}/revoke", post(licenses::revoke));

    Router::<AppState>::new()
        .route("/healthz", get(meta::healthz))
        .nest("/api/v1", api_v1)
        .with_state(state)
}
