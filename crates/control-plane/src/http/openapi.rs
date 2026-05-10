//! Aggregated OpenAPI document for the Control Plane.

use utoipa::OpenApi;

use super::licenses::{ActivateRequest, ActivateResponse};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "LBC Control Plane API",
        version = "0.1.0",
        description = "Cloud-side licensing and fleet API. Phase 0 surface."
    ),
    paths(super::licenses::activate, super::licenses::revoke),
    components(schemas(ActivateRequest, ActivateResponse))
)]
pub struct ApiDoc;
