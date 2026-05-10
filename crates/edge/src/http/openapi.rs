//! Aggregated OpenAPI document.
//!
//! New paths land here as routes are added. Each handler is annotated with
//! `#[utoipa::path(...)]`; this struct just lists them for the document.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::OpenApi;

use crate::auth::Role;

use super::auth::{LoginRequest, LoginResponse, UserSummary};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "LBC Edge API",
        version = "0.1.0",
        description = "Local API exposed by an LBC edge node. Phase 0 surface."
    ),
    paths(super::auth::login, super::auth::me),
    components(schemas(LoginRequest, LoginResponse, UserSummary, Role)),
    modifiers(&BearerAuthAddon),
)]
pub struct ApiDoc;

struct BearerAuthAddon;

impl utoipa::Modify for BearerAuthAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );
    }
}
