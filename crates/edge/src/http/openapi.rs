//! Aggregated OpenAPI document.
//!
//! New paths land here as routes are added. Each handler is annotated with
//! `#[utoipa::path(...)]`; this struct just lists them for the document.

use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::OpenApi;

use crate::auth::Role;

use super::auth::{LoginRequest, LoginResponse, UserSummary};
use super::devices::{DeviceCreate, DevicePatch, DeviceRead};
use super::events::EventRead;
use super::exceptions::ExceptionRead;
use super::ingest::IngestResponse;
use super::rules::{RuleCreate, RulePatch, RuleRead};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "LBC Edge API",
        version = "0.1.0",
        description = "Local API exposed by an LBC edge node."
    ),
    paths(
        super::auth::login,
        super::auth::me,
        super::devices::list,
        super::devices::create,
        super::devices::get,
        super::devices::patch,
        super::devices::delete,
        super::rules::list,
        super::rules::create,
        super::rules::get,
        super::rules::patch,
        super::rules::delete,
        super::events::list,
        super::events::get,
        super::exceptions::list,
        super::exceptions::get,
        super::ingest::webhook,
    ),
    components(schemas(
        LoginRequest, LoginResponse, UserSummary, Role,
        DeviceRead, DeviceCreate, DevicePatch,
        RuleRead, RuleCreate, RulePatch,
        EventRead, ExceptionRead,
        IngestResponse,
    )),
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
