//! Axum extractors for HTTP-layer concerns.
//!
//! Lives outside `auth/` so the auth module stays free of axum imports —
//! `admin.rs` and the CLI reuse `auth` without pulling HTTP machinery in.

use axum::extract::{FromRef, FromRequestParts};
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use crate::auth::{token, JwtSecret, Role};

use super::error::ApiError;

/// Authenticated caller derived from a valid `Authorization: Bearer <jwt>`
/// header. Construction is fallible — handlers that take this as a parameter
/// implicitly require auth.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: i64,
    pub role: Role,
    pub branch_scope: Option<Vec<i64>>,
}

impl AuthUser {
    /// Returns `Ok(())` if the caller's role meets `min`, else `Forbidden`.
    pub fn require(&self, min: Role) -> Result<(), ApiError> {
        if self.role.has_at_least(min) {
            Ok(())
        } else {
            Err(ApiError::Forbidden)
        }
    }
}

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    JwtSecret: FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let raw = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .ok_or(ApiError::Unauthorized)?;
        let secret = JwtSecret::from_ref(state);
        let claims = token::verify(&secret, raw).map_err(|_| ApiError::Unauthorized)?;
        Ok(Self {
            user_id: claims.sub,
            role: claims.role,
            branch_scope: claims.branch_scope,
        })
    }
}
