//! Uniform JSON error type for the Control Plane HTTP layer.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    Unauthorized,
    NotFound,
    BadRequest(String),
    Conflict(String),
    Gone(String),
    Internal(anyhow::Error),
}

impl ApiError {
    fn status(&self) -> StatusCode {
        match self {
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Conflict(_) => StatusCode::CONFLICT,
            Self::Gone(_) => StatusCode::GONE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::NotFound => "not_found",
            Self::BadRequest(_) => "bad_request",
            Self::Conflict(_) => "conflict",
            Self::Gone(_) => "gone",
            Self::Internal(_) => "internal",
        }
    }

    fn message(&self) -> &str {
        match self {
            Self::Unauthorized => "unauthorized",
            Self::NotFound => "not found",
            Self::BadRequest(m) | Self::Conflict(m) | Self::Gone(m) => m,
            Self::Internal(_) => "internal server error",
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Self::Internal(ref e) = self {
            tracing::error!(error = ?e, "control plane internal error");
        }
        let body = json!({ "error": self.kind(), "message": self.message() });
        (self.status(), Json(body)).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        Self::Internal(e.into())
    }
}
