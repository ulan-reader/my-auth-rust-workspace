use auth_core::AuthError;
use axum::{Json, http::StatusCode, response::IntoResponse};
use tracing::warn;

/// Newtype обязателен: orphan rule не даёт impl IntoResponse для чужого AuthError.
pub struct ApiError(pub AuthError);

impl From<AuthError> for ApiError {
    fn from(e: AuthError) -> Self {
        Self(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = match &self.0 {
            AuthError::NotFound => StatusCode::NOT_FOUND,
            AuthError::Conflict => StatusCode::CONFLICT,
            AuthError::Validation(_) => StatusCode::BAD_REQUEST,
            AuthError::InvalidCredentials | AuthError::Unauthorized => StatusCode::UNAUTHORIZED,
            AuthError::AccountDisabled | AuthError::Forbidden => StatusCode::FORBIDDEN,
            AuthError::Internal(_) => {
                warn!(error = %self.0, "internal error");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        };
        (
            status,
            Json(serde_json::json!({ "error": self.0.to_string() })),
        )
            .into_response()
    }
}
