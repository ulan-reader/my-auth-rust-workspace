use auth_core::{AuthError, service::AuthContext};
use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};

use crate::{ApiState, error::ApiError};

pub struct AuthCtx(pub AuthContext);

impl FromRequestParts<ApiState> for AuthCtx {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &ApiState,
    ) -> Result<Self, Self::Rejection> {
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(ApiError(AuthError::Unauthorized))?;
        let ctx = state.auth.authenticate(token).await?;
        Ok(Self(ctx))
    }
}

/// Лёгкая проверка без БД — только подпись и срок JWT, без учёта мгновенного
/// отзыва сессии/деактивации (это знает только auth-server через AuthCtx).
/// Для стороннего микросервиса, который не хочет держать у себя Postgres auth:
/// нужен только тот же JWT-секрет (через auth-crypto::JwtCodec).
#[derive(Clone)]
pub struct JwtVerifier {
    pub codec: std::sync::Arc<dyn auth_core::ports::AccessTokenCodec>,
    pub clock: std::sync::Arc<dyn auth_core::ports::Clock>,
}

impl JwtVerifier {
    pub fn new(
        codec: std::sync::Arc<dyn auth_core::ports::AccessTokenCodec>,
        clock: std::sync::Arc<dyn auth_core::ports::Clock>,
    ) -> Self {
        Self { codec, clock }
    }
}

pub struct RemoteAuthCtx(pub auth_core::domain::AccessClaims);

impl<S> FromRequestParts<S> for RemoteAuthCtx
where
    S: Send + Sync,
    JwtVerifier: axum::extract::FromRef<S>,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let verifier = <JwtVerifier as axum::extract::FromRef<S>>::from_ref(state);
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .ok_or(ApiError(AuthError::Unauthorized))?;
        let claims = verifier.codec.decode(token, verifier.clock.now())?;
        Ok(Self(claims))
    }
}

// Использование в стороннем Axum-сервисе (например, Хижина, свой AppState):
// #[derive(Clone)]
// struct AppState {
//     verifier: auth_api::extract::JwtVerifier,
//     // ...своё
// }
// impl axum::extract::FromRef<AppState> for auth_api::extract::JwtVerifier {
//     fn from_ref(s: &AppState) -> Self { s.verifier.clone() }
// }
//
// // секрет — тот же AUTH__CRYPTO__JWT__SECRET, что у auth-server
// let verifier = JwtVerifier::new(
//     Arc::new(JwtCodec::new(&jwt_cfg)),
//     Arc::new(auth_core::ports::SystemClock),
// );
//
// async fn my_handler(RemoteAuthCtx(claims): RemoteAuthCtx) -> impl IntoResponse {
//     // claims.user_id — дальше сервис сам решает, что этому user_id можно
// }
