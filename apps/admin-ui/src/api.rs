//! Клиент к auth-server. Прямые fetch-запросы из браузера (CORS у сервера
//! permissive), без прокси. Базовый URL — поменяй здесь, если сервер не на
//! localhost:8080.

use gloo_net::http::{Request, Response};
use serde::{Deserialize, Serialize};

pub const API_BASE: &str = "http://localhost:8080";

#[derive(Debug, Clone)]
pub struct ApiError(pub String);

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Deserialize)]
struct ErrorBody {
    error: String,
}

#[derive(Serialize)]
struct LoginRequest<'a> {
    email: &'a str,
    password: &'a str,
}

#[derive(Deserialize, Clone)]
pub struct TokenPairDto {
    pub access_token: String,
}

#[derive(Deserialize, Serialize, Clone, Copy, Debug)]
pub struct SettingsDto {
    pub allow_self_registration: bool,
}

async fn handle<T: for<'de> Deserialize<'de>>(resp: Response) -> Result<T, ApiError> {
    if resp.ok() {
        resp.json::<T>().await.map_err(|e| ApiError(e.to_string()))
    } else {
        let msg = resp
            .json::<ErrorBody>()
            .await
            .map(|b| b.error)
            .unwrap_or_else(|_| format!("HTTP {}", resp.status()));
        Err(ApiError(msg))
    }
}

pub async fn login(email: &str, password: &str) -> Result<TokenPairDto, ApiError> {
    let resp = Request::post(&format!("{API_BASE}/auth/login"))
        .json(&LoginRequest { email, password })
        .map_err(|e| ApiError(e.to_string()))?
        .send()
        .await
        .map_err(|e| ApiError(e.to_string()))?;
    handle(resp).await
}

pub async fn get_settings(token: &str) -> Result<SettingsDto, ApiError> {
    let resp = Request::get(&format!("{API_BASE}/settings"))
        .header("Authorization", &format!("Bearer {token}"))
        .send()
        .await
        .map_err(|e| ApiError(e.to_string()))?;
    handle(resp).await
}

pub async fn update_settings(token: &str, allow_self_registration: bool) -> Result<SettingsDto, ApiError> {
    let resp = Request::put(&format!("{API_BASE}/settings"))
        .header("Authorization", &format!("Bearer {token}"))
        .json(&SettingsDto { allow_self_registration })
        .map_err(|e| ApiError(e.to_string()))?
        .send()
        .await
        .map_err(|e| ApiError(e.to_string()))?;
    handle(resp).await
}
