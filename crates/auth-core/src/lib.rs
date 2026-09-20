//! auth-core — домен, порты и use-case'ы. Никакой инфраструктуры:
//! ни sqlx, ни axum, ни argon2, ни jwt.

pub mod domain;
pub mod error;
pub mod ports;
pub mod service;

#[cfg(test)]
mod testing;

pub use error::AuthError;

pub type Result<T, E = AuthError> = std::result::Result<T, E>;
