//! auth-crypto — реализации портов auth-core: Argon2id-хеширование паролей,
//! EdDSA(Ed25519)-JWT для access-токенов (+ JWKS), криптостойкие refresh-токены.

pub mod config;
pub mod jwt;
pub mod password;
pub mod refresh;

pub use config::{CryptoConfig, JwtConfig, JwtVerificationKey};
pub use jwt::{Ed25519Verifier, Jwk, Jwks, JwtCodec, generate_signing_key};
pub use password::Argon2PasswordHasher;
pub use refresh::Sha256RefreshTokenProvider;
