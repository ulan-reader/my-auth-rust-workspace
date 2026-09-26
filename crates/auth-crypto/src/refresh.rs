//! Refresh-токены: 32 криптостойких случайных байта, base64url без паддинга.
//! В БД хранится SHA-256 от токена, а не сам токен — утечка таблицы сессий
//! не даёт готовых токенов для входа.

use auth_core::{AuthError, Result, domain::TokenHash, ports::RefreshTokenProvider};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};

const TOKEN_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, Default)]
pub struct Sha256RefreshTokenProvider;

impl RefreshTokenProvider for Sha256RefreshTokenProvider {
    fn issue(&self) -> Result<auth_core::ports::IssuedRefreshToken> {
        let mut buf = [0u8; TOKEN_BYTES];
        getrandom::fill(&mut buf).map_err(AuthError::internal)?;
        let token = SecretString::from(URL_SAFE_NO_PAD.encode(buf));
        let hash = self.hash(&token);
        Ok(auth_core::ports::IssuedRefreshToken { token, hash })
    }

    fn hash(&self, token: &SecretString) -> TokenHash {
        let digest = Sha256::digest(token.expose_secret().as_bytes());
        TokenHash::new(URL_SAFE_NO_PAD.encode(digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn issued_tokens_are_unique_and_hash_matches() {
        let p = Sha256RefreshTokenProvider;
        let a = p.issue().unwrap();
        let b = p.issue().unwrap();

        assert_ne!(a.token.expose_secret(), b.token.expose_secret());
        assert_eq!(p.hash(&a.token), a.hash);
    }

    #[test]
    fn hash_is_deterministic_and_sensitive_to_input() {
        let p = Sha256RefreshTokenProvider;
        let t1 = SecretString::from("same-token");
        let t2 = SecretString::from("same-token");
        let t3 = SecretString::from("different-token");

        assert_eq!(p.hash(&t1), p.hash(&t2));
        assert_ne!(p.hash(&t1), p.hash(&t3));
    }

    #[test]
    fn token_is_url_safe_without_padding() {
        let issued = Sha256RefreshTokenProvider.issue().unwrap();
        let raw = issued.token.expose_secret();
        assert!(!raw.contains('+') && !raw.contains('/') && !raw.contains('='));
    }
}
