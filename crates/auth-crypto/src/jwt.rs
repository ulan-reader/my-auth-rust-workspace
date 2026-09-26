//! HS256-JWT для access-токенов. Срок жизни проверяется вручную по `now`,
//! переданному вызывающей стороной (а не системными часами jsonwebtoken) —
//! так `authenticate` в auth-core остаётся детерминированно тестируемым.

use auth_core::{
    AuthError, Result,
    domain::{AccessClaims, SessionId, UserId},
    ports::AccessTokenCodec,
};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::config::JwtConfig;

/// Сериализуемая форма claims. Отдельно от `domain::AccessClaims` намеренно:
/// формат токена (имена полей, unix-время) — деталь адаптера, а не домена.
#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: i64,
    sid: i64,
    iat: i64,
    exp: i64,
    iss: String,
    aud: String,
}

pub struct JwtCodec {
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    issuer: String,
    audience: String,
}

impl JwtCodec {
    pub fn new(cfg: &JwtConfig) -> Self {
        let secret = cfg.secret.expose_secret().as_bytes();
        Self {
            encoding_key: EncodingKey::from_secret(secret),
            decoding_key: DecodingKey::from_secret(secret),
            issuer: cfg.issuer.clone(),
            audience: cfg.audience.clone(),
        }
    }
}

impl AccessTokenCodec for JwtCodec {
    fn encode(&self, claims: &AccessClaims) -> Result<String> {
        let claims = Claims {
            sub: claims.user_id.0,
            sid: claims.session_id.0,
            iat: claims.issued_at.timestamp(),
            exp: claims.expires_at.timestamp(),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
        };
        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding_key)
            .map_err(AuthError::internal)
    }

    fn decode(&self, token: &str, now: DateTime<Utc>) -> Result<AccessClaims> {
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        // exp проверяем сами по переданному `now`, а не по системным часам —
        // это единственная причина, по которой встроенная проверка выключена
        validation.validate_exp = false;
        validation.validate_nbf = false;

        let data = decode::<Claims>(token, &self.decoding_key, &validation)
            .map_err(|_| AuthError::Unauthorized)?;
        let claims = data.claims;

        let issued_at = DateTime::from_timestamp(claims.iat, 0).ok_or(AuthError::Unauthorized)?;
        let expires_at = DateTime::from_timestamp(claims.exp, 0).ok_or(AuthError::Unauthorized)?;
        if expires_at <= now {
            return Err(AuthError::Unauthorized);
        }

        Ok(AccessClaims {
            user_id: UserId(claims.sub),
            session_id: SessionId(claims.sid),
            issued_at,
            expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    fn codec() -> JwtCodec {
        JwtCodec::new(&JwtConfig {
            secret: SecretString::from("test-secret-at-least-32-bytes-long"),
            issuer: "auth-test".into(),
            audience: "auth-test-clients".into(),
        })
    }

    fn claims(now: DateTime<Utc>, ttl_secs: i64) -> AccessClaims {
        AccessClaims {
            user_id: UserId(42),
            session_id: SessionId(7),
            issued_at: now,
            expires_at: now + chrono::TimeDelta::try_seconds(ttl_secs).unwrap(),
        }
    }

    #[test]
    fn roundtrip() {
        let c = codec();
        let now = Utc::now();
        let token = c.encode(&claims(now, 900)).unwrap();
        let decoded = c.decode(&token, now).unwrap();
        assert_eq!(decoded.user_id, UserId(42));
        assert_eq!(decoded.session_id, SessionId(7));
    }

    #[test]
    fn expiry_is_checked_against_passed_now_not_system_clock() {
        let c = codec();
        let now = Utc::now();
        let token = c.encode(&claims(now, 900)).unwrap();

        // "сейчас" ушло на 16 минут вперёд относительно момента выдачи — токен мёртв,
        // хотя системные часы за это время не двигались вовсе
        let later = now + chrono::TimeDelta::try_minutes(16).unwrap();
        assert!(matches!(
            c.decode(&token, later),
            Err(AuthError::Unauthorized)
        ));

        // а на 14-й минуте ещё жив
        let still_ok = now + chrono::TimeDelta::try_minutes(14).unwrap();
        assert!(c.decode(&token, still_ok).is_ok());
    }

    #[test]
    fn garbage_and_wrong_secret_are_rejected() {
        let c = codec();
        let now = Utc::now();
        assert!(matches!(
            c.decode("garbage", now),
            Err(AuthError::Unauthorized)
        ));

        let token = c.encode(&claims(now, 900)).unwrap();
        let other = JwtCodec::new(&JwtConfig {
            secret: SecretString::from("a-completely-different-secret-value"),
            issuer: "auth-test".into(),
            audience: "auth-test-clients".into(),
        });
        assert!(matches!(
            other.decode(&token, now),
            Err(AuthError::Unauthorized)
        ));
    }

    #[test]
    fn wrong_issuer_or_audience_is_rejected() {
        let now = Utc::now();
        let token = codec().encode(&claims(now, 900)).unwrap();

        let wrong_issuer = JwtCodec::new(&JwtConfig {
            secret: SecretString::from("test-secret-at-least-32-bytes-long"),
            issuer: "someone-else".into(),
            audience: "auth-test-clients".into(),
        });
        assert!(matches!(
            wrong_issuer.decode(&token, now),
            Err(AuthError::Unauthorized)
        ));
    }
}
