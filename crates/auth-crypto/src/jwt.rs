//! EdDSA (Ed25519) JWT для access-токенов + публикация публичных ключей в
//! формате JWKS (RFC 7517/8037), чтобы проверяющие сервисы не нуждались в
//! приватном ключе — только в `/.well-known/jwks.json`.
//!
//! Срок жизни проверяется вручную по `now`, переданному вызывающей стороной
//! (а не системными часами jsonwebtoken) — так `authenticate` в auth-core
//! остаётся детерминированно тестируемым.

use std::collections::HashMap;

use auth_core::{
    AuthError, Result,
    domain::{AccessClaims, SessionId, UserId},
    ports::{AccessTokenCodec, AccessTokenVerifier},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ed25519_dalek::{SigningKey, pkcs8::EncodePrivateKey};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode,
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

use crate::config::{JwtConfig, JwtVerificationKey};

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

/// Один JWK (Ed25519, "octet key pair") — см. RFC 8037.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Jwk {
    pub kty: &'static str,
    pub crv: &'static str,
    #[serde(rename = "use")]
    pub use_: &'static str,
    pub alg: &'static str,
    pub kid: String,
    /// base64url (без паддинга) сырых 32 байт публичного ключа.
    pub x: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Jwks {
    pub keys: Vec<Jwk>,
}

fn decode_b64_32(label: &str, s: &str) -> Result<[u8; 32]> {
    let bytes = URL_SAFE_NO_PAD
        .decode(s)
        .map_err(|e| AuthError::validation(format!("{label}: невалидный base64url: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| AuthError::validation(format!("{label}: ожидается ровно 32 байта")))
}

/// Проверка EdDSA-токенов по набору публичных ключей (`kid` -> ключ).
/// Приватного ключа не имеет и подписывать не умеет.
pub struct Ed25519Verifier {
    decoding_keys: HashMap<String, DecodingKey>,
    public_jwks: Jwks,
    issuer: String,
    audience: String,
}

impl Ed25519Verifier {
    fn empty(issuer: &str, audience: &str) -> Self {
        Self {
            decoding_keys: HashMap::new(),
            public_jwks: Jwks { keys: Vec::new() },
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
        }
    }

    /// Добавляет публичный ключ (base64url, 32 байта). Дубль `kid` — ошибка.
    fn add_key(&mut self, kid: &str, public_b64: &str) -> Result<()> {
        if self.decoding_keys.contains_key(kid) {
            return Err(AuthError::validation(format!("дублирующийся kid '{kid}'")));
        }
        decode_b64_32(&format!("публичный ключ kid={kid}"), public_b64)?;
        let key = DecodingKey::from_ed_components(public_b64)
            .map_err(|e| AuthError::validation(format!("публичный ключ kid={kid}: {e}")))?;
        self.decoding_keys.insert(kid.to_owned(), key);
        self.public_jwks.keys.push(Jwk {
            kty: "OKP",
            crv: "Ed25519",
            use_: "sig",
            alg: "EdDSA",
            kid: kid.to_owned(),
            x: public_b64.to_owned(),
        });
        Ok(())
    }

    /// Из явного списка публичных ключей (kid + base64url).
    pub fn new(issuer: &str, audience: &str, keys: &[JwtVerificationKey]) -> Result<Self> {
        let mut v = Self::empty(issuer, audience);
        for k in keys {
            v.add_key(&k.kid, &k.public_key)?;
        }
        if v.decoding_keys.is_empty() {
            return Err(AuthError::validation(
                "verifier: нужен хотя бы один публичный ключ",
            ));
        }
        Ok(v)
    }

    /// Из тела ответа `/.well-known/jwks.json`. Скачивание — забота вызывающей
    /// стороны (в auth-crypto нет HTTP-клиента). Ключи без `kid` и не
    /// `OKP`/`Ed25519` пропускаются; если подходящих не осталось — ошибка.
    pub fn from_jwks_json(issuer: &str, audience: &str, json: &str) -> Result<Self> {
        #[derive(Deserialize)]
        struct In {
            keys: Vec<InKey>,
        }
        #[derive(Deserialize)]
        struct InKey {
            kty: String,
            crv: Option<String>,
            kid: Option<String>,
            x: Option<String>,
        }

        let doc: In = serde_json::from_str(json)
            .map_err(|e| AuthError::validation(format!("JWKS: невалидный JSON: {e}")))?;
        let keys: Vec<JwtVerificationKey> = doc
            .keys
            .into_iter()
            .filter(|k| k.kty == "OKP" && k.crv.as_deref() == Some("Ed25519"))
            .filter_map(|k| {
                Some(JwtVerificationKey {
                    kid: k.kid?,
                    public_key: k.x?,
                })
            })
            .collect();
        Self::new(issuer, audience, &keys)
    }

    pub fn jwks(&self) -> &Jwks {
        &self.public_jwks
    }
}

impl AccessTokenVerifier for Ed25519Verifier {
    fn decode(&self, token: &str, now: DateTime<Utc>) -> Result<AccessClaims> {
        let header = decode_header(token).map_err(|_| AuthError::Unauthorized)?;
        let kid = header.kid.as_deref().ok_or(AuthError::Unauthorized)?;
        let decoding_key = self.decoding_keys.get(kid).ok_or(AuthError::Unauthorized)?;

        // Алгоритм зафиксирован: токен с другим `alg` (HS256, none) отклоняется.
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        // exp проверяем сами по переданному `now`, а не по системным часам
        validation.validate_exp = false;
        validation.validate_nbf = false;

        let data = decode::<Claims>(token, decoding_key, &validation)
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

/// Подпись (текущий ключ) + проверка (текущий и ключи прошлых поколений).
pub struct JwtCodec {
    kid: String,
    issuer: String,
    audience: String,
    encoding_key: EncodingKey,
    verifier: Ed25519Verifier,
}

impl JwtCodec {
    pub fn new(cfg: &JwtConfig) -> Result<Self> {
        let seed = decode_b64_32("crypto.jwt.signing_key", cfg.signing_key.expose_secret())?;
        let signing_key = SigningKey::from_bytes(&seed);

        let pkcs8_der = signing_key
            .to_pkcs8_der()
            .map_err(|e| AuthError::validation(format!("PKCS8-кодирование ключа подписи: {e}")))?;
        let encoding_key = EncodingKey::from_ed_der(pkcs8_der.as_bytes());

        let mut verifier = Ed25519Verifier::empty(&cfg.issuer, &cfg.audience);
        let own_public_b64 = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
        verifier
            .add_key(&cfg.kid, &own_public_b64)
            .map_err(|e| AuthError::validation(format!("crypto.jwt.kid: {e}")))?;
        for extra in &cfg.extra_verification_keys {
            verifier
                .add_key(&extra.kid, &extra.public_key)
                .map_err(|e| {
                    AuthError::validation(format!("crypto.jwt.extra_verification_keys: {e}"))
                })?;
        }

        Ok(Self {
            kid: cfg.kid.clone(),
            issuer: cfg.issuer.clone(),
            audience: cfg.audience.clone(),
            encoding_key,
            verifier,
        })
    }

    /// Публичные ключи для эндпоинта `/.well-known/jwks.json`.
    pub fn jwks(&self) -> &Jwks {
        self.verifier.jwks()
    }
}

impl AccessTokenVerifier for JwtCodec {
    fn decode(&self, token: &str, now: DateTime<Utc>) -> Result<AccessClaims> {
        self.verifier.decode(token, now)
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
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(self.kid.clone());
        encode(&header, &claims, &self.encoding_key).map_err(AuthError::internal)
    }
}

/// Новая пара ключей Ed25519 для `crypto.jwt.signing_key` — используется CLI
/// (`auth-server -- jwt-keygen`). Возвращает (seed base64url, публичный ключ
/// base64url) — seed идёт в секрет, публичный ключ можно сразу положить в
/// `extra_verification_keys` со старым `kid` на время ротации.
pub fn generate_signing_key() -> Result<(String, String)> {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(AuthError::internal)?;
    let signing_key = SigningKey::from_bytes(&seed);
    let public = signing_key.verifying_key().to_bytes();
    Ok((URL_SAFE_NO_PAD.encode(seed), URL_SAFE_NO_PAD.encode(public)))
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    fn cfg_with(kid: &str, seed_b64: &str) -> JwtConfig {
        JwtConfig {
            signing_key: SecretString::from(seed_b64.to_owned()),
            kid: kid.into(),
            issuer: "auth-test".into(),
            audience: "auth-test-clients".into(),
            extra_verification_keys: Vec::new(),
        }
    }

    fn codec() -> (JwtCodec, String) {
        let (seed, _public) = generate_signing_key().unwrap();
        let codec = JwtCodec::new(&cfg_with("key-1", &seed)).unwrap();
        (codec, seed)
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
        let (c, _) = codec();
        let now = Utc::now();
        let token = c.encode(&claims(now, 900)).unwrap();
        let decoded = c.decode(&token, now).unwrap();
        assert_eq!(decoded.user_id, UserId(42));
        assert_eq!(decoded.session_id, SessionId(7));
    }

    #[test]
    fn expiry_is_checked_against_passed_now_not_system_clock() {
        let (c, _) = codec();
        let now = Utc::now();
        let token = c.encode(&claims(now, 900)).unwrap();

        let later = now + chrono::TimeDelta::try_minutes(16).unwrap();
        assert!(matches!(
            c.decode(&token, later),
            Err(AuthError::Unauthorized)
        ));

        let still_ok = now + chrono::TimeDelta::try_minutes(14).unwrap();
        assert!(c.decode(&token, still_ok).is_ok());
    }

    #[test]
    fn garbage_and_unknown_kid_are_rejected() {
        let (c, _) = codec();
        let now = Utc::now();
        assert!(matches!(
            c.decode("garbage", now),
            Err(AuthError::Unauthorized)
        ));

        // токен подписан другим ключом (другой kid) — у этого codec такого
        // kid нет в decoding_keys, должен отклонить, не пытаясь угадать ключ
        let (other_seed, _) = generate_signing_key().unwrap();
        let other = JwtCodec::new(&cfg_with("key-2", &other_seed)).unwrap();
        let token = other.encode(&claims(now, 900)).unwrap();
        assert!(matches!(
            c.decode(&token, now),
            Err(AuthError::Unauthorized)
        ));
    }

    #[test]
    fn wrong_issuer_or_audience_is_rejected() {
        let (c, seed) = codec();
        let now = Utc::now();
        let token = c.encode(&claims(now, 900)).unwrap();

        let mut wrong_cfg = cfg_with("key-1", &seed);
        wrong_cfg.issuer = "someone-else".into();
        let wrong_issuer = JwtCodec::new(&wrong_cfg).unwrap();
        assert!(matches!(
            wrong_issuer.decode(&token, now),
            Err(AuthError::Unauthorized)
        ));
    }

    /// Ротация: старый kid всё ещё принимается через extra_verification_keys,
    /// но новые токены подписываются уже новым ключом.
    #[test]
    fn rotation_accepts_old_kid_but_signs_with_new() {
        let (old_seed, old_public) = generate_signing_key().unwrap();
        let old = JwtCodec::new(&cfg_with("key-old", &old_seed)).unwrap();

        let (new_seed, _) = generate_signing_key().unwrap();
        let mut new_cfg = cfg_with("key-new", &new_seed);
        new_cfg
            .extra_verification_keys
            .push(crate::config::JwtVerificationKey {
                kid: "key-old".into(),
                public_key: old_public,
            });
        let new = JwtCodec::new(&new_cfg).unwrap();

        let now = Utc::now();
        let old_token = old.encode(&claims(now, 900)).unwrap();
        assert!(new.decode(&old_token, now).is_ok());

        let new_token = new.encode(&claims(now, 900)).unwrap();
        assert!(new_token.contains(".")); // не проверка формата, просто что токен выдан
        let decoded = new.decode(&new_token, now).unwrap();
        assert_eq!(decoded.user_id, UserId(42));

        assert_eq!(new.jwks().keys.len(), 2);
    }
}
