//! Argon2id-хеширование. Хеш CPU-тяжёлый, поэтому каждый вызов уходит
//! в `spawn_blocking`, а core остаётся без прямой зависимости на tokio.
//!
//! API `password-hash` 0.6: соль генерируется автоматически внутри
//! `hash_password(password)` (через getrandom), передавать её вручную не нужно;
//! `verify_password` принимает готовую PHC-строку прямо как `&str`.

use argon2::{Algorithm, Argon2, Params, PasswordHasher as _, PasswordVerifier, Version};
use async_trait::async_trait;
use auth_core::{AuthError, Result, domain::PasswordHash, ports::PasswordHasher};
use secrecy::{ExposeSecret, SecretString};

use crate::config::Argon2Config;

/// Пароль, на который считается «пустая» проверка в `verify_dummy` — чтобы
/// время ответа на «email не найден» не отличалось от времени на «пароль неверный».
const DUMMY_PASSWORD: &str = "dummy-password-for-timing-safety";

fn build_argon2(cfg: &Argon2Config) -> Result<Argon2<'static>> {
    let params =
        Params::new(cfg.m_cost_kib, cfg.t_cost, cfg.p_cost, None).map_err(AuthError::internal)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn hash_blocking(argon2: &Argon2<'static>, password: &str) -> Result<PasswordHash> {
    let phc = argon2
        .hash_password(password.as_bytes())
        .map_err(AuthError::internal)?;
    Ok(PasswordHash::new(phc.to_string()))
}

fn verify_blocking(argon2: &Argon2<'static>, password: &str, hash: &str) -> Result<bool> {
    // hash — уже готовая PHC-строка; парсить её вручную в Argon2PasswordHash не нужно,
    // verify_password(&str) делает это сам
    Ok(argon2.verify_password(password.as_bytes(), hash).is_ok())
}

pub struct Argon2PasswordHasher {
    argon2: Argon2<'static>,
    /// Посчитан один раз при старте — тем же Argon2, что и настоящие пароли,
    /// иначе время `verify_dummy` не совпадёт со временем реального `verify`.
    dummy_hash: PasswordHash,
}

impl Argon2PasswordHasher {
    /// Сама Argon2-операция синхронная (без await), поэтому конструктор — обычная
    /// sync-функция; async-рантайм для неё не нужен. Единственный побочный эффект —
    /// на старте процесса один раз считается dummy-хеш (~то же время, что один логин).
    pub fn new(cfg: &Argon2Config) -> Result<Self> {
        let argon2 = build_argon2(cfg)?;
        let dummy_hash = hash_blocking(&argon2, DUMMY_PASSWORD)?;
        Ok(Self { argon2, dummy_hash })
    }
}

#[async_trait]
impl PasswordHasher for Argon2PasswordHasher {
    async fn hash(&self, password: &SecretString) -> Result<PasswordHash> {
        let argon2 = self.argon2.clone();
        let password = password.expose_secret().to_owned();
        tokio::task::spawn_blocking(move || hash_blocking(&argon2, &password))
            .await
            .map_err(AuthError::internal)?
    }

    async fn verify(&self, password: &SecretString, hash: &PasswordHash) -> Result<bool> {
        let argon2 = self.argon2.clone();
        let password = password.expose_secret().to_owned();
        let hash = hash.as_str().to_owned();
        tokio::task::spawn_blocking(move || verify_blocking(&argon2, &password, &hash))
            .await
            .map_err(AuthError::internal)?
    }

    async fn verify_dummy(&self, password: &SecretString) {
        let argon2 = self.argon2.clone();
        let password = password.expose_secret().to_owned();
        let hash = self.dummy_hash.as_str().to_owned();
        // результат осознанно игнорируется — единственная цель здесь: потратить
        // столько же времени, сколько потратил бы настоящий verify()
        let _ =
            tokio::task::spawn_blocking(move || verify_blocking(&argon2, &password, &hash)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hasher() -> Argon2PasswordHasher {
        // в тестах — минимальные параметры, иначе каждый тест ждёт реальные ~100ms Argon2
        Argon2PasswordHasher::new(&Argon2Config {
            m_cost_kib: 8,
            t_cost: 1,
            p_cost: 1,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn hash_then_verify_roundtrip() {
        let h = hasher();
        let pw = SecretString::from("correct horse battery staple");
        let hash = h.hash(&pw).await.unwrap();

        assert!(h.verify(&pw, &hash).await.unwrap());
        assert!(!h.verify(&SecretString::from("wrong"), &hash).await.unwrap());
    }

    #[tokio::test]
    async fn same_password_hashes_differently_each_time() {
        // соль случайная — иначе одинаковые пароли давали бы одинаковый PHC,
        // и утечка БД сразу показала бы, у кого пароли совпадают
        let h = hasher();
        let pw = SecretString::from("same password");
        let a = h.hash(&pw).await.unwrap();
        let b = h.hash(&pw).await.unwrap();
        assert_ne!(a.as_str(), b.as_str());
    }

    #[tokio::test]
    async fn malformed_hash_is_rejected_not_panicking() {
        let h = hasher();

        let result = h
            .verify(
                &SecretString::from("x"),
                &PasswordHash::new("not-a-phc-string"),
            )
            .await
            .unwrap();

        assert!(!result);
    }

    #[tokio::test]
    async fn verify_dummy_does_not_panic() {
        hasher().verify_dummy(&SecretString::from("whatever")).await;
    }
}
