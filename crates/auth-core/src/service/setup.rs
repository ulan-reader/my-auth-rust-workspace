//! Одноразовая первоначальная настройка: первый администратор без CLI.

use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use tracing::{Level, info, instrument, warn};

use super::{
    Ports,
    users::{clean_name, validate_password},
};
use crate::{
    AuthError, Result,
    domain::{Email, User},
    ports::{Clock, NewUser, PasswordHasher, SetupRepository},
};

#[derive(Debug)]
pub struct SetupInput {
    pub setup_token: SecretString,
    pub email: String,
    pub password: SecretString,
    pub first_name: String,
    pub second_name: String,
}

#[derive(Clone)]
pub struct SetupService {
    repo: Arc<dyn SetupRepository>,
    hasher: Arc<dyn PasswordHasher>,
    clock: Arc<dyn Clock>,
    /// `None` — секрет не задан, настройка через API выключена.
    token: Option<Arc<SecretString>>,
}

impl SetupService {
    pub fn new(
        repo: Arc<dyn SetupRepository>,
        hasher: Arc<dyn PasswordHasher>,
        clock: Arc<dyn Clock>,
        token: Option<SecretString>,
    ) -> Self {
        Self {
            repo,
            hasher,
            clock,
            token: token.map(Arc::new),
        }
    }

    pub fn from_ports(ports: &Ports, token: Option<SecretString>) -> Self {
        Self::new(
            ports.setup.clone(),
            ports.hasher.clone(),
            ports.clock.clone(),
            token,
        )
    }

    /// Показывать ли экран первоначальной настройки.
    pub async fn is_required(&self) -> Result<bool> {
        if self.token.is_none() {
            return Ok(false);
        }
        Ok(!self.repo.is_completed().await?)
    }

    #[instrument(skip_all, err(level = Level::WARN))]
    pub async fn initialize(&self, input: SetupInput) -> Result<User> {
        // Выключено или уже сделано — 404: не подсказываем, что эндпоинт вообще есть.
        let Some(expected) = &self.token else {
            return Err(AuthError::NotFound);
        };
        if self.repo.is_completed().await? {
            return Err(AuthError::NotFound);
        }
        if !constant_time_eq(
            input.setup_token.expose_secret().as_bytes(),
            expected.expose_secret().as_bytes(),
        ) {
            warn!("первоначальная настройка: неверный секрет");
            return Err(AuthError::Forbidden);
        }

        let email = Email::parse(&input.email)?;
        validate_password(&input.password)?;
        let new = NewUser {
            email,
            password_hash: self.hasher.hash(&input.password).await?,
            first_name: clean_name(&input.first_name, "имя")?,
            second_name: clean_name(&input.second_name, "фамилия")?,
        };

        // Окончательная проверка «уже настроено» — внутри транзакции под блокировкой:
        // из параллельных запросов пройдёт ровно один.
        let user = self.repo.create_first_admin(&new, self.clock.now()).await?;
        info!(user_id = user.id.0, "первоначальная настройка завершена");
        Ok(user)
    }
}

/// Без раннего выхода: время не зависит от того, сколько символов совпало.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}
