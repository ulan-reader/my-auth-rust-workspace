use std::error::Error as StdError;

use thiserror::Error;

/// Единственный тип ошибки ядра. Адаптеры мапят в него свои ошибки
/// (sqlx, hasher, jwt), а api мапит его в HTTP-статусы.
#[derive(Debug, Error)]
pub enum AuthError {
    #[error("не найдено")]
    NotFound,
    #[error("конфликт: такая запись уже существует")]
    Conflict,
    #[error("некорректные данные: {0}")]
    Validation(String),
    /// Одинаковый ответ и для «нет такого email», и для «неверный пароль» —
    /// чтобы нельзя было перебирать существующие адреса.
    #[error("неверный email или пароль")]
    InvalidCredentials,
    #[error("требуется аутентификация")]
    Unauthorized,
    #[error("недостаточно прав")]
    Forbidden,
    #[error("аккаунт отключён")]
    AccountDisabled,
    /// Текст для клиента общий, причина остаётся в `source` — только для логов.
    #[error("внутренняя ошибка")]
    Internal(#[source] Box<dyn StdError + Send + Sync>),
}

impl AuthError {
    pub fn validation(msg: impl Into<String>) -> Self {
        Self::Validation(msg.into())
    }

    pub fn internal(err: impl StdError + Send + Sync + 'static) -> Self {
        Self::Internal(Box::new(err))
    }
}
