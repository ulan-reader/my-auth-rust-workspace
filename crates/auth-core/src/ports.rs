//! Порты (исходящие): что ядру нужно от внешнего мира. Реализации живут в адаптерах
//! (auth-postgres, auth-crypto, ...). Все трейты dyn-совместимы, рассчитаны на `Arc<dyn ...>`.
//!
//! Договорённости для всех адаптеров:
//! - «записи нет»: `Ok(None)` для `find_*`, `Err(NotFound)` для операций над конкретной записью;
//! - нарушение уникальности -> `Conflict`, битая ссылка (FK) -> `Validation`;
//! - всё остальное (БД, сеть, крипто) -> `AuthError::internal(..)`.

use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secrecy::SecretString;

use crate::{Result, domain::*};

// ===================== ДАННЫЕ, КОТОРЫЕ ХОДЯТ ЧЕРЕЗ ПОРТЫ =====================

pub const DEFAULT_PER_PAGE: i64 = 20;
pub const MAX_PER_PAGE: i64 = 100;

/// Запрос страницы. Всегда нормализован: `page >= 1`, `1 <= per_page <= MAX_PER_PAGE`.
/// Поиск (`search`) — подстрока; экранировать `%` и `_` — забота адаптера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRequest {
    pub page: i64,
    pub per_page: i64,
    pub search: Option<String>,
}

impl PageRequest {
    pub fn new(page: Option<i64>, per_page: Option<i64>, search: Option<String>) -> Self {
        Self {
            page: page.unwrap_or(1).max(1),
            per_page: per_page.unwrap_or(DEFAULT_PER_PAGE).clamp(1, MAX_PER_PAGE),
            search: search
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty()),
        }
    }

    pub fn offset(&self) -> i64 {
        (self.page - 1).saturating_mul(self.per_page)
    }
}

impl Default for PageRequest {
    fn default() -> Self {
        Self::new(None, None, None)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub page: i64,
    pub per_page: i64,
    pub total: i64,
}

impl<T> Page<T> {
    pub fn new(items: Vec<T>, req: &PageRequest, total: i64) -> Self {
        Self {
            items,
            page: req.page,
            per_page: req.per_page,
            total,
        }
    }

    /// Минимум 1, даже для пустой выборки.
    pub fn total_pages(&self) -> i64 {
        ((self.total + self.per_page - 1) / self.per_page).max(1)
    }

    pub fn map<U>(self, f: impl FnMut(T) -> U) -> Page<U> {
        Page {
            items: self.items.into_iter().map(f).collect(),
            page: self.page,
            per_page: self.per_page,
            total: self.total,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub email: Email,
    pub password_hash: PasswordHash,
    pub first_name: String,
    pub second_name: String,
}

#[derive(Debug, Clone)]
pub struct UserUpdate {
    pub email: Email,
    pub first_name: String,
    pub second_name: String,
}

/// Пользователь + хеш пароля: единственное место, где хеш выходит из репозитория.
#[derive(Debug, Clone)]
pub struct UserCredentials {
    pub user: User,
    pub password_hash: PasswordHash,
}

#[derive(Debug, Clone)]
pub struct NewRole {
    pub code: RoleCode,
    pub name: String,
    pub scope: RoleScope,
}

/// `scope` роли менять нельзя: смена ломает уже выданные назначения.
/// Нужно другое — удалить роль и создать заново.
#[derive(Debug, Clone)]
pub struct RoleUpdate {
    pub code: RoleCode,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct NewSession {
    pub user_id: UserId,
    pub token_hash: TokenHash,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Свежий refresh-токен: `token` отдаётся клиенту один раз, `hash` уходит в БД.
#[derive(Debug)]
pub struct IssuedRefreshToken {
    pub token: SecretString,
    pub hash: TokenHash,
}

// ===================== ПОРТЫ: ХРАНИЛИЩЕ =====================

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn find_by_id(&self, id: UserId) -> Result<Option<User>>;

    /// Для логина. `Ok(None)` — такого email нет.
    async fn find_credentials_by_email(&self, email: &Email) -> Result<Option<UserCredentials>>;

    async fn list(&self, req: &PageRequest) -> Result<Page<User>>;

    /// `Conflict`, если email уже занят.
    async fn create(&self, new: &NewUser) -> Result<User>;

    /// `NotFound` / `Conflict` (email занят другим).
    async fn update(&self, id: UserId, upd: &UserUpdate) -> Result<User>;

    async fn set_password_hash(&self, id: UserId, hash: &PasswordHash) -> Result<()>;

    async fn set_active(&self, id: UserId, active: bool) -> Result<()>;

    /// Атомарно вместе с назначениями ролей и сессиями пользователя.
    async fn delete(&self, id: UserId) -> Result<()>;
}

#[async_trait]
pub trait RoleRepository: Send + Sync {
    async fn find_by_id(&self, id: RoleId) -> Result<Option<Role>>;

    async fn list(&self, req: &PageRequest) -> Result<Page<Role>>;

    /// `Conflict`, если код занят.
    async fn create(&self, new: &NewRole) -> Result<Role>;

    async fn update(&self, id: RoleId, upd: &RoleUpdate) -> Result<Role>;

    /// Атомарно вместе с назначениями и правами роли.
    async fn delete(&self, id: RoleId) -> Result<()>;

    async fn permissions_of(&self, role: RoleId) -> Result<Vec<Permission>>;

    /// Атомарно заменяет набор прав роли. Неизвестный `PermissionId` -> `Validation`.
    async fn set_permissions(
        &self,
        role: RoleId,
        permissions: &[PermissionId],
    ) -> Result<Vec<Permission>>;
}

#[async_trait]
pub trait AssignmentRepository: Send + Sync {
    /// Назначения сразу для набора пользователей — одним запросом, без N+1.
    async fn for_users(&self, users: &[UserId]) -> Result<HashMap<UserId, Vec<RoleAssignment>>>;

    /// Соответствие роли и scope (`check_assignment`) проверяет сервис, не адаптер.
    /// `Conflict`, если такая связка уже есть.
    async fn assign(&self, user: UserId, role: RoleId, scope: Option<&ScopeId>) -> Result<()>;

    /// Идемпотентно: отсутствие назначения — не ошибка.
    async fn unassign(&self, user: UserId, role: RoleId, scope: Option<&ScopeId>) -> Result<()>;

    /// Снять все назначения внутри scope. Вызывает проект, когда удаляет
    /// у себя сущность (отдел, проект), чтобы не оставлять висящие права.
    async fn revoke_all_in_scope(&self, scope: &ScopeId) -> Result<u64>;
}

#[async_trait]
pub trait PermissionRepository: Send + Sync {
    async fn list(&self) -> Result<Vec<Permission>>;

    /// Эффективные права пользователя.
    /// - права глобальных ролей действуют всегда;
    /// - права ролей с областью действия — только если `scope == Some(s)`
    ///   и назначение выдано именно на `s`.
    async fn effective_for_user(
        &self,
        user: UserId,
        scope: Option<&ScopeId>,
    ) -> Result<HashSet<PermissionCode>>;
}

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn create(&self, new: &NewSession) -> Result<Session>;

    /// Для проверки access-токена: сессия жива? Ходит в БД на каждый запрос;
    /// если станет узким местом, кэш прячем за этим же портом.
    async fn find_by_id(&self, id: SessionId) -> Result<Option<Session>>;

    /// Включая отозванные и истёкшие: так сервис отличает
    /// «токена нет» от «повторно предъявлен уже использованный токен».
    async fn find_by_token_hash(&self, hash: &TokenHash) -> Result<Option<Session>>;

    async fn list_active(&self, user: UserId, now: DateTime<Utc>) -> Result<Vec<Session>>;

    /// Ротация refresh-токена: в одной транзакции отзывает `old` и создаёт `next`.
    /// Если `old` уже отозвана (гонка, двойное использование) -> `Conflict`.
    async fn rotate(
        &self,
        old: SessionId,
        next: &NewSession,
        now: DateTime<Utc>,
    ) -> Result<Session>;

    /// `NotFound`, если сессии нет или она принадлежит другому пользователю.
    async fn revoke(&self, user: UserId, session: SessionId, now: DateTime<Utc>) -> Result<()>;

    /// Возвращает, сколько сессий отозвано.
    async fn revoke_all_for_user(&self, user: UserId, now: DateTime<Utc>) -> Result<u64>;
}

// ===================== ПОРТЫ: ИНФРАСТРУКТУРА =====================

pub trait Clock: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}

/// `async`, потому что Argon2 тяжёлый: адаптер сам уводит работу в `spawn_blocking`,
/// а core остаётся без зависимости от tokio.
#[async_trait]
pub trait PasswordHasher: Send + Sync {
    async fn hash(&self, password: &SecretString) -> Result<PasswordHash>;

    async fn verify(&self, password: &SecretString, hash: &PasswordHash) -> Result<bool>;

    /// Проверка против заранее посчитанной заглушки. Сервис зовёт её, когда email
    /// не найден: время ответа не должно выдавать, существует ли такой адрес.
    async fn verify_dummy(&self, password: &SecretString);
}

/// Подпись и проверка access-токена.
pub trait AccessTokenCodec: Send + Sync {
    fn encode(&self, claims: &AccessClaims) -> Result<String>;

    /// Проверяет подпись, issuer/audience и срок (по переданному `now`, а не по
    /// системным часам, чтобы тесты были детерминированными). Любая проблема ->
    /// `Unauthorized`, причину клиенту не раскрываем.
    fn decode(&self, token: &str, now: DateTime<Utc>) -> Result<AccessClaims>;
}

pub trait RefreshTokenProvider: Send + Sync {
    /// Новый криптостойкий токен. Сбой генератора случайных чисел -> `Internal`.
    fn issue(&self) -> Result<IssuedRefreshToken>;

    /// Детерминированный хеш предъявленного токена (для поиска сессии).
    fn hash(&self, token: &SecretString) -> TokenHash;
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn page_request_is_normalized() {
        let r = PageRequest::new(Some(0), Some(1000), Some("   ".into()));
        assert_eq!((r.page, r.per_page, r.offset()), (1, MAX_PER_PAGE, 0));
        assert!(r.search.is_none());

        let r = PageRequest::new(Some(3), Some(10), Some(" ab ".into()));
        assert_eq!(r.offset(), 20);
        assert_eq!(r.search.as_deref(), Some("ab"));

        let r = PageRequest::new(Some(i64::MAX), Some(100), None);
        assert!(r.offset() > 0, "смещение не должно переполняться");
    }

    #[test]
    fn total_pages_is_at_least_one() {
        let req = PageRequest::default();
        assert_eq!(Page::<()>::new(vec![], &req, 0).total_pages(), 1);
        assert_eq!(Page::<()>::new(vec![], &req, 20).total_pages(), 1);
        assert_eq!(Page::<()>::new(vec![], &req, 21).total_pages(), 2);
    }

    /// Компилируется -> все порты dyn-совместимы.
    #[test]
    #[allow(clippy::too_many_arguments)]
    fn ports_are_object_safe() {
        fn accepts(
            _: Option<Arc<dyn UserRepository>>,
            _: Option<Arc<dyn RoleRepository>>,
            _: Option<Arc<dyn AssignmentRepository>>,
            _: Option<Arc<dyn PermissionRepository>>,
            _: Option<Arc<dyn SessionRepository>>,
            _: Option<Arc<dyn PasswordHasher>>,
            _: Option<Arc<dyn AccessTokenCodec>>,
            _: Option<Arc<dyn RefreshTokenProvider>>,
            _: Option<Arc<dyn Clock>>,
        ) {
        }
        accepts(None, None, None, None, None, None, None, None, None);
    }
}
