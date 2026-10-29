//! Порты (исходящие): что ядру нужно от внешнего мира. Реализации живут в адаптерах
//! (auth-postgres, auth-crypto, ...). Все трейты dyn-совместимы, рассчитаны на `Arc<dyn ...>`.
//!
//! Договорённости для всех адаптеров:
//! - «записи нет»: `Ok(None)` для `find_*`, `Err(NotFound)` для операций над конкретной записью;
//! - нарушение уникальности -> `Conflict`, битая ссылка (FK) -> `Validation`;
//! - всё остальное (БД, сеть, крипто) -> `AuthError::internal(..)`.
//!
//! Транзакции:
//! - пишущие методы принимают `&mut dyn Tx` и работают внутри неё; сами не коммитят;
//! - читающие (`find_*`, `list*`) идут мимо транзакции и не видят её незакоммиченных изменений;
//! - если метод вернул ошибку, вызывающий не должен коммитить: `Tx`, сброшенная без
//!   `commit`, откатывается — так «откатываются изменения» во всех контрактах ниже.

use std::{
    any::Any,
    collections::{BTreeMap, HashMap, HashSet},
};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use secrecy::SecretString;

use crate::{Result, domain::*};

// ===================== ТРАНЗАКЦИИ =====================

/// Открытая транзакция хранилища. Ядро её не разглядывает — только передаёт
/// в методы репозиториев и в конце коммитит.
///
/// Без `commit` (ранний выход по `?`, паника) транзакция откатывается при drop.
/// Передавать `Tx` можно только в репозитории того же адаптера, который её создал;
/// чужая -> `Internal`.
#[async_trait]
pub trait Tx: Send {
    /// Для адаптера: достать из `dyn Tx` свой конкретный тип (`downcast_mut`).
    /// Ядро этим не пользуется.
    fn as_any_mut(&mut self) -> &mut dyn Any;

    async fn commit(self: Box<Self>) -> Result<()>;
}

/// Фабрика транзакций. Один use-case — одна транзакция:
/// `begin` -> вызовы репозиториев с `&mut *tx` -> `commit`.
#[async_trait]
pub trait UnitOfWork: Send + Sync {
    async fn begin(&self) -> Result<Box<dyn Tx>>;
}

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

/// Роль вместе с её правами, прочитанными под блокировкой (см. `RoleRepository::lock`).
#[derive(Debug, Clone)]
pub struct LockedRole {
    pub role: Role,
    pub permissions: Vec<Permission>,
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
    async fn create(&self, tx: &mut dyn Tx, new: &NewUser) -> Result<User>;

    /// `NotFound` / `Conflict` (email занят другим).
    async fn update(&self, tx: &mut dyn Tx, id: UserId, upd: &UserUpdate) -> Result<User>;

    async fn set_password_hash(
        &self,
        tx: &mut dyn Tx,
        id: UserId,
        hash: &PasswordHash,
    ) -> Result<()>;

    /// Не может оставить систему без активного администратора: если до операции
    /// админ был, а после не осталось ни одного — `Validation` (транзакцию не коммитить).
    async fn set_active(&self, tx: &mut dyn Tx, id: UserId, active: bool) -> Result<()>;

    /// Назначения ролей и сессии пользователя удаляются вместе с ним, в той же `tx`.
    /// Не может оставить систему без активного администратора: если до операции
    /// админ был, а после не осталось ни одного — `Validation` (транзакцию не коммитить).
    async fn delete(&self, tx: &mut dyn Tx, id: UserId) -> Result<()>;
}

#[async_trait]
pub trait RoleRepository: Send + Sync {
    async fn find_by_id(&self, id: RoleId) -> Result<Option<Role>>;

    /// Блокирует роль до конца `tx` и читает её права уже под блокировкой.
    /// Сервис берёт её перед любой правкой роли, её прав или назначений — поэтому
    /// параллельные операции над одной ролью идут по очереди, а проверки сервиса
    /// («у актора есть все права роли», «это не admin») остаются верными до commit.
    /// Роли нет -> `Ok(None)`.
    async fn lock(&self, tx: &mut dyn Tx, id: RoleId) -> Result<Option<LockedRole>>;

    async fn list(&self, req: &PageRequest) -> Result<Page<Role>>;

    /// `Conflict`, если код занят.
    async fn create(&self, tx: &mut dyn Tx, new: &NewRole) -> Result<Role>;

    async fn update(&self, tx: &mut dyn Tx, id: RoleId, upd: &RoleUpdate) -> Result<Role>;

    /// Назначения и права роли удаляются вместе с ней, в той же `tx`.
    async fn delete(&self, tx: &mut dyn Tx, id: RoleId) -> Result<()>;

    async fn permissions_of(&self, role: RoleId) -> Result<Vec<Permission>>;

    /// Заменяет набор прав роли и возвращает новый набор (видимый внутри `tx`).
    /// Нет роли -> `NotFound`; неизвестный `PermissionId` -> `Validation`.
    async fn set_permissions(
        &self,
        tx: &mut dyn Tx,
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
    async fn assign(
        &self,
        tx: &mut dyn Tx,
        user: UserId,
        role: RoleId,
        scope: Option<&ScopeId>,
    ) -> Result<()>;

    /// Идемпотентно: отсутствие назначения — не ошибка.
    /// Не может оставить систему без активного администратора: если до операции
    /// админ был, а после не осталось ни одного — `Validation` (транзакцию не коммитить).
    async fn unassign(
        &self,
        tx: &mut dyn Tx,
        user: UserId,
        role: RoleId,
        scope: Option<&ScopeId>,
    ) -> Result<()>;

    /// Снять все назначения внутри scope. Вызывает проект, когда удаляет
    /// у себя сущность (отдел, проект), чтобы не оставлять висящие права.
    async fn revoke_all_in_scope(&self, tx: &mut dyn Tx, scope: &ScopeId) -> Result<u64>;
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
    async fn create(&self, tx: &mut dyn Tx, new: &NewSession) -> Result<Session>;

    /// Для проверки access-токена: сессия жива? Ходит в БД на каждый запрос;
    /// если станет узким местом, кэш прячем за этим же портом.
    async fn find_by_id(&self, id: SessionId) -> Result<Option<Session>>;

    /// Включая отозванные и истёкшие: так сервис отличает
    /// «токена нет» от «повторно предъявлен уже использованный токен».
    async fn find_by_token_hash(&self, hash: &TokenHash) -> Result<Option<Session>>;

    async fn list_active(&self, user: UserId, now: DateTime<Utc>) -> Result<Vec<Session>>;

    /// Ротация refresh-токена: внутри `tx` блокирует и отзывает `old`, создаёт `next`.
    /// Если `old` уже отозвана (гонка, двойное использование) -> `Conflict`.
    async fn rotate(
        &self,
        tx: &mut dyn Tx,
        old: SessionId,
        next: &NewSession,
        now: DateTime<Utc>,
    ) -> Result<Session>;

    /// `NotFound`, если сессии нет или она принадлежит другому пользователю.
    async fn revoke(
        &self,
        tx: &mut dyn Tx,
        user: UserId,
        session: SessionId,
        now: DateTime<Utc>,
    ) -> Result<()>;

    /// Возвращает, сколько сессий отозвано.
    async fn revoke_all_for_user(
        &self,
        tx: &mut dyn Tx,
        user: UserId,
        now: DateTime<Utc>,
    ) -> Result<u64>;

    /// Удаляет мёртвые сессии (просроченные или отозванные до `before`) — обслуживающая
    /// операция для периодической чистки, а не бизнес-правило. Возвращает, сколько удалено.
    async fn purge_stale(&self, tx: &mut dyn Tx, before: DateTime<Utc>) -> Result<u64>;

    /// То же самое, но без `except` — для самостоятельной смены пароля:
    /// сессия, которой вызывающий пользуется прямо сейчас, должна пережить вызов,
    /// иначе он тут же вылетит из-под себя на середине запроса.
    async fn revoke_all_for_user_except(
        &self,
        tx: &mut dyn Tx,
        user: UserId,
        except: SessionId,
        now: DateTime<Utc>,
    ) -> Result<u64>;
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

/// Только проверка access-токена — этого достаточно стороннему сервису,
/// у которого нет приватного ключа (см. `auth-crypto::Ed25519Verifier`).
pub trait AccessTokenVerifier: Send + Sync {
    /// Проверяет подпись, issuer/audience и срок (по переданному `now`, а не по
    /// системным часам, чтобы тесты были детерминированными). Любая проблема ->
    /// `Unauthorized`, причину клиенту не раскрываем.
    fn decode(&self, token: &str, now: DateTime<Utc>) -> Result<AccessClaims>;
}

/// Подпись access-токена + проверка (всё из `AccessTokenVerifier`).
pub trait AccessTokenCodec: AccessTokenVerifier {
    fn encode(&self, claims: &AccessClaims) -> Result<String>;
}

pub trait RefreshTokenProvider: Send + Sync {
    /// Новый криптостойкий токен. Сбой генератора случайных чисел -> `Internal`.
    fn issue(&self) -> Result<IssuedRefreshToken>;

    /// Детерминированный хеш предъявленного токена (для поиска сессии).
    fn hash(&self, token: &SecretString) -> TokenHash;
}

#[async_trait]
pub trait SettingsRepository: Send + Sync {
    async fn get(&self) -> Result<RuntimeSettings>;
    /// В `tx`, чтобы изменение и его запись в аудит коммитились вместе.
    async fn set_allow_self_registration(&self, tx: &mut dyn Tx, allowed: bool) -> Result<()>;
}

// ===================== АУДИТ =====================

/// Событие для журнала аудита: кто (`actor`), что сделал (`action`), над чем
/// (`target_type` + `target_id`), в каком scope и с какими деталями.
///
/// Детали — плоские строки, которые сервис кладёт явно. Так в журнал не попадёт
/// ничего лишнего: ни хеш пароля, ни токен, как было бы при записи строк целиком.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEvent {
    /// `None` — действие системы, а не пользователя.
    pub actor: Option<UserId>,
    pub action: &'static str,
    pub target_type: &'static str,
    pub target_id: Option<i64>,
    pub scope: Option<ScopeId>,
    pub details: BTreeMap<String, String>,
}

impl AuditEvent {
    pub fn new(
        actor: Option<UserId>,
        action: &'static str,
        target_type: &'static str,
        target_id: Option<i64>,
    ) -> Self {
        Self {
            actor,
            action,
            target_type,
            target_id,
            scope: None,
            details: BTreeMap::new(),
        }
    }

    pub fn scope(mut self, scope: Option<&ScopeId>) -> Self {
        self.scope = scope.cloned();
        self
    }

    pub fn detail(mut self, key: &str, value: impl Into<String>) -> Self {
        self.details.insert(key.to_owned(), value.into());
        self
    }
}

/// Запись журнала, как её читают обратно.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub id: i64,
    pub at: DateTime<Utc>,
    pub actor: Option<UserId>,
    pub action: String,
    pub target_type: String,
    pub target_id: Option<i64>,
    pub scope: Option<ScopeId>,
    pub details: BTreeMap<String, String>,
}

/// Фильтр журнала. Пустые поля не фильтруют.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    pub actor: Option<UserId>,
    pub action: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<i64>,
}

#[async_trait]
pub trait AuditRepository: Send + Sync {
    /// Пишет в той же `tx`, что и само изменение: откатилось изменение — нет и
    /// записи; не удалось записать — откатится изменение (транзакцию не коммитить).
    async fn record(&self, tx: &mut dyn Tx, event: &AuditEvent) -> Result<()>;

    /// Новые сверху. `req.search` не используется.
    async fn list(&self, filter: &AuditFilter, req: &PageRequest) -> Result<Page<AuditRecord>>;
}

#[async_trait]
pub trait SetupRepository: Send + Sync {
    async fn is_completed(&self) -> Result<bool>;

    /// Сам открывает и коммитит транзакцию (не принимает `Tx`): операция
    /// самодостаточна и ни с чем снаружи не комбинируется.
    /// Внутри: блокирует строку настроек, проверяет, что настройка не выполнена
    /// и админа нет; создаёт роль `admin` (если её нет) со всеми правами,
    /// пользователя, назначение и ставит отметку о завершении.
    /// В той же транзакции пишет событие `setup.complete` в журнал аудита.
    /// Уже выполнена (в т.ч. параллельным запросом) -> `NotFound`; email занят -> `Conflict`.
    async fn create_first_admin(&self, new: &NewUser, now: DateTime<Utc>) -> Result<User>;
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
            _: Option<Arc<dyn UnitOfWork>>,
            _: Option<Arc<dyn AuditRepository>>,
        ) {
        }
        accepts(
            None, None, None, None, None, None, None, None, None, None, None,
        );
    }
}
