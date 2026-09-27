//! In-memory заглушки портов для тестов use-case'ов (только `cfg(test)`).
//! Хеш пароля в заглушках — `hash:<пароль>`, токены — простые строки.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicI64, AtomicU64, Ordering},
};

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, TimeZone, Utc};
use secrecy::{ExposeSecret, SecretString};

use crate::{
    AuthError, Result,
    domain::*,
    ports::*,
    service::{AccessService, AuthPolicy, AuthService},
};

// ---------- часы ----------

pub struct FakeClock(Mutex<DateTime<Utc>>);

impl FakeClock {
    pub fn new() -> Arc<Self> {
        let start = Utc.with_ymd_and_hms(2026, 1, 1, 12, 0, 0).unwrap();
        Arc::new(Self(Mutex::new(start)))
    }

    pub fn advance(&self, by: TimeDelta) {
        let mut now = self.0.lock().unwrap();
        *now = *now + by;
    }
}

impl Clock for FakeClock {
    fn now(&self) -> DateTime<Utc> {
        *self.0.lock().unwrap()
    }
}

// ---------- крипто ----------

#[derive(Default)]
pub struct FakeHasher {
    pub dummy_calls: AtomicU64,
}

#[async_trait]
impl PasswordHasher for FakeHasher {
    async fn hash(&self, password: &SecretString) -> Result<PasswordHash> {
        Ok(PasswordHash::new(format!(
            "hash:{}",
            password.expose_secret()
        )))
    }

    async fn verify(&self, password: &SecretString, hash: &PasswordHash) -> Result<bool> {
        Ok(hash.as_str() == format!("hash:{}", password.expose_secret()))
    }

    async fn verify_dummy(&self, _password: &SecretString) {
        self.dummy_calls.fetch_add(1, Ordering::SeqCst);
    }
}

/// Токен = `user:session:iat:exp`. Подписи нет, но срок и формат проверяются.
pub struct FakeCodec;

impl AccessTokenCodec for FakeCodec {
    fn encode(&self, c: &AccessClaims) -> Result<String> {
        Ok(format!(
            "{}:{}:{}:{}",
            c.user_id.0,
            c.session_id.0,
            c.issued_at.timestamp(),
            c.expires_at.timestamp()
        ))
    }

    fn decode(&self, token: &str, now: DateTime<Utc>) -> Result<AccessClaims> {
        let parts: Vec<i64> = token
            .split(':')
            .map(str::parse::<i64>)
            .collect::<std::result::Result<_, _>>()
            .map_err(|_| AuthError::Unauthorized)?;
        let &[user, session, iat, exp] = parts.as_slice() else {
            return Err(AuthError::Unauthorized);
        };
        let issued_at = DateTime::from_timestamp(iat, 0).ok_or(AuthError::Unauthorized)?;
        let expires_at = DateTime::from_timestamp(exp, 0).ok_or(AuthError::Unauthorized)?;
        if expires_at <= now {
            return Err(AuthError::Unauthorized);
        }
        Ok(AccessClaims {
            user_id: UserId(user),
            session_id: SessionId(session),
            issued_at,
            expires_at,
        })
    }
}

#[derive(Default)]
pub struct FakeRefresh(AtomicU64);

impl RefreshTokenProvider for FakeRefresh {
    fn issue(&self) -> Result<IssuedRefreshToken> {
        let n = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        let token = format!("rt-{n}");
        Ok(IssuedRefreshToken {
            hash: TokenHash::new(format!("h({token})")),
            token: SecretString::from(token),
        })
    }

    fn hash(&self, token: &SecretString) -> TokenHash {
        TokenHash::new(format!("h({})", token.expose_secret()))
    }
}

// ---------- пользователи ----------

#[derive(Default)]
pub struct MemUsers {
    rows: Mutex<Vec<(User, PasswordHash)>>,
    next_id: AtomicI64,
}

impl MemUsers {
    /// Добавляет пользователя; пароль хранится в формате, который понимает `FakeHasher`.
    pub fn seed(&self, email: &str, password: &str, is_active: bool) -> User {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let user = User {
            id: UserId(id),
            email: Email::parse(email).unwrap(),
            first_name: "Test".into(),
            second_name: "User".into(),
            is_active,
        };
        self.rows
            .lock()
            .unwrap()
            .push((user.clone(), PasswordHash::new(format!("hash:{password}"))));
        user
    }
}

#[async_trait]
impl UserRepository for MemUsers {
    async fn find_by_id(&self, id: UserId) -> Result<Option<User>> {
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .iter()
            .find(|(u, _)| u.id == id)
            .map(|(u, _)| u.clone()))
    }

    async fn find_credentials_by_email(&self, email: &Email) -> Result<Option<UserCredentials>> {
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .iter()
            .find(|(u, _)| &u.email == email)
            .map(|(u, h)| UserCredentials {
                user: u.clone(),
                password_hash: h.clone(),
            }))
    }

    async fn list(&self, req: &PageRequest) -> Result<Page<User>> {
        let rows = self.rows.lock().unwrap();
        let needle = req.search.as_deref().map(str::to_lowercase);
        let matched: Vec<User> = rows
            .iter()
            .map(|(u, _)| u)
            .filter(|u| match &needle {
                None => true,
                Some(n) => {
                    u.email.as_str().contains(n.as_str())
                        || u.first_name.to_lowercase().contains(n.as_str())
                        || u.second_name.to_lowercase().contains(n.as_str())
                }
            })
            .cloned()
            .collect();
        let total = matched.len() as i64;
        let items = matched
            .into_iter()
            .skip(req.offset() as usize)
            .take(req.per_page as usize)
            .collect();
        Ok(Page::new(items, req, total))
    }

    async fn create(&self, new: &NewUser) -> Result<User> {
        let mut rows = self.rows.lock().unwrap();
        if rows.iter().any(|(u, _)| u.email == new.email) {
            return Err(AuthError::Conflict);
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let user = User {
            id: UserId(id),
            email: new.email.clone(),
            first_name: new.first_name.clone(),
            second_name: new.second_name.clone(),
            is_active: true,
        };
        rows.push((user.clone(), new.password_hash.clone()));
        Ok(user)
    }

    async fn update(&self, id: UserId, upd: &UserUpdate) -> Result<User> {
        let mut rows = self.rows.lock().unwrap();
        // сначала существование (как WHERE id = $N в реальной БД), потом конфликт email —
        // иначе чужой email, случайно совпавший с переданным, маскирует NotFound
        if !rows.iter().any(|(u, _)| u.id == id) {
            return Err(AuthError::NotFound);
        }
        if rows.iter().any(|(u, _)| u.id != id && u.email == upd.email) {
            return Err(AuthError::Conflict);
        }
        let (user, _) = rows.iter_mut().find(|(u, _)| u.id == id).unwrap();
        user.email = upd.email.clone();
        user.first_name = upd.first_name.clone();
        user.second_name = upd.second_name.clone();
        Ok(user.clone())
    }

    async fn set_password_hash(&self, id: UserId, hash: &PasswordHash) -> Result<()> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .iter_mut()
            .find(|(u, _)| u.id == id)
            .ok_or(AuthError::NotFound)?;
        row.1 = hash.clone();
        Ok(())
    }

    async fn set_active(&self, id: UserId, active: bool) -> Result<()> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .iter_mut()
            .find(|(u, _)| u.id == id)
            .ok_or(AuthError::NotFound)?;
        row.0.is_active = active;
        Ok(())
    }

    async fn delete(&self, id: UserId) -> Result<()> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|(u, _)| u.id != id);
        if rows.len() == before {
            Err(AuthError::NotFound)
        } else {
            Ok(())
        }
    }
}

// ---------- сессии ----------

#[derive(Default)]
pub struct MemSessions {
    rows: Mutex<Vec<(Session, TokenHash)>>,
    next_id: AtomicI64,
}

impl MemSessions {
    pub fn all(&self) -> Vec<Session> {
        self.rows
            .lock()
            .unwrap()
            .iter()
            .map(|(s, _)| s.clone())
            .collect()
    }
}

#[async_trait]
impl SessionRepository for MemSessions {
    async fn create(&self, new: &NewSession) -> Result<Session> {
        let id = SessionId(self.next_id.fetch_add(1, Ordering::SeqCst) + 1);
        let session = Session {
            id,
            user_id: new.user_id,
            created_at: new.created_at,
            expires_at: new.expires_at,
            revoked_at: None,
        };
        self.rows
            .lock()
            .unwrap()
            .push((session.clone(), new.token_hash.clone()));
        Ok(session)
    }

    async fn find_by_id(&self, id: SessionId) -> Result<Option<Session>> {
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .iter()
            .find(|(s, _)| s.id == id)
            .map(|(s, _)| s.clone()))
    }

    async fn find_by_token_hash(&self, hash: &TokenHash) -> Result<Option<Session>> {
        let rows = self.rows.lock().unwrap();
        Ok(rows.iter().find(|(_, h)| h == hash).map(|(s, _)| s.clone()))
    }

    async fn list_active(&self, user: UserId, now: DateTime<Utc>) -> Result<Vec<Session>> {
        let rows = self.rows.lock().unwrap();
        Ok(rows
            .iter()
            .map(|(s, _)| s)
            .filter(|s| s.user_id == user && s.is_active(now))
            .cloned()
            .collect())
    }

    async fn rotate(
        &self,
        old: SessionId,
        next: &NewSession,
        now: DateTime<Utc>,
    ) -> Result<Session> {
        let mut rows = self.rows.lock().unwrap();
        let old_row = rows
            .iter_mut()
            .find(|(s, _)| s.id == old)
            .ok_or(AuthError::NotFound)?;
        if old_row.0.revoked_at.is_some() {
            return Err(AuthError::Conflict);
        }
        old_row.0.revoked_at = Some(now);

        let id = SessionId(self.next_id.fetch_add(1, Ordering::SeqCst) + 1);
        let session = Session {
            id,
            user_id: next.user_id,
            created_at: next.created_at,
            expires_at: next.expires_at,
            revoked_at: None,
        };
        rows.push((session.clone(), next.token_hash.clone()));
        Ok(session)
    }

    async fn revoke(&self, user: UserId, session: SessionId, now: DateTime<Utc>) -> Result<()> {
        let mut rows = self.rows.lock().unwrap();
        let row = rows
            .iter_mut()
            .find(|(s, _)| s.id == session && s.user_id == user)
            .ok_or(AuthError::NotFound)?;
        if row.0.revoked_at.is_none() {
            row.0.revoked_at = Some(now);
        }
        Ok(())
    }

    async fn revoke_all_for_user(&self, user: UserId, now: DateTime<Utc>) -> Result<u64> {
        let mut rows = self.rows.lock().unwrap();
        let mut revoked = 0;
        for (s, _) in rows
            .iter_mut()
            .filter(|(s, _)| s.user_id == user && s.revoked_at.is_none())
        {
            s.revoked_at = Some(now);
            revoked += 1;
        }
        Ok(revoked)
    }
}

// ---------- права ----------

type Grant = (UserId, Option<ScopeId>, PermissionCode);

#[derive(Default)]
pub struct MemPermissions {
    grants: Mutex<Vec<Grant>>,
}

impl MemPermissions {
    pub fn grant(&self, user: UserId, scope: Option<&str>, code: &str) {
        self.grants.lock().unwrap().push((
            user,
            scope.map(|s| ScopeId::parse(s).unwrap()),
            PermissionCode::parse(code).unwrap(),
        ));
    }
}

#[async_trait]
impl PermissionRepository for MemPermissions {
    async fn list(&self) -> Result<Vec<Permission>> {
        Ok(Vec::new())
    }

    async fn effective_for_user(
        &self,
        user: UserId,
        scope: Option<&ScopeId>,
    ) -> Result<std::collections::HashSet<PermissionCode>> {
        let grants = self.grants.lock().unwrap();
        Ok(grants
            .iter()
            .filter(|(u, s, _)| *u == user && (s.is_none() || s.as_ref() == scope))
            .map(|(_, _, c)| c.clone())
            .collect())
    }
}

// ---------- всё вместе ----------

pub struct Harness {
    pub clock: Arc<FakeClock>,
    pub users: Arc<MemUsers>,
    pub sessions: Arc<MemSessions>,
    pub hasher: Arc<FakeHasher>,
    pub permissions: Arc<MemPermissions>,
    pub auth: AuthService,
    pub access: AccessService,
}

impl Harness {
    pub fn new() -> Self {
        let clock = FakeClock::new();
        let users = Arc::new(MemUsers::default());
        let sessions = Arc::new(MemSessions::default());
        let hasher = Arc::new(FakeHasher::default());
        let permissions = Arc::new(MemPermissions::default());

        let auth = AuthService::new(
            users.clone(),
            sessions.clone(),
            hasher.clone(),
            Arc::new(FakeCodec),
            Arc::new(FakeRefresh::default()),
            clock.clone(),
            MemSettings::new(false),
            AuthPolicy::default(),
        );

        let access = AccessService::new(permissions.clone());

        Self {
            clock,
            users,
            sessions,
            hasher,
            permissions,
            auth,
            access,
        }
    }
}

// ---------- назначения ролей ----------

use std::collections::HashMap;

#[derive(Default)]
pub struct MemAssignments {
    rows: Mutex<Vec<(UserId, RoleAssignment)>>,
}

impl MemAssignments {
    /// Быстро выдаёт пользователю роль (подготовка тестов).
    pub fn seed(&self, user: UserId, role_code: &str, scope: Option<&str>) {
        let mut rows = self.rows.lock().unwrap();
        let role = Role {
            id: RoleId(rows.len() as i64 + 1),
            code: RoleCode::parse(role_code).unwrap(),
            name: role_code.to_owned(),
            scope: if scope.is_some() {
                RoleScope::Scoped
            } else {
                RoleScope::Global
            },
        };
        rows.push((
            user,
            RoleAssignment {
                role,
                scope: scope.map(|s| ScopeId::parse(s).unwrap()),
            },
        ));
    }
}

#[async_trait]
impl AssignmentRepository for MemAssignments {
    async fn for_users(&self, users: &[UserId]) -> Result<HashMap<UserId, Vec<RoleAssignment>>> {
        let rows = self.rows.lock().unwrap();
        let mut map: HashMap<UserId, Vec<RoleAssignment>> = HashMap::new();
        for (user, assignment) in rows.iter().filter(|(u, _)| users.contains(u)) {
            map.entry(*user).or_default().push(assignment.clone());
        }
        Ok(map)
    }

    async fn assign(&self, user: UserId, role: RoleId, scope: Option<&ScopeId>) -> Result<()> {
        let mut rows = self.rows.lock().unwrap();
        if rows
            .iter()
            .any(|(u, a)| *u == user && a.role.id == role && a.scope.as_ref() == scope)
        {
            return Err(AuthError::Conflict);
        }
        let code = format!("role-{}", role.0);
        rows.push((
            user,
            RoleAssignment {
                role: Role {
                    id: role,
                    code: RoleCode::parse(&code).unwrap(),
                    name: code,
                    scope: if scope.is_some() {
                        RoleScope::Scoped
                    } else {
                        RoleScope::Global
                    },
                },
                scope: scope.cloned(),
            },
        ));
        Ok(())
    }

    async fn unassign(&self, user: UserId, role: RoleId, scope: Option<&ScopeId>) -> Result<()> {
        let mut rows = self.rows.lock().unwrap();
        rows.retain(|(u, a)| !(*u == user && a.role.id == role && a.scope.as_ref() == scope));
        Ok(())
    }

    async fn revoke_all_in_scope(&self, scope: &ScopeId) -> Result<u64> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|(_, a)| a.scope.as_ref() != Some(scope));
        Ok((before - rows.len()) as u64)
    }
}

// ---------- роли ----------

#[derive(Default)]
pub struct MemRoles {
    rows: Mutex<Vec<Role>>,
    role_permissions: Mutex<Vec<(RoleId, Permission)>>,
    next_role_id: AtomicI64,
    next_perm_id: AtomicI64,
}

#[async_trait]
impl RoleRepository for MemRoles {
    async fn find_by_id(&self, id: RoleId) -> Result<Option<Role>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .cloned())
    }

    async fn list(&self, req: &PageRequest) -> Result<Page<Role>> {
        let rows = self.rows.lock().unwrap();
        let needle = req.search.as_deref().map(str::to_lowercase);
        let matched: Vec<Role> = rows
            .iter()
            .filter(|r| match &needle {
                None => true,
                Some(n) => {
                    r.code.as_str().contains(n.as_str())
                        || r.name.to_lowercase().contains(n.as_str())
                }
            })
            .cloned()
            .collect();
        let total = matched.len() as i64;
        let items = matched
            .into_iter()
            .skip(req.offset() as usize)
            .take(req.per_page as usize)
            .collect();
        Ok(Page::new(items, req, total))
    }

    async fn create(&self, new: &NewRole) -> Result<Role> {
        let mut rows = self.rows.lock().unwrap();
        if rows.iter().any(|r| r.code == new.code) {
            return Err(AuthError::Conflict);
        }
        let id = RoleId(self.next_role_id.fetch_add(1, Ordering::SeqCst) + 1);
        let role = Role {
            id,
            code: new.code.clone(),
            name: new.name.clone(),
            scope: new.scope,
        };
        rows.push(role.clone());
        Ok(role)
    }

    async fn update(&self, id: RoleId, upd: &RoleUpdate) -> Result<Role> {
        let mut rows = self.rows.lock().unwrap();
        if rows.iter().any(|r| r.id != id && r.code == upd.code) {
            return Err(AuthError::Conflict);
        }
        let role = rows
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or(AuthError::NotFound)?;
        role.code = upd.code.clone();
        role.name = upd.name.clone();
        Ok(role.clone())
    }

    async fn delete(&self, id: RoleId) -> Result<()> {
        let mut rows = self.rows.lock().unwrap();
        let before = rows.len();
        rows.retain(|r| r.id != id);
        if rows.len() == before {
            return Err(AuthError::NotFound);
        }
        self.role_permissions
            .lock()
            .unwrap()
            .retain(|(r, _)| *r != id);
        Ok(())
    }

    async fn permissions_of(&self, role: RoleId) -> Result<Vec<Permission>> {
        Ok(self
            .role_permissions
            .lock()
            .unwrap()
            .iter()
            .filter(|(r, _)| *r == role)
            .map(|(_, p)| p.clone())
            .collect())
    }

    async fn set_permissions(
        &self,
        role: RoleId,
        permission_ids: &[PermissionId],
    ) -> Result<Vec<Permission>> {
        // упрощённая заглушка: считаем описание неизвестным; в auth-postgres
        // это реальный join с таблицей permissions
        let mut rp = self.role_permissions.lock().unwrap();
        rp.retain(|(r, _)| *r != role);
        let mut result = Vec::new();
        for id in permission_ids {
            let perm = Permission {
                id: *id,
                code: PermissionCode::parse(&format!("perm-{}", id.0)).unwrap(),
                description: String::new(),
            };
            rp.push((role, perm.clone()));
            result.push(perm);
        }
        let _ = self.next_perm_id.load(Ordering::SeqCst); // зарезервировано на будущее
        Ok(result)
    }
}

// ---------- настройки ----------

pub struct MemSettings(std::sync::atomic::AtomicBool);

impl MemSettings {
    pub fn new(allow_self_registration: bool) -> Arc<Self> {
        Arc::new(Self(std::sync::atomic::AtomicBool::new(
            allow_self_registration,
        )))
    }
}

#[async_trait]
impl SettingsRepository for MemSettings {
    async fn get(&self) -> Result<RuntimeSettings> {
        Ok(RuntimeSettings {
            allow_self_registration: self.0.load(Ordering::SeqCst),
        })
    }

    async fn set_allow_self_registration(&self, allowed: bool) -> Result<()> {
        self.0.store(allowed, Ordering::SeqCst);
        Ok(())
    }
}
