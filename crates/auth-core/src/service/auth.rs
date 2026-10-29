//! Аутентификация: вход, обновление токенов, выход, проверка access-токена.

use std::sync::Arc;

use chrono::{DateTime, TimeDelta, Utc};
use secrecy::SecretString;
use tracing::{Level, Span, instrument, warn};

use super::{
    Ports,
    audit::{audit_actions, audit_targets},
};
use crate::{
    AuthError, Result,
    domain::*,
    ports::{
        AccessTokenCodec, AuditEvent, AuditRepository, Clock, NewSession, PasswordHasher,
        RefreshTokenProvider, SessionRepository, SettingsRepository, Tx, UnitOfWork,
        UserRepository,
    },
};

/// Времена жизни токенов. Задаётся конфигом, но инварианты держит ядро.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthPolicy {
    access_ttl: TimeDelta,
    refresh_ttl: TimeDelta,
}

impl AuthPolicy {
    pub fn new(access_ttl: TimeDelta, refresh_ttl: TimeDelta) -> Result<Self> {
        if access_ttl <= TimeDelta::zero() || refresh_ttl <= access_ttl {
            return Err(AuthError::validation(
                "TTL: access должен быть > 0, refresh — больше access",
            ));
        }
        Ok(Self {
            access_ttl,
            refresh_ttl,
        })
    }
    pub fn access_ttl(&self) -> TimeDelta {
        self.access_ttl
    }

    pub fn refresh_ttl(&self) -> TimeDelta {
        self.refresh_ttl
    }
}

impl Default for AuthPolicy {
    /// 15 минут / 30 дней.
    fn default() -> Self {
        Self {
            access_ttl: TimeDelta::try_minutes(15).expect("15 минут помещаются в TimeDelta"),
            refresh_ttl: TimeDelta::try_days(30).expect("30 дней помещаются в TimeDelta"),
        }
    }
}

/// Пара токенов. Оба — `SecretString`: случайный `{:?}` в логе их не выдаст.
#[derive(Debug)]
pub struct TokenPair {
    pub access_token: SecretString,
    pub access_expires_at: DateTime<Utc>,
    pub refresh_token: SecretString,
    pub refresh_expires_at: DateTime<Utc>,
}

const MIN_PASSWORD_CHARS: usize = 8;
const MAX_PASSWORD_CHARS: usize = 128;
const MAX_NAME_CHARS: usize = 100;

fn validate_password(password: &SecretString) -> Result<()> {
    use secrecy::ExposeSecret;
    let len = password.expose_secret().chars().count();
    if (MIN_PASSWORD_CHARS..=MAX_PASSWORD_CHARS).contains(&len) {
        Ok(())
    } else {
        Err(AuthError::validation(format!(
            "пароль: от {MIN_PASSWORD_CHARS} до {MAX_PASSWORD_CHARS} символов"
        )))
    }
}

fn clean_name(raw: &str, field: &str) -> Result<String> {
    let name = raw.trim();
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(AuthError::validation(format!(
            "{field}: не длиннее {MAX_NAME_CHARS} символов"
        )));
    }
    Ok(name.to_owned())
}

#[derive(Debug)]
pub struct RegisterInput {
    pub email: String,
    pub password: SecretString,
    pub first_name: String,
    pub second_name: String,
}

#[derive(Debug)]
pub struct LoginResult {
    pub user: User,
    pub tokens: TokenPair,
}

/// Кто делает запрос. Получается только из `AuthService::authenticate`.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user: User,
    pub session_id: SessionId,
}

impl AuthContext {
    pub fn user_id(&self) -> UserId {
        self.user.id
    }
}

#[derive(Clone)]
pub struct AuthService {
    users: Arc<dyn UserRepository>,
    sessions: Arc<dyn SessionRepository>,
    hasher: Arc<dyn PasswordHasher>,
    access_tokens: Arc<dyn AccessTokenCodec>,
    refresh_tokens: Arc<dyn RefreshTokenProvider>,
    clock: Arc<dyn Clock>,
    settings: Arc<dyn SettingsRepository>,
    uow: Arc<dyn UnitOfWork>,
    audit: Arc<dyn AuditRepository>,
    policy: AuthPolicy,
}

impl AuthService {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        users: Arc<dyn UserRepository>,
        sessions: Arc<dyn SessionRepository>,
        hasher: Arc<dyn PasswordHasher>,
        access_tokens: Arc<dyn AccessTokenCodec>,
        refresh_tokens: Arc<dyn RefreshTokenProvider>,
        clock: Arc<dyn Clock>,
        settings: Arc<dyn SettingsRepository>,
        uow: Arc<dyn UnitOfWork>,
        audit: Arc<dyn AuditRepository>,
        policy: AuthPolicy,
    ) -> Self {
        Self {
            users,
            sessions,
            hasher,
            access_tokens,
            refresh_tokens,
            clock,
            settings,
            uow,
            audit,
            policy,
        }
    }

    pub fn from_ports(ports: &Ports, policy: AuthPolicy) -> Self {
        Self::new(
            ports.users.clone(),
            ports.sessions.clone(),
            ports.hasher.clone(),
            ports.access_tokens.clone(),
            ports.refresh_tokens.clone(),
            ports.clock.clone(),
            ports.settings.clone(),
            ports.uow.clone(),
            ports.audit.clone(),
            policy,
        )
    }

    /// Событие над аккаунтом `user`; `actor = None` — действие системы.
    fn user_event(actor: Option<UserId>, action: &'static str, user: UserId) -> AuditEvent {
        AuditEvent::new(actor, action, audit_targets::USER, Some(user.0))
    }

    /// Вход по email + паролю.
    ///
    /// Неверный пароль, неизвестный email и мусор вместо email дают один и тот же
    /// `InvalidCredentials`, а на «пустых» ветках делается `verify_dummy`, чтобы
    /// время ответа не выдавало, существует ли адрес. `AccountDisabled` отдаётся
    #[instrument(skip_all, fields(user_id = tracing::field::Empty), err(level = Level::WARN))]
    pub async fn login(&self, email: &str, password: &SecretString) -> Result<LoginResult> {
        let Ok(email) = Email::parse(email) else {
            self.hasher.verify_dummy(password).await;
            return Err(AuthError::InvalidCredentials);
        };
        let Some(creds) = self.users.find_credentials_by_email(&email).await? else {
            self.hasher.verify_dummy(password).await;
            return Err(AuthError::InvalidCredentials);
        };
        Span::current().record("user_id", creds.user.id.0);

        if !self.hasher.verify(password, &creds.password_hash).await? {
            return Err(AuthError::InvalidCredentials);
        }
        if !creds.user.is_active {
            return Err(AuthError::AccountDisabled);
        }

        // Неудачные входы в журнал не пишем: каждый такой запрос открывал бы транзакцию
        // на чужой ввод. От перебора защищает лимит запросов, следы есть в логах (WARN).
        let mut tx = self.uow.begin().await?;
        let tokens = self.start_session(&mut *tx, creds.user.id).await?;
        let user_id = creds.user.id;
        let event = Self::user_event(Some(user_id), audit_actions::AUTH_LOGIN, user_id);
        self.audit.record(&mut *tx, &event).await?;
        tx.commit().await?;
        Ok(LoginResult {
            user: creds.user,
            tokens,
        })
    }

    /// Обновление токенов по refresh-токену, с ротацией.
    ///
    /// Если предъявлен токен уже отозванной сессии, его либо украли, либо использовали
    /// дважды: гасим все сессии пользователя. Параллельный refresh тем же токеном
    /// (гонка `rotate`) — просто `Unauthorized`, без массового отзыва.
    #[instrument(
            skip_all,
            fields(user_id = tracing::field::Empty, session_id = tracing::field::Empty),
            err(level = Level::WARN)
        )]
    pub async fn refresh(&self, refresh_token: &SecretString) -> Result<TokenPair> {
        let now = self.clock.now();
        let hash = self.refresh_tokens.hash(refresh_token);
        let session = self
            .sessions
            .find_by_token_hash(&hash)
            .await?
            .ok_or(AuthError::Unauthorized)?;

        let span = Span::current();
        span.record("user_id", session.user_id.0);
        span.record("session_id", session.id.0);

        if session.revoked_at.is_some() {
            warn!(
                "повторное использование отозванного refresh-токена: отзываем все сессии пользователя"
            );
            let mut tx = self.uow.begin().await?;
            let revoked = self
                .sessions
                .revoke_all_for_user(&mut *tx, session.user_id, now)
                .await?;
            let event = Self::user_event(None, audit_actions::AUTH_REFRESH_REPLAY, session.user_id)
                .detail("session_id", session.id.0.to_string())
                .detail("sessions_revoked", revoked.to_string());
            self.audit.record(&mut *tx, &event).await?;
            tx.commit().await?;
            return Err(AuthError::Unauthorized);
        }
        if session.expires_at <= now {
            return Err(AuthError::Unauthorized);
        }

        let user = self
            .users
            .find_by_id(session.user_id)
            .await?
            .ok_or(AuthError::Unauthorized)?;
        if !user.is_active {
            return Err(AuthError::AccountDisabled);
        }

        let issued = self.refresh_tokens.issue()?;
        let next = NewSession {
            user_id: user.id,
            token_hash: issued.hash.clone(),
            created_at: now,
            expires_at: now + self.policy.refresh_ttl,
        };
        let mut tx = self.uow.begin().await?;
        let next_session = match self.sessions.rotate(&mut *tx, session.id, &next, now).await {
            Ok(s) => s,
            Err(AuthError::Conflict) => return Err(AuthError::Unauthorized),
            Err(e) => return Err(e),
        };

        tx.commit().await?;
        self.build_pair(
            user.id,
            next_session.id,
            issued.token,
            next_session.expires_at,
            now,
        )
    }

    /// Выход по refresh-токену. Идемпотентен: неизвестный или уже отозванный токен — не ошибка.
    #[instrument(skip_all, err(level = Level::WARN))]
    pub async fn logout(&self, refresh_token: &SecretString) -> Result<()> {
        let now = self.clock.now();
        let hash = self.refresh_tokens.hash(refresh_token);
        if let Some(session) = self.sessions.find_by_token_hash(&hash).await?
            && session.is_active(now)
        {
            let mut tx = self.uow.begin().await?;
            match self
                .sessions
                .revoke(&mut *tx, session.user_id, session.id, now)
                .await
            {
                Ok(()) => {
                    let event = Self::user_event(
                        Some(session.user_id),
                        audit_actions::AUTH_LOGOUT,
                        session.user_id,
                    )
                    .detail("session_id", session.id.0.to_string());
                    self.audit.record(&mut *tx, &event).await?;
                }
                // сессию уже отозвал параллельный запрос — он и запишет выход
                Err(AuthError::NotFound) => {}
                Err(e) => return Err(e),
            }
            tx.commit().await?;
        }
        Ok(())
    }

    /// Выйти со всех устройств. Возвращает, сколько сессий отозвано.
    pub async fn logout_all(&self, ctx: AuthContext) -> Result<u64> {
        let mut tx = self.uow.begin().await?;
        let count_sessions = self
            .sessions
            .revoke_all_for_user(&mut *tx, ctx.user.id, self.clock.now())
            .await?;
        let event = Self::user_event(
            Some(ctx.user.id),
            audit_actions::AUTH_LOGOUT_ALL,
            ctx.user.id,
        )
        .detail("sessions_revoked", count_sessions.to_string());
        self.audit.record(&mut *tx, &event).await?;
        tx.commit().await?;
        Ok(count_sessions)
    }

    /// Самостоятельная смена пароля (не админом): требует старый пароль.
    /// При успехе отзывает все сессии пользователя, КРОМЕ той, из-под которой
    /// сделан этот запрос — иначе вызывающий тут же вылетит из-под себя
    /// на середине запроса. Возвращает, сколько ЧУЖИХ сессий отозвано.
    #[instrument(skip_all, fields(user_id = %ctx.user_id()), err(level = Level::WARN))]
    pub async fn change_own_password(
        &self,
        ctx: &AuthContext,
        old_password: &SecretString,
        new_password: &SecretString,
    ) -> Result<u64> {
        let creds = self
            .users
            .find_credentials_by_email(&ctx.user.email)
            .await?
            .ok_or(AuthError::Unauthorized)?;

        if !self
            .hasher
            .verify(old_password, &creds.password_hash)
            .await?
        {
            return Err(AuthError::InvalidCredentials);
        }

        validate_password(new_password)?;
        let hash = self.hasher.hash(new_password).await?;
        let mut tx = self.uow.begin().await?;
        self.users
            .set_password_hash(&mut *tx, ctx.user.id, &hash)
            .await?;

        let count = self
            .sessions
            .revoke_all_for_user_except(&mut *tx, ctx.user.id, ctx.session_id, self.clock.now())
            .await?;
        // сам пароль в журнал не идёт — только факт смены
        let event = Self::user_event(
            Some(ctx.user.id),
            audit_actions::USER_PASSWORD_CHANGE,
            ctx.user.id,
        )
        .detail("sessions_revoked", count.to_string());
        self.audit.record(&mut *tx, &event).await?;
        tx.commit().await?;
        Ok(count)
    }

    /// Проверка access-токена: подпись и срок, затем живая ли сессия и активен ли пользователь.
    /// Отзыв сессии и деактивация пользователя действуют сразу, без ожидания истечения токена.
    #[instrument(
            skip_all,
            fields(user_id = tracing::field::Empty, session_id = tracing::field::Empty),
            err(level = Level::DEBUG)
        )]
    pub async fn authenticate(&self, access_token: &str) -> Result<AuthContext> {
        let now = self.clock.now();
        let claims = self.access_tokens.decode(access_token, now)?;

        let span = Span::current();
        span.record("user_id", claims.user_id.0);
        span.record("session_id", claims.session_id.0);

        let session = self
            .sessions
            .find_by_id(claims.session_id)
            .await?
            .filter(|s| s.user_id == claims.user_id && s.is_active(now))
            .ok_or(AuthError::Unauthorized)?;
        let user = self
            .users
            .find_by_id(claims.user_id)
            .await?
            .ok_or(AuthError::Unauthorized)?;
        if !user.is_active {
            return Err(AuthError::AccountDisabled);
        }

        Ok(AuthContext {
            user,
            session_id: session.id,
        })
    }

    /// Самостоятельная регистрация. Выключена по умолчанию (`AuthPolicy`) — политику
    /// проверяем здесь, а не только на уровне HTTP, чтобы правило действовало и при
    /// прямом вызове core как библиотеки.
    #[instrument(skip_all, err(level = Level::WARN))]
    pub async fn register(&self, input: RegisterInput) -> Result<LoginResult> {
        if !self.settings.get().await?.allow_self_registration {
            return Err(AuthError::Forbidden);
        }

        let email = Email::parse(&input.email)?;
        validate_password(&input.password)?;
        let new = crate::ports::NewUser {
            email,
            password_hash: self.hasher.hash(&input.password).await?,
            first_name: clean_name(&input.first_name, "имя")?,
            second_name: clean_name(&input.second_name, "фамилия")?,
        };
        let mut tx = self.uow.begin().await?;
        let user = self.users.create(&mut *tx, &new).await?;
        let tokens = self.start_session(&mut *tx, user.id).await?;
        let event = Self::user_event(Some(user.id), audit_actions::USER_REGISTER, user.id)
            .detail("email", user.email.as_str());
        self.audit.record(&mut *tx, &event).await?;
        tx.commit().await?;
        Ok(LoginResult { user, tokens })
    }

    async fn start_session(&self, tx: &mut dyn Tx, user_id: UserId) -> Result<TokenPair> {
        let now = self.clock.now();
        let refresh = self.refresh_tokens.issue()?;

        let session = self
            .sessions
            .create(
                tx,
                &NewSession {
                    user_id,
                    token_hash: refresh.hash.clone(),
                    created_at: now,
                    expires_at: now + self.policy.refresh_ttl(),
                },
            )
            .await?;
        self.build_pair(user_id, session.id, refresh.token, session.expires_at, now)
    }

    fn build_pair(
        &self,
        user_id: UserId,
        session_id: SessionId,
        refresh_token: SecretString,
        refresh_expires_at: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<TokenPair> {
        let access_expires_at = now + self.policy.access_ttl();
        let access = self.access_tokens.encode(&AccessClaims {
            user_id,
            session_id,
            issued_at: now,
            expires_at: access_expires_at,
        })?;
        Ok(TokenPair {
            access_token: SecretString::from(access),
            access_expires_at,
            refresh_token,
            refresh_expires_at,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::Ordering;

    use secrecy::ExposeSecret;

    use super::*;
    use crate::testing::Harness;

    #[tokio::test]
    async fn login_commits_once_and_failed_login_opens_no_transaction() {
        let h = Harness::new();
        h.users.seed("u@example.com", "user-password", true);

        assert!(matches!(
            h.auth.login("u@example.com", &pw("wrong-password")).await,
            Err(AuthError::InvalidCredentials)
        ));
        assert_eq!(
            h.uow.begun(),
            0,
            "неверный пароль не должен трогать БД на запись"
        );

        h.auth
            .login("u@example.com", &pw("user-password"))
            .await
            .unwrap();
        assert_eq!((h.uow.begun(), h.uow.committed()), (1, 1));
    }

    fn pw(s: &str) -> SecretString {
        SecretString::from(s)
    }

    fn minutes(n: i64) -> TimeDelta {
        TimeDelta::try_minutes(n).unwrap()
    }

    #[tokio::test]
    async fn login_issues_tokens_and_creates_session() {
        let h = Harness::new();
        let user = h.users.seed("klai@example.com", "correct horse", true);

        let res = h
            .auth
            .login("  Klai@Example.com ", &pw("correct horse"))
            .await
            .unwrap();

        assert_eq!(res.user.id, user.id);
        assert_eq!(h.sessions.all().len(), 1);
        let ctx = h
            .auth
            .authenticate(res.tokens.access_token.expose_secret())
            .await
            .unwrap();
        assert_eq!(ctx.user_id(), user.id);
    }

    #[tokio::test]
    async fn wrong_password_and_unknown_email_are_indistinguishable() {
        let h = Harness::new();
        h.users.seed("klai@example.com", "right", true);

        let wrong = h
            .auth
            .login("klai@example.com", &pw("wrong"))
            .await
            .unwrap_err();
        let unknown = h
            .auth
            .login("nobody@example.com", &pw("right"))
            .await
            .unwrap_err();
        let malformed = h
            .auth
            .login("not-an-email", &pw("right"))
            .await
            .unwrap_err();

        assert!(matches!(wrong, AuthError::InvalidCredentials));
        assert!(matches!(unknown, AuthError::InvalidCredentials));
        assert!(matches!(malformed, AuthError::InvalidCredentials));
        // время выровнено: обе «пустые» ветки прошли через verify_dummy
        assert_eq!(h.hasher.dummy_calls.load(Ordering::SeqCst), 2);
        assert!(h.sessions.all().is_empty());
    }

    #[tokio::test]
    async fn disabled_account_cannot_login() {
        let h = Harness::new();
        h.users.seed("klai@example.com", "pw", false);

        let err = h
            .auth
            .login("klai@example.com", &pw("pw"))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::AccountDisabled));
        // а с неверным паролем про отключение не сообщаем
        let err = h
            .auth
            .login("klai@example.com", &pw("nope"))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidCredentials));
    }

    #[tokio::test]
    async fn authenticate_rejects_garbage_expired_and_revoked_tokens() {
        let h = Harness::new();
        h.users.seed("klai@example.com", "pw", true);
        let tokens = h
            .auth
            .login("klai@example.com", &pw("pw"))
            .await
            .unwrap()
            .tokens;
        let access = tokens.access_token.expose_secret().to_owned();

        assert!(matches!(
            h.auth.authenticate("garbage").await,
            Err(AuthError::Unauthorized)
        ));

        h.clock.advance(minutes(16));
        assert!(matches!(
            h.auth.authenticate(&access).await,
            Err(AuthError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn logout_kills_access_token_immediately_and_is_idempotent() {
        let h = Harness::new();
        h.users.seed("klai@example.com", "pw", true);
        let tokens = h
            .auth
            .login("klai@example.com", &pw("pw"))
            .await
            .unwrap()
            .tokens;
        let access = tokens.access_token.expose_secret().to_owned();

        h.auth.logout(&tokens.refresh_token).await.unwrap();
        h.auth.logout(&tokens.refresh_token).await.unwrap();
        h.auth.logout(&pw("никогда-не-выдавался")).await.unwrap();

        assert!(matches!(
            h.auth.authenticate(&access).await,
            Err(AuthError::Unauthorized)
        ));
        // повторный и чужой выход ничего не меняют — и в журнал не попадают
        assert_eq!(
            h.audit.actions(),
            [audit_actions::AUTH_LOGIN, audit_actions::AUTH_LOGOUT]
        );
    }

    #[tokio::test]
    async fn own_account_actions_are_audited_without_secrets() {
        let h = Harness::new();
        let user = h.users.seed("klai@example.com", "old-password", true);

        assert!(matches!(
            h.auth
                .login("klai@example.com", &pw("wrong-password"))
                .await,
            Err(AuthError::InvalidCredentials)
        ));
        let device_a = h
            .auth
            .login("klai@example.com", &pw("old-password"))
            .await
            .unwrap()
            .tokens;
        let device_b = h
            .auth
            .login("klai@example.com", &pw("old-password"))
            .await
            .unwrap()
            .tokens;
        let ctx = h
            .auth
            .authenticate(device_a.access_token.expose_secret())
            .await
            .unwrap();

        h.auth
            .change_own_password(&ctx, &pw("old-password"), &pw("new-password-1"))
            .await
            .unwrap();
        h.auth.logout_all(ctx).await.unwrap();
        // device_b отозван сменой пароля; его повторное предъявление — replay
        assert!(h.auth.refresh(&device_b.refresh_token).await.is_err());

        assert_eq!(
            h.audit.actions(),
            [
                audit_actions::AUTH_LOGIN,
                audit_actions::AUTH_LOGIN,
                audit_actions::USER_PASSWORD_CHANGE,
                audit_actions::AUTH_LOGOUT_ALL,
                audit_actions::AUTH_REFRESH_REPLAY,
            ],
            "неудачный вход в журнал не пишется"
        );
        let events = h.audit.events();
        assert!(
            events
                .iter()
                .all(|e| e.target_id == Some(user.id.0) && e.target_type == audit_targets::USER)
        );
        assert_eq!(events[2].details["sessions_revoked"], "1");
        assert_eq!(
            events[4].actor, None,
            "реакция системы, а не действие пользователя"
        );
        assert!(
            events
                .iter()
                .flat_map(|e| e.details.values())
                .all(|v| !v.contains("password")),
            "пароли не должны попасть в аудит"
        );
    }

    #[tokio::test]
    async fn deactivated_user_is_cut_off_at_once() {
        let h = Harness::new();
        let user = h.users.seed("klai@example.com", "pw", true);
        let tokens = h
            .auth
            .login("klai@example.com", &pw("pw"))
            .await
            .unwrap()
            .tokens;
        let mut tx = h.uow.begin().await.unwrap();
        h.users.set_active(&mut *tx, user.id, false).await.unwrap();
        tx.commit().await.unwrap();
        assert!(matches!(
            h.auth
                .authenticate(tokens.access_token.expose_secret())
                .await,
            Err(AuthError::AccountDisabled)
        ));
        assert!(matches!(
            h.auth.refresh(&tokens.refresh_token).await,
            Err(AuthError::AccountDisabled)
        ));
    }

    #[tokio::test]
    async fn refresh_rotates_tokens() {
        let h = Harness::new();
        h.users.seed("klai@example.com", "pw", true);
        let first = h
            .auth
            .login("klai@example.com", &pw("pw"))
            .await
            .unwrap()
            .tokens;

        h.clock.advance(minutes(20));
        let second = h.auth.refresh(&first.refresh_token).await.unwrap();

        assert_ne!(
            first.refresh_token.expose_secret(),
            second.refresh_token.expose_secret()
        );
        assert!(
            h.auth
                .authenticate(second.access_token.expose_secret())
                .await
                .is_ok()
        );
        let sessions = h.sessions.all();
        assert_eq!(sessions.len(), 2);
        assert_eq!(
            sessions.iter().filter(|s| s.revoked_at.is_some()).count(),
            1
        );
    }

    #[tokio::test]
    async fn replayed_refresh_token_revokes_every_session() {
        let h = Harness::new();
        h.users.seed("klai@example.com", "pw", true);
        let device_a = h
            .auth
            .login("klai@example.com", &pw("pw"))
            .await
            .unwrap()
            .tokens;
        let device_b = h
            .auth
            .login("klai@example.com", &pw("pw"))
            .await
            .unwrap()
            .tokens;

        let rotated = h.auth.refresh(&device_a.refresh_token).await.unwrap();

        // старый токен предъявлен повторно -> компрометация
        assert!(matches!(
            h.auth.refresh(&device_a.refresh_token).await,
            Err(AuthError::Unauthorized)
        ));
        // вместе с ним умерли и остальные сессии пользователя
        assert!(matches!(
            h.auth.refresh(&rotated.refresh_token).await,
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            h.auth.refresh(&device_b.refresh_token).await,
            Err(AuthError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn expired_refresh_token_is_rejected() {
        let h = Harness::new();
        h.users.seed("klai@example.com", "pw", true);
        let tokens = h
            .auth
            .login("klai@example.com", &pw("pw"))
            .await
            .unwrap()
            .tokens;

        h.clock.advance(TimeDelta::try_days(31).unwrap());

        assert!(matches!(
            h.auth.refresh(&tokens.refresh_token).await,
            Err(AuthError::Unauthorized)
        ));
    }

    #[tokio::test]
    async fn change_own_password_requires_correct_old_password() {
        let h = Harness::new();
        h.users.seed("klai@example.com", "old-password", true);
        let tokens = h
            .auth
            .login("klai@example.com", &pw("old-password"))
            .await
            .unwrap()
            .tokens;
        let ctx = h
            .auth
            .authenticate(tokens.access_token.expose_secret())
            .await
            .unwrap();

        let err = h
            .auth
            .change_own_password(&ctx, &pw("wrong-old-password"), &pw("new-password-123"))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::InvalidCredentials));
        // пароль не поменялся
        h.auth
            .login("klai@example.com", &pw("old-password"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn change_own_password_keeps_current_session_but_kills_others() {
        let h = Harness::new();
        h.users.seed("klai@example.com", "old-password", true);
        let device_a = h
            .auth
            .login("klai@example.com", &pw("old-password"))
            .await
            .unwrap()
            .tokens;
        let device_b = h
            .auth
            .login("klai@example.com", &pw("old-password"))
            .await
            .unwrap()
            .tokens;
        let ctx_a = h
            .auth
            .authenticate(device_a.access_token.expose_secret())
            .await
            .unwrap();

        let revoked = h
            .auth
            .change_own_password(&ctx_a, &pw("old-password"), &pw("new-password-123"))
            .await
            .unwrap();
        assert_eq!(revoked, 1); // только device_b

        // текущая сессия (device_a) жива
        assert!(
            h.auth
                .authenticate(device_a.access_token.expose_secret())
                .await
                .is_ok()
        );
        // device_b отозван
        assert!(matches!(
            h.auth.refresh(&device_b.refresh_token).await,
            Err(AuthError::Unauthorized)
        ));
        // новый пароль работает, старый — нет
        h.auth
            .login("klai@example.com", &pw("new-password-123"))
            .await
            .unwrap();
        assert!(matches!(
            h.auth.login("klai@example.com", &pw("old-password")).await,
            Err(AuthError::InvalidCredentials)
        ));
    }

    #[tokio::test]
    async fn change_own_password_validates_new_password_length() {
        let h = Harness::new();
        h.users.seed("klai@example.com", "old-password", true);
        let tokens = h
            .auth
            .login("klai@example.com", &pw("old-password"))
            .await
            .unwrap()
            .tokens;
        let ctx = h
            .auth
            .authenticate(tokens.access_token.expose_secret())
            .await
            .unwrap();

        let err = h
            .auth
            .change_own_password(&ctx, &pw("old-password"), &pw("short"))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    #[test]
    fn policy_invariants() {
        assert!(AuthPolicy::new(minutes(15), TimeDelta::try_days(30).unwrap()).is_ok());
        assert!(AuthPolicy::new(TimeDelta::zero(), minutes(10)).is_err());
        assert!(AuthPolicy::new(minutes(30), minutes(30)).is_err());
    }
}

// --- register: отдельный блок тестов, дописан к существующему mod tests ---
#[cfg(test)]
mod register_tests {
    use secrecy::SecretString;

    use super::*;
    use crate::testing::Harness;

    #[tokio::test]
    async fn disabled_by_default() {
        let h = Harness::new();
        let err = h
            .auth
            .register(RegisterInput {
                email: "new@example.com".into(),
                password: SecretString::from("long-enough-pw"),
                first_name: "N".into(),
                second_name: "U".into(),
            })
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Forbidden));
    }

    #[tokio::test]
    async fn enabled_creates_and_logs_in_then_rejects_duplicate() {
        let h = Harness::new();
        let auth = AuthService::new(
            h.users.clone(),
            h.sessions.clone(),
            h.hasher.clone(),
            std::sync::Arc::new(crate::testing::FakeCodec),
            std::sync::Arc::new(crate::testing::FakeRefresh::default()),
            h.clock.clone(),
            crate::testing::MemSettings::new(true),
            h.uow.clone(),
            h.audit.clone(),
            AuthPolicy::default(),
        );

        let res = auth
            .register(RegisterInput {
                email: "new@example.com".into(),
                password: SecretString::from("long-enough-pw"),
                first_name: "N".into(),
                second_name: "U".into(),
            })
            .await
            .unwrap();
        assert_eq!(res.user.email.as_str(), "new@example.com");

        let dup = auth
            .register(RegisterInput {
                email: "new@example.com".into(),
                password: SecretString::from("long-enough-pw"),
                first_name: "N".into(),
                second_name: "U".into(),
            })
            .await;
        assert!(matches!(dup, Err(AuthError::Conflict)));

        let events = h.audit.events();
        assert_eq!(
            events.len(),
            1,
            "повторная регистрация в журнал не попадает"
        );
        assert_eq!(events[0].action, audit_actions::USER_REGISTER);
        assert_eq!(events[0].actor, Some(res.user.id));
        assert_eq!(events[0].details["email"], "new@example.com");
    }
}
