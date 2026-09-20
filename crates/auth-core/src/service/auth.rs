//! Аутентификация: вход, обновление токенов, выход, проверка access-токена.

use std::sync::Arc;

use chrono::{DateTime, TimeDelta, Utc};
use secrecy::SecretString;
use tracing::{Level, Span, instrument, warn};

use super::Ports;
use crate::{
    AuthError, Result,
    domain::*,
    ports::{
        AccessTokenCodec, Clock, NewSession, PasswordHasher, RefreshTokenProvider,
        SessionRepository, UserRepository,
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
    policy: AuthPolicy,
}

impl AuthService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        sessions: Arc<dyn SessionRepository>,
        hasher: Arc<dyn PasswordHasher>,
        access_tokens: Arc<dyn AccessTokenCodec>,
        refresh_tokens: Arc<dyn RefreshTokenProvider>,
        clock: Arc<dyn Clock>,
        policy: AuthPolicy,
    ) -> Self {
        Self {
            users,
            sessions,
            hasher,
            access_tokens,
            refresh_tokens,
            clock,
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
            policy,
        )
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

        let tokens = self.start_session(creds.user.id).await?;
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
            self.sessions
                .revoke_all_for_user(session.user_id, now)
                .await?;
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
        let next_session = match self.sessions.rotate(session.id, &next, now).await {
            Ok(s) => s,
            Err(AuthError::Conflict) => return Err(AuthError::Unauthorized),
            Err(e) => return Err(e),
        };

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
            match self.sessions.revoke(session.user_id, session.id, now).await {
                Ok(()) | Err(AuthError::NotFound) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Выйти со всех устройств. Возвращает, сколько сессий отозвано.
    pub async fn logout_all(&self, ctx: AuthContext) -> Result<u64> {
        self.sessions
            .revoke_all_for_user(ctx.user.id, self.clock.now())
            .await
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

    async fn start_session(&self, user_id: UserId) -> Result<TokenPair> {
        let now = self.clock.now();
        let refresh = self.refresh_tokens.issue()?;
        let session = self
            .sessions
            .create(&NewSession {
                user_id,
                token_hash: refresh.hash.clone(),
                created_at: now,
                expires_at: now + self.policy.refresh_ttl(),
            })
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

        h.users.set_active(user.id, false).await.unwrap();

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

    #[test]
    fn policy_invariants() {
        assert!(AuthPolicy::new(minutes(15), TimeDelta::try_days(30).unwrap()).is_ok());
        assert!(AuthPolicy::new(TimeDelta::zero(), minutes(10)).is_err());
        assert!(AuthPolicy::new(minutes(30), minutes(30)).is_err());
    }
}
