//! Управление пользователями: админские use-case'ы. Каждый метод сам проверяет
//! право актёра, поэтому «забыть проверку» в api-слое нельзя.

use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use tracing::{Level, info, instrument};

use super::{AccessService, AuthContext, Ports, admin_permissions as perm};
use crate::{
    AuthError, Result,
    domain::*,
    ports::{
        AssignmentRepository, Clock, NewUser, Page, PageRequest, PasswordHasher, SessionRepository,
        UserRepository, UserUpdate,
    },
};

const MIN_PASSWORD_CHARS: usize = 8;
const MAX_PASSWORD_CHARS: usize = 128; // верхняя граница защищает Argon2 от гигантских входов
const MAX_NAME_CHARS: usize = 100;

#[derive(Debug)]
pub struct CreateUser {
    pub email: String,
    pub password: SecretString,
    pub first_name: String,
    pub second_name: String,
}

#[derive(Debug)]
pub struct UpdateUser {
    pub email: String,
    pub first_name: String,
    pub second_name: String,
}

#[derive(Debug, Clone)]
pub struct UserWithRoles {
    pub user: User,
    pub roles: Vec<RoleAssignment>,
}

fn validate_password(password: &SecretString) -> Result<()> {
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

#[derive(Clone)]
pub struct UserService {
    users: Arc<dyn UserRepository>,
    assignments: Arc<dyn AssignmentRepository>,
    sessions: Arc<dyn SessionRepository>,
    hasher: Arc<dyn PasswordHasher>,
    clock: Arc<dyn Clock>,
    access: AccessService,
}

impl UserService {
    pub fn new(
        users: Arc<dyn UserRepository>,
        assignments: Arc<dyn AssignmentRepository>,
        sessions: Arc<dyn SessionRepository>,
        hasher: Arc<dyn PasswordHasher>,
        clock: Arc<dyn Clock>,
        access: AccessService,
    ) -> Self {
        Self {
            users,
            assignments,
            sessions,
            hasher,
            clock,
            access,
        }
    }

    pub fn from_ports(ports: &Ports) -> Self {
        Self::new(
            ports.users.clone(),
            ports.assignments.clone(),
            ports.sessions.clone(),
            ports.hasher.clone(),
            ports.clock.clone(),
            AccessService::from_ports(ports),
        )
    }

    #[instrument(skip_all, fields(actor = %actor.user_id()), err(level = Level::WARN))]
    pub async fn list(
        &self,
        actor: &AuthContext,
        req: &PageRequest,
    ) -> Result<Page<UserWithRoles>> {
        self.access
            .require_permission(actor, perm::USERS_VIEW, None)
            .await?;

        let page = self.users.list(req).await?;
        let ids: Vec<UserId> = page.items.iter().map(|u| u.id).collect();
        let mut roles = self.assignments.for_users(&ids).await?;

        Ok(page.map(|user| {
            let roles = roles.remove(&user.id).unwrap_or_default();
            UserWithRoles { user, roles }
        }))
    }

    #[instrument(skip_all, fields(actor = %actor.user_id(), target = %id), err(level = Level::WARN))]
    pub async fn get(&self, actor: &AuthContext, id: UserId) -> Result<UserWithRoles> {
        self.access
            .require_permission(actor, perm::USERS_VIEW, None)
            .await?;

        let user = self
            .users
            .find_by_id(id)
            .await?
            .ok_or(AuthError::NotFound)?;
        self.with_roles(user).await
    }

    #[instrument(skip_all, fields(actor = %actor.user_id()), err(level = Level::WARN))]
    pub async fn create(&self, actor: &AuthContext, input: CreateUser) -> Result<UserWithRoles> {
        self.access
            .require_permission(actor, perm::USERS_MANAGE, None)
            .await?;

        let email = Email::parse(&input.email)?;
        validate_password(&input.password)?;
        let new = NewUser {
            email,
            password_hash: self.hasher.hash(&input.password).await?,
            first_name: clean_name(&input.first_name, "имя")?,
            second_name: clean_name(&input.second_name, "фамилия")?,
        };

        let user = self.users.create(&new).await?;
        Ok(UserWithRoles {
            user,
            roles: Vec::new(),
        })
    }

    #[instrument(skip_all, fields(actor = %actor.user_id(), target = %id), err(level = Level::WARN))]
    pub async fn update(
        &self,
        actor: &AuthContext,
        id: UserId,
        input: &UpdateUser,
    ) -> Result<UserWithRoles> {
        self.access
            .require_permission(actor, perm::USERS_MANAGE, None)
            .await?;

        let upd = UserUpdate {
            email: Email::parse(&input.email)?,
            first_name: clean_name(&input.first_name, "имя")?,
            second_name: clean_name(&input.second_name, "фамилия")?,
        };

        let user = self.users.update(id, &upd).await?;
        self.with_roles(user).await
    }

    /// Смена пароля админом. Все сессии пользователя отзываются:
    /// кто знал старый пароль, не должен остаться внутри.
    #[instrument(skip_all, fields(actor = %actor.user_id(), target = %id), err(level = Level::WARN))]
    pub async fn set_password(
        &self,
        actor: &AuthContext,
        id: UserId,
        password: &SecretString,
    ) -> Result<()> {
        self.access
            .require_permission(actor, perm::USERS_MANAGE, None)
            .await?;

        validate_password(password)?;
        let hash = self.hasher.hash(password).await?;
        self.users.set_password_hash(id, &hash).await?;
        self.sessions
            .revoke_all_for_user(id, self.clock.now())
            .await?;

        Ok(())
    }

    /// Блокировка обрывает и сессии: уволенный не остаётся залогиненным до конца refresh.
    #[instrument(skip_all, fields(actor = %actor.user_id(), target = %id), err(level = Level::WARN))]
    pub async fn set_active(&self, actor: &AuthContext, id: UserId, active: bool) -> Result<()> {
        self.access
            .require_permission(actor, perm::USERS_MANAGE, None)
            .await?;

        if actor.user_id() == id && !active {
            return Err(AuthError::validation("нельзя деактивировать самого себя"));
        }

        self.users.set_active(id, active).await?;
        if !active {
            let revoked = self
                .sessions
                .revoke_all_for_user(id, self.clock.now())
                .await?;
            info!(revoked, "пользователь деактивирован, сессии отозваны");
        }
        Ok(())
    }

    /// Роли и сессии удаляются вместе с пользователем (атомарно, внутри репозитория).
    #[instrument(skip_all, fields(actor = %actor.user_id(), target = %id), err(level = Level::WARN))]
    pub async fn delete(&self, actor: &AuthContext, id: UserId) -> Result<()> {
        self.access
            .require_permission(actor, perm::USERS_MANAGE, None)
            .await?;

        if actor.user_id() == id {
            return Err(AuthError::validation("нельзя удалить самого себя"));
        }
        self.users.delete(id).await
    }

    async fn with_roles(&self, user: User) -> Result<UserWithRoles> {
        let mut map = self.assignments.for_users(&[user.id]).await?;
        let roles = map.remove(&user.id).unwrap_or_default();
        Ok(UserWithRoles { user, roles })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Harness, MemAssignments};

    fn pw(s: &str) -> SecretString {
        SecretString::from(s)
    }

    fn ctx(user: User) -> AuthContext {
        AuthContext {
            user,
            session_id: SessionId(1),
        }
    }

    fn new_user(email: &str, password: &str) -> CreateUser {
        CreateUser {
            email: email.into(),
            password: pw(password),
            first_name: "Test".into(),
            second_name: "User".into(),
        }
    }

    struct Fixture {
        h: Harness,
        svc: UserService,
        assignments: Arc<MemAssignments>,
        admin: AuthContext,
    }

    fn fixture() -> Fixture {
        let h = Harness::new();
        let assignments = Arc::new(MemAssignments::default());
        let svc = UserService::new(
            h.users.clone(),
            assignments.clone(),
            h.sessions.clone(),
            h.hasher.clone(),
            h.clock.clone(),
            h.access.clone(),
        );
        let admin = h.users.seed("admin@example.com", "admin-password", true);
        for code in [perm::USERS_VIEW, perm::USERS_MANAGE] {
            h.permissions.grant(admin.id, None, code);
        }
        Fixture {
            h,
            svc,
            assignments,
            admin: ctx(admin),
        }
    }

    #[tokio::test]
    async fn create_normalizes_hashes_and_enforces_rules() {
        let f = fixture();

        let created = f
            .svc
            .create(
                &f.admin,
                CreateUser {
                    email: " New@Example.COM ".into(),
                    password: pw("long-enough-pw"),
                    first_name: "  Ann ".into(),
                    second_name: "Lee".into(),
                },
            )
            .await
            .unwrap();
        assert_eq!(created.user.email.as_str(), "new@example.com");
        assert_eq!(created.user.first_name, "Ann");
        assert!(created.roles.is_empty());
        // пароль сохранён хешем и годится для входа
        f.h.auth
            .login("new@example.com", &pw("long-enough-pw"))
            .await
            .unwrap();

        let dup = f
            .svc
            .create(&f.admin, new_user("new@example.com", "long-enough-pw"))
            .await;
        assert!(matches!(dup, Err(AuthError::Conflict)));
        let short = f
            .svc
            .create(&f.admin, new_user("a@example.com", "short"))
            .await;
        assert!(matches!(short, Err(AuthError::Validation(_))));
        let bad_email = f
            .svc
            .create(&f.admin, new_user("nope", "long-enough-pw"))
            .await;
        assert!(matches!(bad_email, Err(AuthError::Validation(_))));
    }

    #[tokio::test]
    async fn every_method_requires_its_permission() {
        let f = fixture();
        let nobody = ctx(f
            .h
            .users
            .seed("nobody@example.com", "nobody-password", true));
        let target = f.h.users.seed("t@example.com", "t-password", true);

        let update = UpdateUser {
            email: "x@example.com".into(),
            first_name: "X".into(),
            second_name: "Y".into(),
        };
        assert!(matches!(
            f.svc.list(&nobody, &PageRequest::default()).await,
            Err(AuthError::Forbidden)
        ));
        assert!(matches!(
            f.svc.get(&nobody, target.id).await,
            Err(AuthError::Forbidden)
        ));
        assert!(matches!(
            f.svc
                .create(&nobody, new_user("a@example.com", "long-enough-pw"))
                .await,
            Err(AuthError::Forbidden)
        ));
        assert!(matches!(
            f.svc.update(&nobody, target.id, &update).await,
            Err(AuthError::Forbidden)
        ));
        assert!(matches!(
            f.svc
                .set_password(&nobody, target.id, &pw("long-enough-pw"))
                .await,
            Err(AuthError::Forbidden)
        ));
        assert!(matches!(
            f.svc.set_active(&nobody, target.id, false).await,
            Err(AuthError::Forbidden)
        ));
        assert!(matches!(
            f.svc.delete(&nobody, target.id).await,
            Err(AuthError::Forbidden)
        ));
    }

    #[tokio::test]
    async fn list_attaches_roles_and_supports_search() {
        let f = fixture();
        let anna = f.h.users.seed("anna@example.com", "anna-password", true);
        let boris = f.h.users.seed("boris@example.com", "boris-password", true);
        f.assignments.seed(anna.id, "admin", None);
        f.assignments
            .seed(boris.id, "dept_head", Some("department:1"));

        let page = f.svc.list(&f.admin, &PageRequest::default()).await.unwrap();
        assert_eq!(page.total, 3); // admin + anna + boris

        let of = |email: &str| {
            page.items
                .iter()
                .find(|u| u.user.email.as_str() == email)
                .unwrap()
        };
        assert_eq!(of("anna@example.com").roles.len(), 1);
        assert_eq!(
            of("boris@example.com").roles[0]
                .scope
                .as_ref()
                .map(ScopeId::as_str),
            Some("department:1")
        );
        assert!(of("admin@example.com").roles.is_empty());

        let found = f
            .svc
            .list(&f.admin, &PageRequest::new(None, None, Some("bor".into())))
            .await
            .unwrap();
        assert_eq!(found.total, 1);
    }

    #[tokio::test]
    async fn update_normalizes_and_reports_conflicts() {
        let f = fixture();
        let target = f.h.users.seed("t@example.com", "t-password", true);
        let other = f.h.users.seed("other@example.com", "other-password", true);

        let taken = UpdateUser {
            email: "t@example.com".into(),
            first_name: "X".into(),
            second_name: "Y".into(),
        };
        assert!(matches!(
            f.svc.update(&f.admin, other.id, &taken).await,
            Err(AuthError::Conflict)
        ));

        let ok = UpdateUser {
            email: " Renamed@Example.com ".into(),
            first_name: " Xena ".into(),
            second_name: "Y".into(),
        };
        let updated = f.svc.update(&f.admin, target.id, &ok).await.unwrap();
        assert_eq!(updated.user.email.as_str(), "renamed@example.com");
        assert_eq!(updated.user.first_name, "Xena");

        assert!(matches!(
            f.svc.update(&f.admin, UserId(999), &ok).await,
            Err(AuthError::NotFound)
        ));
    }

    #[tokio::test]
    async fn set_password_revokes_sessions() {
        let f = fixture();
        let target = f.h.users.seed("t@example.com", "t-password", true);
        let tokens =
            f.h.auth
                .login("t@example.com", &pw("t-password"))
                .await
                .unwrap()
                .tokens;

        f.svc
            .set_password(&f.admin, target.id, &pw("brand-new-pass"))
            .await
            .unwrap();

        assert!(matches!(
            f.h.auth.login("t@example.com", &pw("t-password")).await,
            Err(AuthError::InvalidCredentials)
        ));
        f.h.auth
            .login("t@example.com", &pw("brand-new-pass"))
            .await
            .unwrap();
        assert!(matches!(
            f.h.auth.refresh(&tokens.refresh_token).await,
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            f.svc.set_password(&f.admin, target.id, &pw("short")).await,
            Err(AuthError::Validation(_))
        ));
    }

    #[tokio::test]
    async fn deactivation_ends_sessions_and_self_lockout_is_blocked() {
        let f = fixture();
        let target = f.h.users.seed("t@example.com", "t-password", true);
        let tokens =
            f.h.auth
                .login("t@example.com", &pw("t-password"))
                .await
                .unwrap()
                .tokens;

        f.svc.set_active(&f.admin, target.id, false).await.unwrap();

        assert!(matches!(
            f.h.auth
                .authenticate(tokens.access_token.expose_secret())
                .await,
            Err(AuthError::Unauthorized)
        ));
        assert!(matches!(
            f.h.auth.login("t@example.com", &pw("t-password")).await,
            Err(AuthError::AccountDisabled)
        ));

        assert!(matches!(
            f.svc.set_active(&f.admin, f.admin.user_id(), false).await,
            Err(AuthError::Validation(_))
        ));

        // обратно включается
        f.svc.set_active(&f.admin, target.id, true).await.unwrap();
        f.h.auth
            .login("t@example.com", &pw("t-password"))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn delete_removes_user_but_not_yourself() {
        let f = fixture();
        let target = f.h.users.seed("t@example.com", "t-password", true);

        assert!(matches!(
            f.svc.delete(&f.admin, f.admin.user_id()).await,
            Err(AuthError::Validation(_))
        ));

        f.svc.delete(&f.admin, target.id).await.unwrap();
        assert!(matches!(
            f.svc.get(&f.admin, target.id).await,
            Err(AuthError::NotFound)
        ));
        assert!(matches!(
            f.svc.delete(&f.admin, target.id).await,
            Err(AuthError::NotFound)
        ));
    }
}
