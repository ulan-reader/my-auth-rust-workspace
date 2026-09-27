//! Авторизация: есть ли у аутентифицированного пользователя нужное право.

use std::sync::Arc;

use tracing::{Level, instrument};

use super::{AuthContext, Ports};
use crate::{
    AuthError, Result,
    domain::{PermissionCode, ScopeId},
    ports::PermissionRepository,
};

/// Права собственной админки auth-сервиса (как в старом admin.rs).
pub mod admin_permissions {
    pub const USERS_VIEW: &str = "users.view";
    pub const USERS_MANAGE: &str = "users.manage";
    pub const ROLES_VIEW: &str = "roles.view";
    pub const ROLES_MANAGE: &str = "roles.manage";
    pub const ROLES_ASSIGN: &str = "roles.assign";
    pub const PERMISSIONS_VIEW: &str = "permissions.view";
    pub const SETTINGS_MANAGE: &str = "settings.manage";
}

#[derive(Clone)]
pub struct AccessService {
    permissions: Arc<dyn PermissionRepository>,
}

impl AccessService {
    pub fn new(permissions: Arc<dyn PermissionRepository>) -> Self {
        Self { permissions }
    }

    pub fn from_ports(ports: &Ports) -> Self {
        Self::new(ports.permissions.clone())
    }

    /// `scope = None` — считаются только глобальные роли. `Some(s)` — глобальные
    /// плюс роли, назначенные именно на `s`.
    ///
    /// Код права — строка; невалидный код это ошибка программиста, а не пользователя,
    /// поэтому результат `Internal`, а не `Validation`.
    #[instrument(skip(self, ctx), fields(user_id = %ctx.user.id), err(level = Level::WARN))]
    pub async fn has_permission(
        &self,
        ctx: &AuthContext,
        code: &str,
        scope: Option<&ScopeId>,
    ) -> Result<bool> {
        let code = PermissionCode::parse(code).map_err(AuthError::internal)?;
        let granted = self
            .permissions
            .effective_for_user(ctx.user.id, scope)
            .await?;
        Ok(granted.contains(&code))
    }

    /// То же, но нет права -> `Forbidden`.
    pub async fn require_permission(
        &self,
        ctx: &AuthContext,
        code: &str,
        scope: Option<&ScopeId>,
    ) -> Result<()> {
        if self.has_permission(ctx, code, scope).await? {
            Ok(())
        } else {
            Err(AuthError::Forbidden)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{domain::SessionId, testing::Harness};

    fn ctx_for(h: &Harness) -> AuthContext {
        let user = h.users.seed("klai@example.com", "pw", true);
        AuthContext {
            user,
            session_id: SessionId(1),
        }
    }

    #[tokio::test]
    async fn global_permission_applies_everywhere_scoped_only_in_its_scope() {
        let h = Harness::new();
        let ctx = ctx_for(&h);
        h.permissions.grant(ctx.user_id(), None, "users.view");
        h.permissions
            .grant(ctx.user_id(), Some("department:1"), "roles.manage");

        let dept1 = ScopeId::parse("department:1").unwrap();
        let dept2 = ScopeId::parse("department:2").unwrap();

        assert!(
            h.access
                .has_permission(&ctx, "users.view", None)
                .await
                .unwrap()
        );
        assert!(
            h.access
                .has_permission(&ctx, "users.view", Some(&dept2))
                .await
                .unwrap()
        );
        assert!(
            h.access
                .has_permission(&ctx, "roles.manage", Some(&dept1))
                .await
                .unwrap()
        );
        assert!(
            !h.access
                .has_permission(&ctx, "roles.manage", Some(&dept2))
                .await
                .unwrap()
        );
        assert!(
            !h.access
                .has_permission(&ctx, "roles.manage", None)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn require_permission_returns_forbidden() {
        let h = Harness::new();
        let ctx = ctx_for(&h);

        let err = h
            .access
            .require_permission(&ctx, admin_permissions::USERS_MANAGE, None)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Forbidden));

        h.permissions
            .grant(ctx.user_id(), None, admin_permissions::USERS_MANAGE);
        h.access
            .require_permission(&ctx, admin_permissions::USERS_MANAGE, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn malformed_code_is_a_programmer_error() {
        let h = Harness::new();
        let ctx = ctx_for(&h);

        let err = h
            .access
            .has_permission(&ctx, "Users View!", None)
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Internal(_)));
    }
}
