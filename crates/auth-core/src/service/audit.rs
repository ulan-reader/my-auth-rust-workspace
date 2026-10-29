//! Журнал аудита: кто и когда менял доступы. Пишут его сами use-case'ы — в той же
//! транзакции, что и изменение (`AuditRepository::record`); здесь — только чтение.

use std::sync::Arc;

use tracing::{Level, instrument};

use super::{AccessService, AuthContext, Ports, admin_permissions as perm};
use crate::{
    Result,
    ports::{AuditFilter, AuditRecord, AuditRepository, Page, PageRequest},
};

/// Коды действий в журнале. Меняя код, помните: старые записи останутся со старым.
pub mod audit_actions {
    pub const ROLE_CREATE: &str = "role.create";
    pub const ROLE_UPDATE: &str = "role.update";
    pub const ROLE_DELETE: &str = "role.delete";
    pub const ROLE_PERMISSIONS_SET: &str = "role.permissions.set";
    pub const ROLE_ASSIGN: &str = "role.assign";
    pub const ROLE_UNASSIGN: &str = "role.unassign";

    pub const USER_CREATE: &str = "user.create";
    pub const USER_UPDATE: &str = "user.update";
    pub const USER_PASSWORD_SET: &str = "user.password.set";
    pub const USER_ACTIVATE: &str = "user.activate";
    pub const USER_DEACTIVATE: &str = "user.deactivate";
    pub const USER_DELETE: &str = "user.delete";

    /// Действия самого пользователя над своим аккаунтом.
    pub const USER_REGISTER: &str = "user.register";
    pub const USER_PASSWORD_CHANGE: &str = "user.password.change";
    pub const AUTH_LOGIN: &str = "auth.login";
    pub const AUTH_LOGOUT: &str = "auth.logout";
    pub const AUTH_LOGOUT_ALL: &str = "auth.logout_all";
    /// Предъявлен refresh-токен уже отозванной сессии: вероятная кража,
    /// все сессии пользователя отозваны. `actor = None` — это реакция системы.
    pub const AUTH_REFRESH_REPLAY: &str = "auth.refresh.replay";

    pub const SETTINGS_UPDATE: &str = "settings.update";
    /// Пишет адаптер внутри `SetupRepository::create_first_admin`.
    pub const SETUP_COMPLETE: &str = "setup.complete";
}

/// Типы объектов в журнале (`target_type`).
pub(crate) mod audit_targets {
    pub const ROLE: &str = "role";
    pub const USER: &str = "user";
    pub const SETTINGS: &str = "settings";
}

#[derive(Clone)]
pub struct AuditService {
    audit: Arc<dyn AuditRepository>,
    access: AccessService,
}

impl AuditService {
    pub fn new(audit: Arc<dyn AuditRepository>, access: AccessService) -> Self {
        Self { audit, access }
    }

    pub fn from_ports(ports: &Ports) -> Self {
        Self::new(ports.audit.clone(), AccessService::from_ports(ports))
    }

    #[instrument(skip_all, fields(actor = %actor.user_id()), err(level = Level::WARN))]
    pub async fn list(
        &self,
        actor: &AuthContext,
        filter: &AuditFilter,
        req: &PageRequest,
    ) -> Result<Page<AuditRecord>> {
        self.access
            .require_permission(actor, perm::AUDIT_VIEW, None)
            .await?;
        self.audit.list(filter, req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthError,
        domain::SessionId,
        ports::{AuditEvent, UnitOfWork},
        testing::Harness,
    };

    #[tokio::test]
    async fn list_requires_audit_view_and_filters() {
        let h = Harness::new();
        let svc = AuditService::new(h.audit.clone(), h.access.clone());
        let user = h.users.seed("auditor@example.com", "password-1", true);
        let actor = AuthContext {
            user: user.clone(),
            session_id: SessionId(1),
        };

        let mut tx = h.uow.begin().await.unwrap();
        for action in [audit_actions::ROLE_CREATE, audit_actions::USER_CREATE] {
            h.audit
                .record(
                    &mut *tx,
                    &AuditEvent::new(Some(user.id), action, audit_targets::ROLE, Some(1)),
                )
                .await
                .unwrap();
        }

        let all = AuditFilter::default();
        assert!(matches!(
            svc.list(&actor, &all, &PageRequest::default()).await,
            Err(AuthError::Forbidden)
        ));

        h.permissions.grant(user.id, None, perm::AUDIT_VIEW);
        let page = svc
            .list(&actor, &all, &PageRequest::default())
            .await
            .unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(
            page.items[0].action,
            audit_actions::USER_CREATE,
            "новые сверху"
        );

        let only_roles = AuditFilter {
            action: Some(audit_actions::ROLE_CREATE.into()),
            ..Default::default()
        };
        let page = svc
            .list(&actor, &only_roles, &PageRequest::default())
            .await
            .unwrap();
        assert_eq!(page.total, 1);
    }
}
