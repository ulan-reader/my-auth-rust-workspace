//! Управление ролями: CRUD, права роли, назначение/снятие с пользователей.

use std::sync::Arc;

use tracing::{Level, instrument};

use super::{AccessService, AuthContext, Ports, admin_permissions as perm};
use crate::{
    AuthError, Result,
    domain::*,
    ports::{AssignmentRepository, NewRole, Page, PageRequest, RoleRepository, RoleUpdate},
};

#[derive(Debug)]
pub struct CreateRole {
    pub code: String,
    pub name: String,
    pub scope: RoleScope,
}

#[derive(Debug)]
pub struct UpdateRole {
    pub code: String,
    pub name: String,
}

/// Назначение/снятие роли. `scope: None` — глобально; `Some(s)` — в рамках `s`.
/// Соответствие `role.scope` и `scope` проверяется через `RoleScope::check_assignment`.
#[derive(Debug)]
pub struct AssignRole {
    pub user: UserId,
    pub role: RoleId,
    pub scope: Option<String>,
}

#[derive(Clone)]
pub struct RoleService {
    roles: Arc<dyn RoleRepository>,
    assignments: Arc<dyn AssignmentRepository>,
    access: AccessService,
}

impl RoleService {
    pub fn new(
        roles: Arc<dyn RoleRepository>,
        assignments: Arc<dyn AssignmentRepository>,
        access: AccessService,
    ) -> Self {
        Self {
            roles,
            assignments,
            access,
        }
    }

    pub fn from_ports(ports: &Ports) -> Self {
        Self::new(
            ports.roles.clone(),
            ports.assignments.clone(),
            AccessService::from_ports(ports),
        )
    }

    #[instrument(skip_all, fields(actor = %actor.user_id()), err(level = Level::WARN))]
    pub async fn list(&self, actor: &AuthContext, req: &PageRequest) -> Result<Page<Role>> {
        self.access
            .require_permission(actor, perm::ROLES_VIEW, None)
            .await?;

        self.roles.list(req).await
    }

    #[instrument(skip_all, fields(actor = %actor.user_id(), target = %id), err(level = Level::WARN))]
    pub async fn get(&self, actor: &AuthContext, id: RoleId) -> Result<Role> {
        self.access
            .require_permission(actor, perm::ROLES_VIEW, None)
            .await?;
        self.roles.find_by_id(id).await?.ok_or(AuthError::NotFound)
    }

    #[instrument(skip_all, fields(actor = %actor.user_id()), err(level = Level::WARN))]
    pub async fn create(&self, actor: &AuthContext, input: CreateRole) -> Result<Role> {
        self.access
            .require_permission(actor, perm::ROLES_MANAGE, None)
            .await?;

        let new = NewRole {
            code: RoleCode::parse(&input.code)?,
            name: clean_name(&input.name)?,
            scope: input.scope,
        };

        self.roles.create(&new).await
    }

    /// `scope` роли этим методом не меняется: смена `scope` у уже назначенной роли
    /// ломает существующие назначения. Нужно другое — удалить роль и создать заново.
    #[instrument(skip_all, fields(actor = %actor.user_id(), target = %id), err(level = Level::WARN))]
    pub async fn update(
        &self,
        actor: &AuthContext,
        id: RoleId,
        input: &UpdateRole,
    ) -> Result<Role> {
        self.access
            .require_permission(actor, perm::ROLES_MANAGE, None)
            .await?;

        let upd = RoleUpdate {
            code: RoleCode::parse(&input.code)?,
            name: clean_name(&input.name)?,
        };

        self.roles.update(id, &upd).await
    }

    /// Назначения роли и её права удаляются вместе с ней (атомарно, внутри репозитория).
    #[instrument(skip_all, fields(actor = %actor.user_id(), target = %id), err(level = Level::WARN))]
    pub async fn delete(&self, actor: &AuthContext, id: RoleId) -> Result<()> {
        self.access
            .require_permission(actor, perm::ROLES_MANAGE, None)
            .await?;
        self.roles.delete(id).await
    }

    #[instrument(skip_all, fields(actor = %actor.user_id(), target = %role), err(level = Level::WARN))]
    pub async fn permissions_of(
        &self,
        actor: &AuthContext,
        role: RoleId,
    ) -> Result<Vec<Permission>> {
        self.access
            .require_permission(actor, perm::ROLES_VIEW, None)
            .await?;
        self.roles.permissions_of(role).await
    }

    /// Атомарно заменяет набор прав роли.
    #[instrument(skip_all, fields(actor = %actor.user_id(), target = %role), err(level = Level::WARN))]
    pub async fn set_permissions(
        &self,
        actor: &AuthContext,
        role: RoleId,
        permission_ids: &[PermissionId],
    ) -> Result<Vec<Permission>> {
        self.access
            .require_permission(actor, perm::ROLES_MANAGE, None)
            .await?;
        self.roles.set_permissions(role, permission_ids).await
    }

    /// Назначает роль пользователю. Соответствие `role.scope` и `input.scope`
    /// проверяется по домену (`RoleScope::check_assignment`), не по адаптеру.
    #[instrument(skip_all, fields(actor = %actor.user_id()), err(level = Level::WARN))]
    pub async fn assign(&self, actor: &AuthContext, input: AssignRole) -> Result<()> {
        self.access
            .require_permission(actor, perm::ROLES_ASSIGN, None)
            .await?;

        let role = self
            .roles
            .find_by_id(input.role)
            .await?
            .ok_or(AuthError::NotFound)?;
        let scope = input.scope.as_deref().map(ScopeId::parse).transpose()?;
        role.scope.check_assignment(scope.as_ref())?;

        self.assignments
            .assign(input.user, input.role, scope.as_ref())
            .await
    }

    /// Идемпотентно: отсутствие назначения — не ошибка.
    #[instrument(skip_all, fields(actor = %actor.user_id()), err(level = Level::WARN))]
    pub async fn unassign(&self, actor: &AuthContext, input: AssignRole) -> Result<()> {
        self.access
            .require_permission(actor, perm::ROLES_ASSIGN, None)
            .await?;

        let scope = input.scope.as_deref().map(ScopeId::parse).transpose()?;
        self.assignments
            .unassign(input.user, input.role, scope.as_ref())
            .await
    }
}

fn clean_name(raw: &str) -> Result<String> {
    let name = raw.trim();
    if name.is_empty() {
        return Err(AuthError::validation("название роли обязательно"));
    }

    if name.chars().count() > 100 {
        return Err(AuthError::validation(
            "название роли: не длиннее 100 символов",
        ));
    }
    Ok(name.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{Harness, MemAssignments, MemRoles};

    fn ctx(user: User) -> AuthContext {
        AuthContext {
            user,
            session_id: SessionId(1),
        }
    }

    struct Fixture {
        h: Harness,
        svc: RoleService,
        admin: AuthContext,
    }

    fn fixture() -> Fixture {
        let h = Harness::new();
        let roles = Arc::new(MemRoles::default());
        let assignments = Arc::new(MemAssignments::default());
        let svc = RoleService::new(roles, assignments, h.access.clone());
        let admin = h.users.seed("admin@example.com", "admin-password", true);
        for code in [perm::ROLES_VIEW, perm::ROLES_MANAGE, perm::ROLES_ASSIGN] {
            h.permissions.grant(admin.id, None, code);
        }
        Fixture {
            h,
            svc,
            admin: ctx(admin),
        }
    }

    #[tokio::test]
    async fn create_validates_and_rejects_duplicate_code() {
        let f = fixture();

        let global = f
            .svc
            .create(
                &f.admin,
                CreateRole {
                    code: "admin".into(),
                    name: " Администратор ".into(),
                    scope: RoleScope::Global,
                },
            )
            .await
            .unwrap();
        assert_eq!(global.name, "Администратор");

        let dup = f
            .svc
            .create(
                &f.admin,
                CreateRole {
                    code: "admin".into(),
                    name: "Дубликат".into(),
                    scope: RoleScope::Global,
                },
            )
            .await;
        assert!(matches!(dup, Err(AuthError::Conflict)));

        let bad_code = f
            .svc
            .create(
                &f.admin,
                CreateRole {
                    code: "Bad Code".into(),
                    name: "X".into(),
                    scope: RoleScope::Global,
                },
            )
            .await;
        assert!(matches!(bad_code, Err(AuthError::Validation(_))));
    }

    #[tokio::test]
    async fn every_method_requires_its_permission() {
        let f = fixture();
        let nobody = ctx(f
            .h
            .users
            .seed("nobody@example.com", "nobody-password", true));
        let role = f
            .svc
            .create(
                &f.admin,
                CreateRole {
                    code: "editor".into(),
                    name: "Editor".into(),
                    scope: RoleScope::Global,
                },
            )
            .await
            .unwrap();

        assert!(matches!(
            f.svc.list(&nobody, &PageRequest::default()).await,
            Err(AuthError::Forbidden)
        ));
        assert!(matches!(
            f.svc.get(&nobody, role.id).await,
            Err(AuthError::Forbidden)
        ));
        assert!(matches!(
            f.svc.set_permissions(&nobody, role.id, &[]).await,
            Err(AuthError::Forbidden)
        ));
        assert!(matches!(
            f.svc
                .assign(
                    &nobody,
                    AssignRole {
                        user: f.admin.user_id(),
                        role: role.id,
                        scope: None
                    }
                )
                .await,
            Err(AuthError::Forbidden)
        ));
    }

    #[tokio::test]
    async fn assign_enforces_scope_rules_and_is_reflected_in_effective_permissions() {
        let f = fixture();
        let user = f.h.users.seed("u@example.com", "u-password", true);
        let global_role = f
            .svc
            .create(
                &f.admin,
                CreateRole {
                    code: "viewer".into(),
                    name: "Viewer".into(),
                    scope: RoleScope::Global,
                },
            )
            .await
            .unwrap();
        let scoped_role = f
            .svc
            .create(
                &f.admin,
                CreateRole {
                    code: "dept_head".into(),
                    name: "Dept Head".into(),
                    scope: RoleScope::Scoped,
                },
            )
            .await
            .unwrap();

        // глобальной роли нельзя дать scope
        assert!(matches!(
            f.svc
                .assign(
                    &f.admin,
                    AssignRole {
                        user: user.id,
                        role: global_role.id,
                        scope: Some("department:1".into()),
                    }
                )
                .await,
            Err(AuthError::Validation(_))
        ));
        // роли с областью действия scope обязателен
        assert!(matches!(
            f.svc
                .assign(
                    &f.admin,
                    AssignRole {
                        user: user.id,
                        role: scoped_role.id,
                        scope: None
                    }
                )
                .await,
            Err(AuthError::Validation(_))
        ));

        f.svc
            .assign(
                &f.admin,
                AssignRole {
                    user: user.id,
                    role: global_role.id,
                    scope: None,
                },
            )
            .await
            .unwrap();
        f.svc
            .assign(
                &f.admin,
                AssignRole {
                    user: user.id,
                    role: scoped_role.id,
                    scope: Some("department:1".into()),
                },
            )
            .await
            .unwrap();
        // повторное назначение — конфликт
        assert!(matches!(
            f.svc
                .assign(
                    &f.admin,
                    AssignRole {
                        user: user.id,
                        role: global_role.id,
                        scope: None
                    }
                )
                .await,
            Err(AuthError::Conflict)
        ));

        f.svc
            .unassign(
                &f.admin,
                AssignRole {
                    user: user.id,
                    role: global_role.id,
                    scope: None,
                },
            )
            .await
            .unwrap();
        // повторный unassign идемпотентен
        f.svc
            .unassign(
                &f.admin,
                AssignRole {
                    user: user.id,
                    role: global_role.id,
                    scope: None,
                },
            )
            .await
            .unwrap();
    }
}
