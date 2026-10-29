//! Управление ролями: CRUD, права роли, назначение/снятие с пользователей.

use std::{collections::HashSet, sync::Arc};

use tracing::{Level, instrument};

use super::{AccessService, AuthContext, Ports, access::require_subset, admin_permissions as perm};
use crate::{
    AuthError, Result,
    domain::*,
    ports::{
        AssignmentRepository, LockedRole, NewRole, Page, PageRequest, RoleRepository, RoleUpdate,
        UnitOfWork,
    },
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
    uow: Arc<dyn UnitOfWork>,
}

impl RoleService {
    pub fn new(
        roles: Arc<dyn RoleRepository>,
        assignments: Arc<dyn AssignmentRepository>,
        access: AccessService,
        uow: Arc<dyn UnitOfWork>,
    ) -> Self {
        Self {
            roles,
            assignments,
            access,
            uow,
        }
    }

    pub fn from_ports(ports: &Ports) -> Self {
        Self::new(
            ports.roles.clone(),
            ports.assignments.clone(),
            AccessService::from_ports(ports),
            ports.uow.clone(),
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

        let mut tx = self.uow.begin().await?;
        let role: Role = self.roles.create(&mut *tx, &new).await?;
        tx.commit().await?;
        Ok(role)
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
        let granted = self.access.granted(actor, None).await?;

        let upd = RoleUpdate {
            code: RoleCode::parse(&input.code)?,
            name: clean_name(&input.name)?,
        };
        
        let mut tx = self.uow.begin().await?;
        let locked = self
            .roles
            .lock(&mut *tx, id)
            .await?
            .ok_or(AuthError::NotFound)?;
        require_holds(&granted, &locked)?;
        if locked.role.code.as_str() == ADMIN_ROLE_CODE && input.code.trim() != ADMIN_ROLE_CODE {
            return Err(AuthError::validation(
                "код системной роли admin менять нельзя",
            ));
        }

        let role = self.roles.update(&mut *tx, id, &upd).await?;
        tx.commit().await?;
        Ok(role)
    }

    /// Назначения роли и её права удаляются вместе с ней (атомарно, внутри репозитория).
    #[instrument(skip_all, fields(actor = %actor.user_id(), target = %id), err(level = Level::WARN))]
    pub async fn delete(&self, actor: &AuthContext, id: RoleId) -> Result<()> {
        self.access
            .require_permission(actor, perm::ROLES_MANAGE, None)
            .await?;
        let granted = self.access.granted(actor, None).await?;

        let mut tx = self.uow.begin().await?;
        let locked = self
            .roles
            .lock(&mut *tx, id)
            .await?
            .ok_or(AuthError::NotFound)?;
        require_holds(&granted, &locked)?;
        ensure_not_system(&locked.role, "удалить")?;
        self.roles.delete(&mut *tx, id).await?;
        tx.commit().await
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
        let granted = self.access.granted(actor, None).await?;
        let wanted = self.access.codes_of(permission_ids).await?;
        require_subset(&granted, &wanted)?;

        let mut tx = self.uow.begin().await?;
        let locked = self
            .roles
            .lock(&mut *tx, role)
            .await?
            .ok_or(AuthError::NotFound)?;
        require_holds(&granted, &locked)?;
        ensure_not_system(
            &locked.role,
            "редактировать по правам: у неё всегда все права",
        )?;
        let permissions = self
            .roles
            .set_permissions(&mut *tx, role, permission_ids)
            .await?;
        tx.commit().await?;
        Ok(permissions)
    }

    /// Назначает роль пользователю. Соответствие `role.scope` и `input.scope`
    /// проверяется по домену (`RoleScope::check_assignment`), не по адаптеру.
    #[instrument(skip_all, fields(actor = %actor.user_id()), err(level = Level::WARN))]
    pub async fn assign(&self, actor: &AuthContext, input: AssignRole) -> Result<()> {
        // право на назначение проверяем в том scope, куда назначаем:
        // админ раздела раздаёт роли только у себя
        let scope = input.scope.as_deref().map(ScopeId::parse).transpose()?;
        self.access
            .require_permission(actor, perm::ROLES_ASSIGN, scope.as_ref())
            .await?;
        let granted = self.access.granted(actor, scope.as_ref()).await?;

        let mut tx = self.uow.begin().await?;
        let locked = self
            .roles
            .lock(&mut *tx, input.role)
            .await?
            .ok_or(AuthError::NotFound)?;
        locked.role.scope.check_assignment(scope.as_ref())?;
        require_holds(&granted, &locked)?;
        self.assignments
            .assign(&mut *tx, input.user, input.role, scope.as_ref())
            .await?;
        tx.commit().await
    }

    /// Идемпотентно: отсутствие назначения — не ошибка.
    #[instrument(skip_all, fields(actor = %actor.user_id()), err(level = Level::WARN))]
    pub async fn unassign(&self, actor: &AuthContext, input: AssignRole) -> Result<()> {
        let scope = input.scope.as_deref().map(ScopeId::parse).transpose()?;
        self.access
            .require_permission(actor, perm::ROLES_ASSIGN, scope.as_ref())
            .await?;
        let granted = self.access.granted(actor, scope.as_ref()).await?;

        let mut tx = self.uow.begin().await?;
        let Some(locked) = self.roles.lock(&mut *tx, input.role).await? else {
            return Ok(()); // нет роли — нет и назначения: идемпотентно, как и раньше
        };
        require_holds(&granted, &locked)?;
        self.assignments
            .unassign(&mut *tx, input.user, input.role, scope.as_ref())
            .await?;
        tx.commit().await
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

fn ensure_not_system(role: &Role, action: &str) -> Result<()> {
    if role.code.as_str() == ADMIN_ROLE_CODE {
        return Err(AuthError::validation(format!(
            "системную роль admin нельзя {action}"
        )));
    }
    Ok(())
}

/// Трогать роль можно, только если у тебя есть все её права: иначе через
/// назначение или правку роли можно поднять себе (или снять с других) чужие права.
fn require_holds(granted: &HashSet<PermissionCode>, role: &LockedRole) -> Result<()> {
    require_subset(granted, role.permissions.iter().map(|p| &p.code))
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
        let svc = RoleService::new(roles, assignments, h.access.clone(), h.uow.clone());
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
    async fn scope_admin_assigns_only_inside_own_scope() {
        let f = fixture();
        let editor = f
            .svc
            .create(
                &f.admin,
                CreateRole {
                    code: "wiki_editor".into(),
                    name: "Wiki editor".into(),
                    scope: RoleScope::Scoped,
                },
            )
            .await
            .unwrap();
        let viewer = f
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

        let wiki_admin = f.h.users.seed("wiki-admin@example.com", "password-1", true);
        f.h.permissions
            .grant(wiki_admin.id, Some("space:wiki"), perm::ROLES_ASSIGN);
        let wiki_admin = ctx(wiki_admin);
        let user = f.h.users.seed("user@example.com", "password-1", true);
        let assign = |role: RoleId, scope: Option<&str>| AssignRole {
            user: user.id,
            role,
            scope: scope.map(Into::into),
        };

        // в своём разделе — можно, в том числе снять
        f.svc
            .assign(&wiki_admin, assign(editor.id, Some("space:wiki")))
            .await
            .unwrap();
        f.svc
            .unassign(&wiki_admin, assign(editor.id, Some("space:wiki")))
            .await
            .unwrap();

        // в чужом разделе — нельзя
        assert!(matches!(
            f.svc
                .assign(&wiki_admin, assign(editor.id, Some("space:hr")))
                .await,
            Err(AuthError::Forbidden)
        ));
        // глобальную роль — нельзя
        assert!(matches!(
            f.svc.assign(&wiki_admin, assign(viewer.id, None)).await,
            Err(AuthError::Forbidden)
        ));
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

    #[tokio::test]
    async fn cannot_assign_role_with_permissions_actor_lacks() {
        let f = fixture();
        let role = f
            .svc
            .create(
                &f.admin,
                CreateRole {
                    code: "super".into(),
                    name: "Super".into(),
                    scope: RoleScope::Global,
                },
            )
            .await
            .unwrap();
        // MemRoles называет права "perm-{id}"
        f.svc
            .set_permissions(&f.admin, role.id, &[PermissionId(42)])
            .await
            .unwrap();
        let victim = f.h.users.seed("victim@example.com", "password-1", true);
        let assign = || AssignRole {
            user: victim.id,
            role: role.id,
            scope: None,
        };

        assert!(matches!(
            f.svc.assign(&f.admin, assign()).await,
            Err(AuthError::Forbidden)
        ));

        f.h.permissions.grant(f.admin.user_id(), None, "perm-42");
        f.svc.assign(&f.admin, assign()).await.unwrap();
    }
}
