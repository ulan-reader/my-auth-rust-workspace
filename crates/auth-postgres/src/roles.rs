use async_trait::async_trait;
use auth_core::{
    AuthError, Result,
    domain::{Permission, PermissionCode, PermissionId, Role, RoleCode, RoleId, RoleScope},
    ports::{NewRole, Page, PageRequest, RoleRepository, RoleUpdate},
};
use sqlx::PgPool;
use tracing::instrument;

use crate::error::map_db_error;

#[derive(sqlx::FromRow)]
struct RoleRow {
    id: i64,
    code: String,
    name: String,
    scope: String,
}

impl RoleRow {
    fn into_role(self) -> Result<Role> {
        Ok(Role {
            id: RoleId(self.id),
            code: RoleCode::parse(&self.code).map_err(AuthError::internal)?,
            name: self.name,
            scope: self
                .scope
                .parse::<RoleScope>()
                .map_err(AuthError::internal)?,
        })
    }
}

#[derive(sqlx::FromRow)]
struct PermissionRow {
    id: i64,
    code: String,
    description: String,
}

impl PermissionRow {
    fn into_permission(self) -> Result<Permission> {
        Ok(Permission {
            id: PermissionId(self.id),
            code: PermissionCode::parse(&self.code).map_err(AuthError::internal)?,
            description: self.description,
        })
    }
}

pub struct PgRoleRepository {
    pool: PgPool,
}

impl PgRoleRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoleRepository for PgRoleRepository {
    #[instrument(skip(self), err)]
    async fn find_by_id(&self, id: RoleId) -> Result<Option<Role>> {
        let row: Option<RoleRow> =
            sqlx::query_as("select id, code, name, scope from roles where id = $1")
                .bind(id.0)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
        row.map(RoleRow::into_role).transpose()
    }

    #[instrument(skip(self), err)]
    async fn list(&self, req: &PageRequest) -> Result<Page<Role>> {
        let pattern = req.search.as_ref().map(|s| format!("%{s}%"));
        let rows: Vec<(i64, String, String, String, i64)> = sqlx::query_as(
            r#"
            select id, code, name, scope, count(*) over() as total_count
            from roles
            where ($1::text is null or code ilike $1 or name ilike $1)
            order by id
            limit $2 offset $3
            "#,
        )
        .bind(&pattern)
        .bind(req.per_page)
        .bind(req.offset())
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        let total = rows.first().map(|r| r.4).unwrap_or(0);
        let items = rows
            .into_iter()
            .map(|(id, code, name, scope, _)| {
                RoleRow {
                    id,
                    code,
                    name,
                    scope,
                }
                .into_role()
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Page::new(items, req, total))
    }

    #[instrument(skip_all, err)]
    async fn create(&self, new: &NewRole) -> Result<Role> {
        let row: RoleRow = sqlx::query_as(
            r#"
            insert into roles (code, name, scope)
            values ($1, $2, $3)
            returning id, code, name, scope
            "#,
        )
        .bind(new.code.as_str())
        .bind(&new.name)
        .bind(new.scope.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(map_db_error)?;
        row.into_role()
    }

    /// `scope` роли этим методом сознательно не меняется — только `code` и `name`.
    #[instrument(skip(self), err)]
    async fn update(&self, id: RoleId, upd: &RoleUpdate) -> Result<Role> {
        let row: Option<RoleRow> = sqlx::query_as(
            r#"
            update roles set code = $1, name = $2
            where id = $3
            returning id, code, name, scope
            "#,
        )
        .bind(upd.code.as_str())
        .bind(&upd.name)
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;
        row.ok_or(AuthError::NotFound)?.into_role()
    }

    #[instrument(skip(self), err)]
    async fn delete(&self, id: RoleId) -> Result<()> {
        // role_permissions и user_roles удаляются каскадом
        let result = sqlx::query("delete from roles where id = $1")
            .bind(id.0)
            .execute(&self.pool)
            .await
            .map_err(map_db_error)?;
        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn permissions_of(&self, role: RoleId) -> Result<Vec<Permission>> {
        let rows: Vec<PermissionRow> = sqlx::query_as(
            r#"
            select p.id, p.code, p.description
            from role_permissions rp
            join permissions p on p.id = rp.permission_id
            where rp.role_id = $1
            order by p.code
            "#,
        )
        .bind(role.0)
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;
        rows.into_iter()
            .map(PermissionRow::into_permission)
            .collect()
    }

    #[instrument(skip(self), err)]
    async fn set_permissions(
        &self,
        role: RoleId,
        permission_ids: &[PermissionId],
    ) -> Result<Vec<Permission>> {
        let role_exists: bool =
            sqlx::query_scalar("select exists(select 1 from roles where id = $1)")
                .bind(role.0)
                .fetch_one(&self.pool)
                .await
                .map_err(map_db_error)?;
        if !role_exists {
            return Err(AuthError::NotFound);
        }

        let mut tx = self.pool.begin().await.map_err(map_db_error)?;
        sqlx::query("delete from role_permissions where role_id = $1")
            .bind(role.0)
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

        if !permission_ids.is_empty() {
            let ids: Vec<i64> = permission_ids.iter().map(|p| p.0).collect();
            // неизвестный id -> нарушение FK (23503) -> map_db_error даёт Validation,
            // как и требует контракт порта
            sqlx::query(
                "insert into role_permissions (role_id, permission_id) select $1, unnest($2::bigint[])",
            )
            .bind(role.0)
            .bind(&ids)
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;
        }
        tx.commit().await.map_err(map_db_error)?;

        let rows: Vec<PermissionRow> = sqlx::query_as(
            r#"
            select p.id, p.code, p.description
            from role_permissions rp
            join permissions p on p.id = rp.permission_id
            where rp.role_id = $1
            order by p.code
            "#,
        )
        .bind(role.0)
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;
        rows.into_iter()
            .map(PermissionRow::into_permission)
            .collect()
    }
}
