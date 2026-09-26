use std::collections::HashMap;

use async_trait::async_trait;
use auth_core::{
    AuthError, Result,
    domain::{Role, RoleAssignment, RoleCode, RoleId, RoleScope, ScopeId, UserId},
    ports::AssignmentRepository,
};
use sqlx::PgPool;
use tracing::instrument;

use crate::error::map_db_error;

/// `''` <-> `None`: тот же сентинел, что в схеме — глобальное назначение хранится
/// с пустой строкой вместо NULL (см. миграцию 0001_init.sql).
fn scope_to_db(scope: Option<&ScopeId>) -> &str {
    scope.map(ScopeId::as_str).unwrap_or("")
}

fn scope_from_db(raw: &str) -> Result<Option<ScopeId>> {
    if raw.is_empty() {
        Ok(None)
    } else {
        ScopeId::parse(raw).map(Some).map_err(AuthError::internal)
    }
}

pub struct PgAssignmentRepository {
    pool: PgPool,
}

impl PgAssignmentRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AssignmentRepository for PgAssignmentRepository {
    #[instrument(skip(self), err)]
    async fn for_users(&self, users: &[UserId]) -> Result<HashMap<UserId, Vec<RoleAssignment>>> {
        if users.is_empty() {
            return Ok(HashMap::new());
        }
        let ids: Vec<i64> = users.iter().map(|u| u.0).collect();
        let rows: Vec<(i64, i64, String, String, String, String)> = sqlx::query_as(
            r#"
            select ur.user_id, r.id, r.code, r.name, r.scope, ur.scope
            from user_roles ur
            join roles r on r.id = ur.role_id
            where ur.user_id = any($1)
            order by r.code
            "#,
        )
        .bind(&ids)
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        let mut map: HashMap<UserId, Vec<RoleAssignment>> = HashMap::new();
        for (user_id, role_id, code, name, role_scope, assignment_scope) in rows {
            let role = Role {
                id: RoleId(role_id),
                code: RoleCode::parse(&code).map_err(AuthError::internal)?,
                name,
                scope: role_scope
                    .parse::<RoleScope>()
                    .map_err(AuthError::internal)?,
            };
            map.entry(UserId(user_id))
                .or_default()
                .push(RoleAssignment {
                    role,
                    scope: scope_from_db(&assignment_scope)?,
                });
        }
        Ok(map)
    }

    #[instrument(skip(self), err)]
    async fn assign(&self, user: UserId, role: RoleId, scope: Option<&ScopeId>) -> Result<()> {
        // конфликт по PRIMARY KEY (user_id, role_id, scope) -> 23505 -> Conflict
        sqlx::query("insert into user_roles (user_id, role_id, scope) values ($1, $2, $3)")
            .bind(user.0)
            .bind(role.0)
            .bind(scope_to_db(scope))
            .execute(&self.pool)
            .await
            .map_err(map_db_error)?;
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn unassign(&self, user: UserId, role: RoleId, scope: Option<&ScopeId>) -> Result<()> {
        sqlx::query("delete from user_roles where user_id = $1 and role_id = $2 and scope = $3")
            .bind(user.0)
            .bind(role.0)
            .bind(scope_to_db(scope))
            .execute(&self.pool)
            .await
            .map_err(map_db_error)?;
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn revoke_all_in_scope(&self, scope: &ScopeId) -> Result<u64> {
        let result = sqlx::query("delete from user_roles where scope = $1")
            .bind(scope.as_str())
            .execute(&self.pool)
            .await
            .map_err(map_db_error)?;
        Ok(result.rows_affected())
    }
}
