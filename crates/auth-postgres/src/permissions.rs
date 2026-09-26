use std::collections::HashSet;

use async_trait::async_trait;
use auth_core::{
    AuthError,
    domain::{Permission, PermissionId},
};
use auth_core::{
    Result,
    domain::{PermissionCode, ScopeId, UserId},
    ports::PermissionRepository,
};
use sqlx::PgPool;
use tracing::instrument;

use crate::error::map_db_error;

pub struct PgPermissionRepository {
    pool: PgPool,
}

impl PgPermissionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PermissionRepository for PgPermissionRepository {
    #[instrument(skip(self), err)]
    async fn list(&self) -> Result<Vec<Permission>> {
        let rows: Vec<(i64, String, String)> =
            sqlx::query_as("select id, code, description from permissions order by code")
                .fetch_all(&self.pool)
                .await
                .map_err(map_db_error)?;
        rows.into_iter()
            .map(|(id, code, description)| {
                Ok(Permission {
                    id: PermissionId(id),
                    code: PermissionCode::parse(&code).map_err(AuthError::internal)?,
                    description,
                })
            })
            .collect()
    }

    /// Глобальные роли (`r.scope = 'global'`) действуют всегда. Роли с областью действия
    /// (`r.scope = 'scoped'`) — только если назначение (`ur.scope`) совпадает с запрошенным
    /// `scope`. `scope = None` биндится как SQL NULL: `ur.scope = NULL` никогда не истинно,
    /// поэтому в этом случае считаются только глобальные роли — ровно то, что требует контракт порта.
    #[instrument(skip(self), err)]
    async fn effective_for_user(
        &self,
        user: UserId,
        scope: Option<&ScopeId>,
    ) -> Result<HashSet<PermissionCode>> {
        let codes: Vec<String> = sqlx::query_scalar(
            r#"
            select distinct p.code
            from user_roles ur
            join roles r on r.id = ur.role_id
            join role_permissions rp on rp.role_id = r.id
            join permissions p on p.id = rp.permission_id
            where ur.user_id = $1
              and (r.scope = 'global' or ur.scope = $2)
            "#,
        )
        .bind(user.0)
        .bind(scope.map(ScopeId::as_str))
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        codes
            .into_iter()
            .map(|c| PermissionCode::parse(&c).map_err(AuthError::internal))
            .collect()
    }
}
