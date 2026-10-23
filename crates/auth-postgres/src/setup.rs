use async_trait::async_trait;
use auth_core::{
    AuthError, Result,
    domain::User,
    ports::{NewUser, SetupRepository},
};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::instrument;

use crate::{error::map_db_error, users::UserRow};

pub struct PgSetupRepository {
    pool: PgPool,
}

impl PgSetupRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SetupRepository for PgSetupRepository {
    #[instrument(skip(self), err)]
    async fn is_completed(&self) -> Result<bool> {
        sqlx::query_scalar("select setup_completed_at is not null from app_settings where id = 1")
            .fetch_one(&self.pool)
            .await
            .map_err(map_db_error)
    }

    #[instrument(skip_all, err)]
    async fn create_first_admin(&self, new: &NewUser, now: DateTime<Utc>) -> Result<User> {
        let mut tx = self.pool.begin().await.map_err(map_db_error)?;

        // FOR UPDATE: параллельный запрос ждёт здесь и после нашего commit
        // увидит заполненный setup_completed_at.
        let completed: bool = sqlx::query_scalar(
            "select setup_completed_at is not null from app_settings where id = 1 for update",
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_db_error)?;
        let admin_exists: bool = sqlx::query_scalar(
            r#"select exists(
                select 1 from user_roles ur join roles r on r.id = ur.role_id
                where r.code = 'admin')"#,
        )
        .fetch_one(&mut *tx)
        .await
        .map_err(map_db_error)?;
        if completed || admin_exists {
            return Err(AuthError::NotFound); // транзакция откатится на drop
        }

        // роль admin: создать или взять существующую, но только глобальную
        let role_id: Option<i64> = sqlx::query_scalar(
            r#"
            insert into roles (code, name, scope) values ('admin', 'Admin', 'global')
            on conflict (code) do update set code = excluded.code
                where roles.scope = 'global'
            returning id
            "#,
        )
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_db_error)?;
        let role_id = role_id
            .ok_or_else(|| AuthError::validation("роль admin существует, но не глобальная"))?;

        sqlx::query(
            "insert into role_permissions (role_id, permission_id) \
             select $1, id from permissions on conflict do nothing",
        )
        .bind(role_id)
        .execute(&mut *tx)
        .await
        .map_err(map_db_error)?;

        let user: UserRow = sqlx::query_as(
            r#"
            insert into users (email, password_hash, first_name, second_name)
            values ($1, $2, $3, $4)
            returning id, email, password_hash, first_name, second_name, is_active
            "#,
        )
        .bind(new.email.as_str())
        .bind(new.password_hash.as_str())
        .bind(&new.first_name)
        .bind(&new.second_name)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_db_error)?;

        sqlx::query("insert into user_roles (user_id, role_id, scope) values ($1, $2, '')")
            .bind(user.id)
            .bind(role_id)
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

        sqlx::query("update app_settings set setup_completed_at = $1 where id = 1")
            .bind(now)
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

        tx.commit().await.map_err(map_db_error)?;
        user.into_user()
    }
}
