use async_trait::async_trait;
use auth_core::{
    AuthError, Result,
    domain::{Email, PasswordHash, User, UserId},
    ports::{NewUser, Page, PageRequest, UserCredentials, UserRepository, UserUpdate},
};
use sqlx::PgPool;
use tracing::instrument;

use crate::error::map_db_error;

#[derive(sqlx::FromRow)]
struct UserRow {
    id: i64,
    email: String,
    password_hash: String,
    first_name: String,
    second_name: String,
    is_active: bool,
}

impl UserRow {
    /// Данные из БД уже должны быть валидны (пишем их сами через `Email::parse`
    /// на входе), поэтому ошибка парсинга здесь — признак повреждения данных,
    /// а не пользовательская ошибка: `Internal`, не `Validation`.
    fn into_user(self) -> Result<User> {
        Ok(User {
            id: UserId(self.id),
            email: Email::parse(&self.email).map_err(AuthError::internal)?,
            first_name: self.first_name,
            second_name: self.second_name,
            is_active: self.is_active,
        })
    }
}

pub struct PgUserRepository {
    pool: PgPool,
}

impl PgUserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for PgUserRepository {
    #[instrument(skip(self), err)]
    async fn find_by_id(&self, id: UserId) -> Result<Option<User>> {
        let row: Option<UserRow> =
            sqlx::query_as("select id, email, password_hash, first_name, second_name, is_active from users where id = $1")
                .bind(id.0)
                .fetch_optional(&self.pool)
                .await
                .map_err(map_db_error)?;
        row.map(UserRow::into_user).transpose()
    }

    #[instrument(skip_all, err)]
    async fn find_credentials_by_email(&self, email: &Email) -> Result<Option<UserCredentials>> {
        let row: Option<UserRow> = sqlx::query_as(
            "select id, email, password_hash, first_name, second_name, is_active from users where email = $1"
        )
        .bind(email.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;
        let Some(row) = row else { return Ok(None) };
        let password_hash = PasswordHash::new(row.password_hash.clone());
        Ok(Some(UserCredentials {
            user: row.into_user()?,
            password_hash,
        }))
    }

    #[instrument(skip(self), err)]
    async fn list(&self, req: &PageRequest) -> Result<Page<User>> {
        let pattern = req.search.as_ref().map(|s| format!("%{s}%"));
        let rows: Vec<(i64, String, String, String, String, bool, i64)> = sqlx::query_as(
            r#"
            select id, email, password_hash, first_name, second_name, is_active,
                   count(*) over() as total_count
            from users
            where ($1::text is null or email ilike $1 or first_name ilike $1 or second_name ilike $1)
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

        let total = rows.first().map(|r| r.6).unwrap_or(0);
        let items = rows
            .into_iter()
            .map(
                |(id, email, password_hash, first_name, second_name, is_active, _)| {
                    UserRow {
                        id,
                        email,
                        password_hash,
                        first_name,
                        second_name,
                        is_active,
                    }
                    .into_user()
                },
            )
            .collect::<Result<Vec<_>>>()?;
        Ok(Page::new(items, req, total))
    }

    #[instrument(skip_all, err)]
    async fn create(&self, new: &NewUser) -> Result<User> {
        let row: UserRow = sqlx::query_as(
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
        .fetch_one(&self.pool)
        .await
        .map_err(map_db_error)?;
        row.into_user()
    }

    #[instrument(skip(self), err)]
    async fn update(&self, id: UserId, upd: &UserUpdate) -> Result<User> {
        let row: Option<UserRow> = sqlx::query_as(
            r#"
            update users set email = $1, first_name = $2, second_name = $3
            where id = $4
            returning id, email, password_hash, first_name, second_name, is_active
            "#,
        )
        .bind(upd.email.as_str())
        .bind(&upd.first_name)
        .bind(&upd.second_name)
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;
        row.ok_or(AuthError::NotFound)?.into_user()
    }

    #[instrument(skip(self), err)]
    async fn set_password_hash(&self, id: UserId, hash: &PasswordHash) -> Result<()> {
        let result = sqlx::query("update users set password_hash = $1 where id = $2")
            .bind(hash.as_str())
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
    async fn set_active(&self, id: UserId, active: bool) -> Result<()> {
        let result = sqlx::query("update users set is_active = $1 where id = $2")
            .bind(active)
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
    async fn delete(&self, id: UserId) -> Result<()> {
        // user_roles и sessions удаляются каскадом (ON DELETE CASCADE в миграции)
        let result = sqlx::query("delete from users where id = $1")
            .bind(id.0)
            .execute(&self.pool)
            .await
            .map_err(map_db_error)?;
        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }
}
