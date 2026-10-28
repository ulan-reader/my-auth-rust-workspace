use async_trait::async_trait;
use auth_core::{
    AuthError, Result,
    domain::{Email, PasswordHash, User, UserId},
    ports::{NewUser, Page, PageRequest, Tx, UserCredentials, UserRepository, UserUpdate},
};
use sqlx::PgPool;
use tracing::instrument;

use crate::{admin_guard, error::map_db_error, tx::PgTx};

#[derive(sqlx::FromRow)]
pub(crate) struct UserRow {
    pub(crate) id: i64,
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
    pub(crate) fn into_user(self) -> Result<User> {
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

        let total: i64 = sqlx::query_scalar(
            r#"
            select count(*)
            from users
            where (
                $1::text is null
                or email ilike $1
                or first_name ilike $1
                or second_name ilike $1
            )
            "#,
        )
        .bind(&pattern)
        .fetch_one(&self.pool)
        .await
        .map_err(map_db_error)?;

        let rows: Vec<UserRow> = sqlx::query_as(
            r#"
            select id, email, password_hash, first_name, second_name, is_active
            from users
            where (
                $1::text is null
                or email ilike $1
                or first_name ilike $1
                or second_name ilike $1
            )
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

        let items = rows
            .into_iter()
            .map(UserRow::into_user)
            .collect::<Result<Vec<_>>>()?;

        Ok(Page::new(items, req, total))
    }

    #[instrument(skip_all, err)]
    async fn create(&self, tx: &mut dyn Tx, new: &NewUser) -> Result<User> {
        let conn = PgTx::from_dyn(tx)?.conn();
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
        .fetch_one(conn)
        .await
        .map_err(map_db_error)?;
        row.into_user()
    }

    #[instrument(skip(self, tx), err)]
    async fn update(&self, tx: &mut dyn Tx, id: UserId, upd: &UserUpdate) -> Result<User> {
        let conn = PgTx::from_dyn(tx)?.conn();
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
        .fetch_optional(conn)
        .await
        .map_err(map_db_error)?;
        row.ok_or(AuthError::NotFound)?.into_user()
    }

    #[instrument(skip(self, tx), err)]
    async fn set_password_hash(
        &self,
        tx: &mut dyn Tx,
        id: UserId,
        hash: &PasswordHash,
    ) -> Result<()> {
        let conn = PgTx::from_dyn(tx)?.conn();
        let result = sqlx::query("update users set password_hash = $1 where id = $2")
            .bind(hash.as_str())
            .bind(id.0)
            .execute(conn)
            .await
            .map_err(map_db_error)?;
        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    #[instrument(skip(self, tx), err)]
    async fn set_active(&self, tx: &mut dyn Tx, id: UserId, active: bool) -> Result<()> {
        let conn = PgTx::from_dyn(tx)?.conn();
        let before = admin_guard::lock(conn).await?;

        let result = sqlx::query("update users set is_active = $1 where id = $2")
            .bind(active)
            .bind(id.0)
            .execute(&mut *conn)
            .await
            .map_err(map_db_error)?;
        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }

        admin_guard::ensure_remains(conn, before).await
    }

    #[instrument(skip(self, tx), err)]
    async fn delete(&self, tx: &mut dyn Tx, id: UserId) -> Result<()> {
        let conn = PgTx::from_dyn(tx)?.conn();
        let before = admin_guard::lock(conn).await?;

        // user_roles и sessions удаляются каскадом (ON DELETE CASCADE в миграции)
        let result = sqlx::query("delete from users where id = $1")
            .bind(id.0)
            .execute(&mut *conn)
            .await
            .map_err(map_db_error)?;
        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }

        admin_guard::ensure_remains(conn, before).await
    }
}
