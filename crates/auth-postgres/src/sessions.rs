use async_trait::async_trait;
use auth_core::{
    AuthError, Result,
    domain::{Session, SessionId, TokenHash, UserId},
    ports::{NewSession, SessionRepository},
};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::instrument;

use crate::error::map_db_error;

#[derive(sqlx::FromRow)]
struct SessionRow {
    id: i64,
    user_id: i64,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
}

impl From<SessionRow> for Session {
    fn from(r: SessionRow) -> Self {
        Session {
            id: SessionId(r.id),
            user_id: UserId(r.user_id),
            created_at: r.created_at,
            expires_at: r.expires_at,
            revoked_at: r.revoked_at,
        }
    }
}

pub struct PgSessionRepository {
    pool: PgPool,
}

impl PgSessionRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for PgSessionRepository {
    #[instrument(skip_all, err)]
    async fn create(&self, new: &NewSession) -> Result<Session> {
        let row: SessionRow = sqlx::query_as(
            r#"
            insert into sessions (user_id, token_hash, created_at, expires_at)
            values ($1, $2, $3, $4)
            returning id, user_id, created_at, expires_at, revoked_at
            "#,
        )
        .bind(new.user_id.0)
        .bind(new.token_hash.as_str())
        .bind(new.created_at)
        .bind(new.expires_at)
        .fetch_one(&self.pool)
        .await
        .map_err(map_db_error)?;
        Ok(row.into())
    }

    #[instrument(skip(self), err)]
    async fn find_by_id(&self, id: SessionId) -> Result<Option<Session>> {
        let row: Option<SessionRow> = sqlx::query_as(
            "select id, user_id, created_at, expires_at, revoked_at from sessions where id = $1",
        )
        .bind(id.0)
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;
        Ok(row.map(Into::into))
    }

    #[instrument(skip_all, err)]
    async fn find_by_token_hash(&self, hash: &TokenHash) -> Result<Option<Session>> {
        let row: Option<SessionRow> = sqlx::query_as(
            "select id, user_id, created_at, expires_at, revoked_at from sessions where token_hash = $1"
        )
        .bind(hash.as_str())
        .fetch_optional(&self.pool)
        .await
        .map_err(map_db_error)?;
        Ok(row.map(Into::into))
    }

    #[instrument(skip(self), err)]
    async fn list_active(&self, user: UserId, now: DateTime<Utc>) -> Result<Vec<Session>> {
        let rows: Vec<SessionRow> = sqlx::query_as(
            r#"
            select id, user_id, created_at, expires_at, revoked_at from sessions
            where user_id = $1 and revoked_at is null and expires_at > $2
            order by created_at desc
            "#,
        )
        .bind(user.0)
        .bind(now)
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }

    /// `SELECT ... FOR UPDATE` внутри транзакции: параллельный refresh тем же токеном
    /// дождётся этой блокировки и увидит уже выставленный `revoked_at`, получив `Conflict` —
    /// без гонки, при которой оба запроса выдали бы валидную пару токенов.
    #[instrument(skip(self, next), err)]
    async fn rotate(
        &self,
        old: SessionId,
        next: &NewSession,
        now: DateTime<Utc>,
    ) -> Result<Session> {
        let mut tx = self.pool.begin().await.map_err(map_db_error)?;

        let old_row: Option<SessionRow> = sqlx::query_as(
            "select id, user_id, created_at, expires_at, revoked_at from sessions where id = $1 for update"
        )
        .bind(old.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(map_db_error)?;
        let old_row = old_row.ok_or(AuthError::NotFound)?;
        if old_row.revoked_at.is_some() {
            return Err(AuthError::Conflict);
        }

        sqlx::query("update sessions set revoked_at = $1 where id = $2")
            .bind(now)
            .bind(old.0)
            .execute(&mut *tx)
            .await
            .map_err(map_db_error)?;

        let new_row: SessionRow = sqlx::query_as(
            r#"
            insert into sessions (user_id, token_hash, created_at, expires_at)
            values ($1, $2, $3, $4)
            returning id, user_id, created_at, expires_at, revoked_at
            "#,
        )
        .bind(next.user_id.0)
        .bind(next.token_hash.as_str())
        .bind(next.created_at)
        .bind(next.expires_at)
        .fetch_one(&mut *tx)
        .await
        .map_err(map_db_error)?;

        tx.commit().await.map_err(map_db_error)?;
        Ok(new_row.into())
    }

    #[instrument(skip(self), err)]
    async fn revoke(&self, user: UserId, session: SessionId, now: DateTime<Utc>) -> Result<()> {
        let result = sqlx::query(
            "update sessions set revoked_at = $1 where id = $2 and user_id = $3 and revoked_at is null",
        )
        .bind(now)
        .bind(session.0)
        .bind(user.0)
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;
        if result.rows_affected() == 0 {
            // отличаем "нет такой сессии/чужая" от "уже отозвана" отдельным select —
            // порт требует NotFound именно для первого случая, а повторный revoke идемпотентен
            let exists: bool = sqlx::query_scalar(
                "select exists(select 1 from sessions where id = $1 and user_id = $2)",
            )
            .bind(session.0)
            .bind(user.0)
            .fetch_one(&self.pool)
            .await
            .map_err(map_db_error)?;
            if !exists {
                return Err(AuthError::NotFound);
            }
        }
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn revoke_all_for_user(&self, user: UserId, now: DateTime<Utc>) -> Result<u64> {
        let result = sqlx::query(
            "update sessions set revoked_at = $1 where user_id = $2 and revoked_at is null",
        )
        .bind(now)
        .bind(user.0)
        .execute(&self.pool)
        .await
        .map_err(map_db_error)?;
        Ok(result.rows_affected())
    }
}
