use async_trait::async_trait;
use auth_core::{Result, domain::RuntimeSettings, ports::SettingsRepository};
use sqlx::PgPool;
use tracing::instrument;

use crate::error::map_db_error;

pub struct PgSettingsRepository {
    pool: PgPool,
}

impl PgSettingsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SettingsRepository for PgSettingsRepository {
    #[instrument(skip(self), err)]
    async fn get(&self) -> Result<RuntimeSettings> {
        let allow: bool =
            sqlx::query_scalar("select allow_self_registration from app_settings where id = 1")
                .fetch_one(&self.pool)
                .await
                .map_err(map_db_error)?;
        Ok(RuntimeSettings {
            allow_self_registration: allow,
        })
    }

    #[instrument(skip(self), err)]
    async fn set_allow_self_registration(&self, allowed: bool) -> Result<()> {
        sqlx::query("update app_settings set allow_self_registration = $1 where id = 1")
            .bind(allowed)
            .execute(&self.pool)
            .await
            .map_err(map_db_error)?;
        Ok(())
    }
}
