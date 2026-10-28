use std::any::Any;

use async_trait::async_trait;
use sqlx::{Postgres, Transaction};

use crate::error::map_db_error;
use auth_core::{
    AuthError, Result,
    ports::{Tx, UnitOfWork},
};

pub struct PgTx {
    transaction: Transaction<'static, Postgres>,
}

impl PgTx {
    pub fn new(transaction: Transaction<'static, Postgres>) -> Self {
        Self { transaction }
    }

    pub(crate) fn from_dyn(tx: &mut dyn Tx) -> Result<&mut PgTx> {
        tx.as_any_mut()
            .downcast_mut::<PgTx>()
            .ok_or_else(|| AuthError::internal(ForeignTx))
    }

    /// Соединение внутри транзакции: его принимают sqlx-запросы.
    pub(crate) fn conn(&mut self) -> &mut sqlx::PgConnection {
        &mut self.transaction
    }
}

#[async_trait]
impl Tx for PgTx {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    async fn commit(self: Box<Self>) -> Result<()> {
        let PgTx { transaction } = *self;

        transaction.commit().await.map_err(map_db_error)?;

        Ok(())
    }
}

#[derive(Debug)]
struct ForeignTx;

impl std::fmt::Display for ForeignTx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("транзакция создана не адаптером auth-postgres")
    }
}

impl std::error::Error for ForeignTx {}

use sqlx::PgPool;

#[derive(Clone)]
pub struct PgUnitOfWork {
    pool: PgPool,
}

impl PgUnitOfWork {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UnitOfWork for PgUnitOfWork {
    async fn begin(&self) -> Result<Box<dyn Tx>> {
        let transaction = self.pool.begin().await.map_err(map_db_error)?;

        Ok(Box::new(PgTx::new(transaction)))
    }
}
