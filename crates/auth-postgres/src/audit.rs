use std::collections::BTreeMap;

use async_trait::async_trait;
use auth_core::{
    AuthError, Result,
    domain::{ScopeId, UserId},
    ports::{AuditEvent, AuditFilter, AuditRecord, AuditRepository, Page, PageRequest, Tx},
};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::instrument;

use crate::{error::map_db_error, tx::PgTx};

pub struct PgAuditRepository {
    pool: PgPool,
}

impl PgAuditRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

/// Детали хранятся как `jsonb`-объект строк. Пишем через `jsonb_object(keys, values)`,
/// читаем обратно двумя массивами — так обходимся без serde_json в адаптере.
type AuditRow = (
    i64,
    DateTime<Utc>,
    Option<i64>,
    String,
    String,
    Option<i64>,
    Option<String>,
    Vec<String>,
    Vec<String>,
);

fn into_record(row: AuditRow) -> Result<AuditRecord> {
    let (id, at, actor, action, target_type, target_id, scope, keys, values) = row;
    Ok(AuditRecord {
        id,
        at,
        actor: actor.map(UserId),
        action,
        target_type,
        target_id,
        scope: scope
            .map(|s| ScopeId::parse(&s))
            .transpose()
            .map_err(AuthError::internal)?,
        details: keys.into_iter().zip(values).collect::<BTreeMap<_, _>>(),
    })
}

#[async_trait]
impl AuditRepository for PgAuditRepository {
    #[instrument(skip(self, tx), err)]
    async fn record(&self, tx: &mut dyn Tx, event: &AuditEvent) -> Result<()> {
        let conn = PgTx::from_dyn(tx)?.conn();
        let keys: Vec<&str> = event.details.keys().map(String::as_str).collect();
        let values: Vec<&str> = event.details.values().map(String::as_str).collect();
        sqlx::query(
            r#"
            insert into audit_events (actor_id, action, target_type, target_id, scope, details)
            values ($1, $2, $3, $4, $5, jsonb_object($6::text[], $7::text[]))
            "#,
        )
        .bind(event.actor.map(|a| a.0))
        .bind(event.action)
        .bind(event.target_type)
        .bind(event.target_id)
        .bind(event.scope.as_ref().map(ScopeId::as_str))
        .bind(&keys)
        .bind(&values)
        .execute(conn)
        .await
        .map_err(map_db_error)?;
        Ok(())
    }

    #[instrument(skip(self), err)]
    async fn list(&self, filter: &AuditFilter, req: &PageRequest) -> Result<Page<AuditRecord>> {
        // `$n is null or ...` — пустой фильтр не ограничивает выборку. Макрос, а не
        // `format!`: склейка через `concat!` остаётся `&'static str`, sqlx её принимает.
        macro_rules! audit_where {
            () => {
                r#"
                where ($1::bigint is null or actor_id = $1)
                  and ($2::text is null or action = $2)
                  and ($3::text is null or target_type = $3)
                  and ($4::bigint is null or target_id = $4)
                "#
            };
        }

        let total: i64 =
            sqlx::query_scalar(concat!("select count(*) from audit_events", audit_where!()))
                .bind(filter.actor.map(|a| a.0))
                .bind(filter.action.as_deref())
                .bind(filter.target_type.as_deref())
                .bind(filter.target_id)
                .fetch_one(&self.pool)
                .await
                .map_err(map_db_error)?;

        let rows: Vec<AuditRow> = sqlx::query_as(concat!(
            r#"
            select id, at, actor_id, action, target_type, target_id, scope,
                   coalesce((select array_agg(key order by key) from jsonb_each_text(details)), '{}'),
                   coalesce((select array_agg(value order by key) from jsonb_each_text(details)), '{}')
            from audit_events
            "#,
            audit_where!(),
            "order by at desc, id desc limit $5 offset $6"
        ))
        .bind(filter.actor.map(|a| a.0))
        .bind(filter.action.as_deref())
        .bind(filter.target_type.as_deref())
        .bind(filter.target_id)
        .bind(req.per_page)
        .bind(req.offset())
        .fetch_all(&self.pool)
        .await
        .map_err(map_db_error)?;

        let items = rows.into_iter().map(into_record).collect::<Result<_>>()?;
        Ok(Page::new(items, req, total))
    }
}
