use std::collections::BTreeMap;

use auth_core::{
    domain::UserId,
    ports::{AuditFilter, AuditRecord, PageRequest},
};
use axum::{
    Json, Router,
    extract::{Query, State},
    routing::get,
};
use serde::{Deserialize, Serialize};

use crate::{ApiState, dto::PageDto, error::ApiError, extract::AuthCtx};

#[derive(Serialize)]
pub struct AuditDto {
    pub id: i64,
    pub at: chrono::DateTime<chrono::Utc>,
    pub actor_id: Option<i64>,
    pub action: String,
    pub target_type: String,
    pub target_id: Option<i64>,
    pub scope: Option<String>,
    pub details: BTreeMap<String, String>,
}

impl From<AuditRecord> for AuditDto {
    fn from(r: AuditRecord) -> Self {
        Self {
            id: r.id,
            at: r.at,
            actor_id: r.actor.map(|a| a.0),
            action: r.action,
            target_type: r.target_type,
            target_id: r.target_id,
            scope: r.scope.map(|s| s.as_str().to_owned()),
            details: r.details,
        }
    }
}

#[derive(Deserialize)]
pub struct AuditQuery {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
    pub actor_id: Option<i64>,
    pub action: Option<String>,
    pub target_type: Option<String>,
    pub target_id: Option<i64>,
}

/// `GET /audit?actor_id=&action=&target_type=&target_id=&page=&per_page=` — новые сверху.
async fn list(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Query(q): Query<AuditQuery>,
) -> Result<Json<PageDto<AuditDto>>, ApiError> {
    let filter = AuditFilter {
        actor: q.actor_id.map(UserId),
        action: q.action,
        target_type: q.target_type,
        target_id: q.target_id,
    };
    let req = PageRequest::new(q.page, q.per_page, None);
    let page = state.audit.list(&ctx, &filter, &req).await?;
    Ok(Json(page.into()))
}

pub fn router() -> Router<ApiState> {
    Router::new().route("/", get(list))
}
