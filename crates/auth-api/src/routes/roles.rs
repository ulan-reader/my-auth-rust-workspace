use auth_core::{
    AuthError,
    domain::{PermissionId, RoleId, RoleScope, UserId},
    service::{AssignRole, CreateRole, UpdateRole, admin_permissions as perm},
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, post},
};
use serde::Deserialize;

use crate::{
    ApiState,
    dto::{PageDto, PageQuery, PermissionDto, RoleDto},
    error::ApiError,
    extract::AuthCtx,
};

async fn list(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Json<PageDto<RoleDto>>, ApiError> {
    let req = auth_core::ports::PageRequest::new(q.page, q.per_page, q.search);
    let page = state.roles.list(&ctx, &req).await?;
    Ok(Json(page.into()))
}

async fn get_one(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Path(id): Path<i64>,
) -> Result<Json<RoleDto>, ApiError> {
    Ok(Json(state.roles.get(&ctx, RoleId(id)).await?.into()))
}

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    pub code: String,
    pub name: String,
    /// "global" | "scoped"
    pub scope: String,
}

async fn create(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Json(req): Json<CreateRoleRequest>,
) -> Result<Json<RoleDto>, ApiError> {
    let scope: RoleScope = req.scope.parse().map_err(|e: AuthError| ApiError(e))?;
    let role = state
        .roles
        .create(
            &ctx,
            CreateRole {
                code: req.code,
                name: req.name,
                scope,
            },
        )
        .await?;
    Ok(Json(role.into()))
}

#[derive(Deserialize)]
pub struct UpdateRoleRequest {
    pub code: String,
    pub name: String,
}

async fn update(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Path(id): Path<i64>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<Json<RoleDto>, ApiError> {
    let upd = UpdateRole {
        code: req.code,
        name: req.name,
    };
    Ok(Json(
        state.roles.update(&ctx, RoleId(id), &upd).await?.into(),
    ))
}

async fn delete_role(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Path(id): Path<i64>,
) -> Result<(), ApiError> {
    state.roles.delete(&ctx, RoleId(id)).await?;
    Ok(())
}

async fn get_permissions(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Path(id): Path<i64>,
) -> Result<Json<Vec<PermissionDto>>, ApiError> {
    let perms = state.roles.permissions_of(&ctx, RoleId(id)).await?;
    Ok(Json(perms.into_iter().map(Into::into).collect()))
}

#[derive(Deserialize)]
pub struct SetPermissionsRequest {
    pub permission_ids: Vec<i64>,
}

async fn set_permissions(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Path(id): Path<i64>,
    Json(req): Json<SetPermissionsRequest>,
) -> Result<Json<Vec<PermissionDto>>, ApiError> {
    let ids: Vec<PermissionId> = req.permission_ids.into_iter().map(PermissionId).collect();
    let perms = state.roles.set_permissions(&ctx, RoleId(id), &ids).await?;
    Ok(Json(perms.into_iter().map(Into::into).collect()))
}

#[derive(Deserialize)]
pub struct ScopeQuery {
    pub scope: Option<String>,
}

async fn assign(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Path((user_id, role_id)): Path<(i64, i64)>,
    Query(q): Query<ScopeQuery>,
) -> Result<(), ApiError> {
    state
        .roles
        .assign(
            &ctx,
            AssignRole {
                user: UserId(user_id),
                role: RoleId(role_id),
                scope: q.scope,
            },
        )
        .await?;
    Ok(())
}

async fn unassign(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Path((user_id, role_id)): Path<(i64, i64)>,
    Query(q): Query<ScopeQuery>,
) -> Result<(), ApiError> {
    state
        .roles
        .unassign(
            &ctx,
            AssignRole {
                user: UserId(user_id),
                role: RoleId(role_id),
                scope: q.scope,
            },
        )
        .await?;
    Ok(())
}

/// Единственное место в auth-api, где хендлер напрямую держит порт (а не сервис) —
/// в auth-core нет отдельного use-case на "просто отдать список всех permissions".
async fn list_all_permissions(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
) -> Result<Json<Vec<PermissionDto>>, ApiError> {
    state
        .access
        .require_permission(&ctx, perm::PERMISSIONS_VIEW, None)
        .await?;
    let perms = state.permissions.list().await?;
    Ok(Json(perms.into_iter().map(Into::into).collect()))
}

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/{id}", get(get_one).put(update).delete(delete_role))
        .route(
            "/{id}/permissions",
            get(get_permissions).put(set_permissions),
        )
        .route("/{user_id}/{role_id}", post(assign).delete(unassign))
}

pub fn permissions_router() -> Router<ApiState> {
    Router::new().route("/", get(list_all_permissions))
}
