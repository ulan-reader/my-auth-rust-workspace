use auth_core::{
    domain::UserId,
    service::{CreateUser, UpdateUser},
};
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    routing::{get, patch, post},
};
use secrecy::SecretString;
use serde::Deserialize;

use crate::{
    ApiState,
    dto::{PageDto, PageQuery, UserDto},
    error::ApiError,
    extract::AuthCtx,
};

async fn list(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Query(q): Query<PageQuery>,
) -> Result<Json<PageDto<UserDto>>, ApiError> {
    let req = auth_core::ports::PageRequest::new(q.page, q.per_page, q.search);
    let page = state.users.list(&ctx, &req).await?;
    Ok(Json(page.into()))
}

async fn get_one(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Path(id): Path<i64>,
) -> Result<Json<UserDto>, ApiError> {
    let user = state.users.get(&ctx, UserId(id)).await?;
    Ok(Json(user.into()))
}

#[derive(Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub password: SecretString,
    pub first_name: String,
    pub second_name: String,
}

async fn create(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<UserDto>, ApiError> {
    let user = state
        .users
        .create(
            &ctx,
            CreateUser {
                email: req.email,
                password: req.password,
                first_name: req.first_name,
                second_name: req.second_name,
            },
        )
        .await?;
    Ok(Json(user.into()))
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub email: String,
    pub first_name: String,
    pub second_name: String,
}

async fn update(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Path(id): Path<i64>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserDto>, ApiError> {
    let upd = UpdateUser {
        email: req.email,
        first_name: req.first_name,
        second_name: req.second_name,
    };
    let user = state.users.update(&ctx, UserId(id), &upd).await?;
    Ok(Json(user.into()))
}

#[derive(Deserialize)]
pub struct SetPasswordRequest {
    pub password: SecretString,
}

async fn set_password(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Path(id): Path<i64>,
    Json(req): Json<SetPasswordRequest>,
) -> Result<(), ApiError> {
    state
        .users
        .set_password(&ctx, UserId(id), &req.password)
        .await?;
    Ok(())
}

#[derive(Deserialize)]
pub struct SetActiveRequest {
    pub is_active: bool,
}

async fn set_active(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Path(id): Path<i64>,
    Json(req): Json<SetActiveRequest>,
) -> Result<(), ApiError> {
    state
        .users
        .set_active(&ctx, UserId(id), req.is_active)
        .await?;
    Ok(())
}

async fn delete(
    State(state): State<ApiState>,
    AuthCtx(ctx): AuthCtx,
    Path(id): Path<i64>,
) -> Result<(), ApiError> {
    state.users.delete(&ctx, UserId(id)).await?;
    Ok(())
}

pub fn router() -> Router<ApiState> {
    Router::new()
        .route("/", get(list).post(create))
        .route("/{id}", get(get_one).put(update).delete(delete))
        .route("/{id}/password", post(set_password))
        .route("/{id}/active", patch(set_active))
}
