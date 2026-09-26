//! Use-case'ы: вся бизнес-логика. Зависят только от портов.

mod access;
mod auth;
mod roles;
mod users;

use std::sync::Arc;

use crate::ports::{
    AccessTokenCodec, AssignmentRepository, Clock, PasswordHasher, PermissionRepository,
    RefreshTokenProvider, RoleRepository, SessionRepository, UserRepository,
};

pub use access::{AccessService, admin_permissions};
pub use auth::{AuthContext, AuthPolicy, AuthService, LoginResult, TokenPair};
pub use roles::{AssignRole, CreateRole, RoleService, UpdateRole};
pub use users::{CreateUser, UpdateUser, UserService, UserWithRoles};

/// Все порты разом. Собирается один раз в composition root (auth-server)
/// и раздаётся сервисам через `Service::from_ports(&ports, ..)`.
#[derive(Clone)]
pub struct Ports {
    pub users: Arc<dyn UserRepository>,
    pub roles: Arc<dyn RoleRepository>,
    pub assignments: Arc<dyn AssignmentRepository>,
    pub permissions: Arc<dyn PermissionRepository>,
    pub sessions: Arc<dyn SessionRepository>,
    pub hasher: Arc<dyn PasswordHasher>,
    pub access_tokens: Arc<dyn AccessTokenCodec>,
    pub refresh_tokens: Arc<dyn RefreshTokenProvider>,
    pub clock: Arc<dyn Clock>,
}
