use auth_core::{
    domain::{Permission, Role, RoleAssignment, Session},
    ports::Page,
    service::{TokenPair, UserWithRoles},
};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct RoleAssignmentDto {
    pub role_id: i64,
    pub role_code: String,
    pub role_name: String,
    pub scope: Option<String>,
}

impl From<RoleAssignment> for RoleAssignmentDto {
    fn from(a: RoleAssignment) -> Self {
        Self {
            role_id: a.role.id.0,
            role_code: a.role.code.as_str().to_owned(),
            role_name: a.role.name,
            scope: a.scope.map(|s| s.as_str().to_owned()),
        }
    }
}

#[derive(Serialize)]
pub struct UserDto {
    pub id: i64,
    pub email: String,
    pub first_name: String,
    pub second_name: String,
    pub is_active: bool,
    pub roles: Vec<RoleAssignmentDto>,
}

impl From<UserWithRoles> for UserDto {
    fn from(u: UserWithRoles) -> Self {
        Self {
            id: u.user.id.0,
            email: u.user.email.as_str().to_owned(),
            first_name: u.user.first_name,
            second_name: u.user.second_name,
            is_active: u.user.is_active,
            roles: u.roles.into_iter().map(Into::into).collect(),
        }
    }
}

#[derive(Serialize)]
pub struct RoleDto {
    pub id: i64,
    pub code: String,
    pub name: String,
    pub scope: String,
}

impl From<Role> for RoleDto {
    fn from(r: Role) -> Self {
        Self {
            id: r.id.0,
            code: r.code.as_str().to_owned(),
            name: r.name,
            scope: r.scope.as_str().to_owned(),
        }
    }
}

#[derive(Serialize)]
pub struct PermissionDto {
    pub id: i64,
    pub code: String,
    pub description: String,
}

impl From<Permission> for PermissionDto {
    fn from(p: Permission) -> Self {
        Self {
            id: p.id.0,
            code: p.code.as_str().to_owned(),
            description: p.description,
        }
    }
}

#[derive(Serialize)]
pub struct SessionDto {
    pub id: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

impl From<Session> for SessionDto {
    fn from(s: Session) -> Self {
        Self {
            id: s.id.0,
            created_at: s.created_at,
            expires_at: s.expires_at,
        }
    }
}

#[derive(Serialize)]
pub struct PageDto<T> {
    pub items: Vec<T>,
    pub page: i64,
    pub per_page: i64,
    pub total: i64,
    pub total_pages: i64,
}

impl<T, U: From<T>> From<Page<T>> for PageDto<U> {
    fn from(p: Page<T>) -> Self {
        let total_pages = p.total_pages();
        Self {
            items: p.items.into_iter().map(Into::into).collect(),
            page: p.page,
            per_page: p.per_page,
            total: p.total,
            total_pages,
        }
    }
}

/// `expose_secret()` здесь единственный оправданный вызов во всём auth-api:
/// токен уходит клиенту ровно один раз, в теле HTTP-ответа.
#[derive(Serialize)]
pub struct TokenPairDto {
    pub access_token: String,
    pub access_expires_at: chrono::DateTime<chrono::Utc>,
    pub refresh_token: String,
    pub refresh_expires_at: chrono::DateTime<chrono::Utc>,
}

impl From<TokenPair> for TokenPairDto {
    fn from(t: TokenPair) -> Self {
        Self {
            access_token: t.access_token.expose_secret().to_owned(),
            access_expires_at: t.access_expires_at,
            refresh_token: t.refresh_token.expose_secret().to_owned(),
            refresh_expires_at: t.refresh_expires_at,
        }
    }
}

#[derive(Deserialize)]
pub struct PageQuery {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
    pub search: Option<String>,
}
