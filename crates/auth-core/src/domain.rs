use std::{fmt, str::FromStr};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{AuthError, Result};

// ============ ID-newtype'ы: RoleId нельзя случайно передать вместо UserId ============

macro_rules! id_type {
    ($name:ident) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub i64);

        impl From<i64> for $name {
            fn from(v: i64) -> Self {
                Self(v)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

id_type!(UserId);
id_type!(RoleId);
id_type!(PermissionId);
id_type!(SessionId);

// ============ Валидируемые строки: невалидное значение не существует ============

macro_rules! string_type {
    ($name:ident, $validator:path) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn parse(raw: &str) -> Result<Self> {
                $validator(raw).map(Self)
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = AuthError;

            fn try_from(v: String) -> Result<Self> {
                Self::parse(&v)
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

/// Trim + lowercase: `Klai@X.com` и `klai@x.com` — один и тот же пользователь.
/// Проверка намеренно простая; настоящая валидация адреса — это письмо на него.
fn validate_email(raw: &str) -> Result<String> {
    let s = raw.trim().to_lowercase();
    let valid = s.len() <= 254
        && !s.chars().any(char::is_whitespace)
        && s.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty()
                && !domain.contains('@')
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        });

    if valid {
        Ok(s)
    } else {
        Err(AuthError::validation("некорректный email"))
    }
}

/// Коды ролей и прав: `admin`, `users.manage`, `dept_head`.
fn validate_code(raw: &str) -> Result<String> {
    let s = raw.trim();
    let mut chars = s.chars();
    let valid = s.len() <= 64
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));

    if valid {
        Ok(s.to_owned())
    } else {
        Err(AuthError::validation(
            "код: a-z, 0-9, '.', '_', '-'; начинается с буквы; до 64 символов",
        ))
    }
}

/// Идентификатор области действия роли. Для auth он непрозрачный: что за ним
/// стоит (отдел, проект, пространство), знает только приложение-потребитель.
/// Регистр сохраняется. Рекомендуемая договорённость: `<тип>:<id>`,
/// например `department:17`.
fn validate_scope_id(raw: &str) -> Result<String> {
    let s = raw.trim();
    let valid = !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ':' | '.' | '_' | '-'));

    if valid {
        Ok(s.to_owned())
    } else {
        Err(AuthError::validation(
            "scope: a-z, A-Z, 0-9, ':', '.', '_', '-'; от 1 до 128 символов",
        ))
    }
}

string_type!(Email, validate_email);
string_type!(RoleCode, validate_code);
string_type!(PermissionCode, validate_code);
string_type!(ScopeId, validate_scope_id);

// ============ Хеши: в логи не попадают ============

/// Хеш пароля (PHC-строка). `Debug` содержимое не печатает.
#[derive(Clone, PartialEq, Eq)]
pub struct PasswordHash(String);

impl PasswordHash {
    pub fn new(phc: impl Into<String>) -> Self {
        Self(phc.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PasswordHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordHash(***)")
    }
}

/// Хеш refresh-токена: в БД лежит он, а не сам токен.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TokenHash(String);

impl TokenHash {
    pub fn new(hash: impl Into<String>) -> Self {
        Self(hash.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// ============ Тип роли ============
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoleScope {
    /// Действует во всей системе.
    Global,
    /// Действует только внутри конкретного scope (отдел, проект, пространство —
    /// что именно, решает приложение-потребитель).
    Scoped,
}

impl RoleScope {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Scoped => "scoped",
        }
    }

    /// Правило домена (бывший `match` из `assign_role`).
    pub fn check_assignment(self, scope: Option<&ScopeId>) -> Result<()> {
        match (self, scope) {
            (Self::Global, Some(_)) => Err(AuthError::validation(
                "у глобальной роли не может быть scope",
            )),
            (Self::Scoped, None) => Err(AuthError::validation(
                "для роли с областью действия обязателен scope",
            )),
            _ => Ok(()),
        }
    }
}

impl FromStr for RoleScope {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "global" => Ok(Self::Global),
            "scoped" => Ok(Self::Scoped),
            _ => Err(AuthError::validation("scope роли: 'global' или 'scoped'")),
        }
    }
}

// ============ Сущности ============
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    pub id: UserId,
    pub email: Email,
    pub first_name: String,
    pub second_name: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Role {
    pub id: RoleId,
    pub code: RoleCode,
    pub name: String,
    pub scope: RoleScope,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permission {
    pub id: PermissionId,
    pub code: PermissionCode,
    pub description: String,
}

/// Роль, назначенная пользователю. `scope` — `None` для глобальных ролей.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleAssignment {
    pub role: Role,
    pub scope: Option<ScopeId>,
}

/// Сессия = один refresh-токен (одно устройство).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub id: SessionId,
    pub user_id: UserId,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl Session {
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at > now
    }
}

/// То, что лежит в access-токене. Права сюда намеренно не кладём:
/// они читаются из БД на каждый запрос, и отзыв действует сразу.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessClaims {
    pub user_id: UserId,
    pub session_id: SessionId,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_is_trimmed_and_lowercased() {
        let e = Email::parse("  Klai@Example.COM  ").unwrap();
        assert_eq!(e.as_str(), "klai@example.com");
    }

    #[test]
    fn email_rejects_garbage() {
        for bad in [
            "",
            "no-at",
            "@x.com",
            "a@b",
            "a b@c.com",
            "a@@b.com",
            "a@.com",
            "a@b.",
        ] {
            assert!(Email::parse(bad).is_err(), "должен быть отклонён: {bad:?}");
        }
    }

    #[test]
    fn codes_accept_valid_and_reject_invalid() {
        for ok in ["admin", "users.manage", "dept_head", "a-1"] {
            assert!(RoleCode::parse(ok).is_ok(), "{ok}");
            assert!(PermissionCode::parse(ok).is_ok(), "{ok}");
        }

        let too_long = "a".repeat(65);
        for bad in ["", "Admin", "1abc", "a b", "a/b", too_long.as_str()] {
            assert!(RoleCode::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn scope_id_validation() {
        for ok in ["department:17", "space:main", "a", "X.y_z-1"] {
            assert!(ScopeId::parse(ok).is_ok(), "{ok}");
        }

        let too_long = "a".repeat(129);
        for bad in ["", " ", "a b", "dept/1", "отдел:1", too_long.as_str()] {
            assert!(ScopeId::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn role_scope_assignment_rules() {
        let s = ScopeId::parse("department:1").unwrap();
        assert!(RoleScope::Global.check_assignment(None).is_ok());
        assert!(RoleScope::Global.check_assignment(Some(&s)).is_err());
        assert!(RoleScope::Scoped.check_assignment(Some(&s)).is_ok());
        assert!(RoleScope::Scoped.check_assignment(None).is_err());
    }

    #[test]
    fn role_scope_roundtrip() {
        for s in [RoleScope::Global, RoleScope::Scoped] {
            assert_eq!(s.as_str().parse::<RoleScope>().unwrap(), s);
        }
        assert!("weird".parse::<RoleScope>().is_err());
    }

    #[test]
    fn password_hash_is_not_printed() {
        let dbg = format!("{:?}", PasswordHash::new("$argon2id$secret"));
        assert!(!dbg.contains("secret"));
    }

    #[test]
    fn session_activity() {
        let now = Utc::now();
        let mk = |secs: i64, revoked: bool| Session {
            id: SessionId(1),
            user_id: UserId(1),
            created_at: now,
            expires_at: now + chrono::TimeDelta::try_seconds(secs).unwrap(),
            revoked_at: revoked.then_some(now),
        };
        assert!(mk(60, false).is_active(now));
        assert!(!mk(-1, false).is_active(now));
        assert!(!mk(60, true).is_active(now));
    }
}
