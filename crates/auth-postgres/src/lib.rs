//! auth-postgres — адаптер хранения: реализации портов auth-core на sqlx/Postgres.

mod assignments;
mod error;
mod permissions;
mod pool;
mod roles;
mod sessions;
mod settings;
mod users;

pub use assignments::PgAssignmentRepository;
pub use permissions::PgPermissionRepository;
pub use pool::{PostgresConfig, connect, migrate};
pub use roles::PgRoleRepository;
pub use sessions::PgSessionRepository;
pub use settings::PgSettingsRepository;
pub use users::PgUserRepository;
