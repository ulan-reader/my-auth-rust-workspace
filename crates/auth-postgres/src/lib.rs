//! auth-postgres — адаптер хранения: реализации портов auth-core на sqlx/Postgres.

mod admin_guard;
mod assignments;
mod audit;
mod error;
mod permissions;
mod pool;
mod roles;
mod sessions;
mod settings;
mod setup;
mod tx;
mod users;

pub use assignments::PgAssignmentRepository;
pub use audit::PgAuditRepository;
pub use permissions::PgPermissionRepository;
pub use pool::{PostgresConfig, connect, migrate, ping};
pub use roles::PgRoleRepository;
pub use sessions::PgSessionRepository;
pub use settings::PgSettingsRepository;
pub use setup::PgSetupRepository;
/// Реэкспорт, чтобы `auth-server` не тащил `sqlx` явной зависимостью только
/// для аннотации типа (например, в сигнатуре health-check функции).
pub use sqlx::PgPool;
pub use tx::PgUnitOfWork;
pub use users::PgUserRepository;
