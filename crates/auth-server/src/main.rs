//! Composition root: читает конфиг, собирает адаптеры (postgres/crypto) за
//! портами core, строит ApiState, поднимает axum и слушает до Ctrl+C.
//! Подкоманда `bootstrap-admin` создаёт первого админа в обход проверки прав —
//! иначе создать первого пользователя некому (POST /users сам требует админа).

mod config;

use std::sync::Arc;

use anyhow::{Context, bail};
use auth_api::ApiState;
use auth_core::{
    AuthError,
    domain::{Email, RoleScope},
    ports::{NewRole, NewUser, PageRequest, PasswordHasher, RoleRepository, UserRepository},
    service::{Ports, admin_permissions as perm},
};
use auth_crypto::{Argon2PasswordHasher, JwtCodec, Sha256RefreshTokenProvider};
use auth_postgres::{
    PgAssignmentRepository, PgPermissionRepository, PgRoleRepository, PgSessionRepository,
    PgSettingsRepository, PgUserRepository,
};
use clap::{Parser, Subcommand};
use config::AppConfig;
use secrecy::SecretString;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Создать (или обновить права) первого администратора.
    BootstrapAdmin {
        #[arg(long)]
        email: String,
        #[arg(long)]
        password: String,
        #[arg(long, default_value = "Admin")]
        first_name: String,
        #[arg(long, default_value = "User")]
        second_name: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();

    let env = std::env::var("AUTH_ENV").unwrap_or_else(|_| "dev".into());
    let cfg: AppConfig = ::config::Config::builder()
        .add_source(::config::File::with_name("config/default").required(false))
        .add_source(::config::File::with_name(&format!("config/{env}")).required(false))
        .add_source(::config::Environment::with_prefix("AUTH").separator("__"))
        .build()
        .context("сборка конфига")?
        .try_deserialize()
        .context("разбор конфига (проверь AUTH__POSTGRES__URL и AUTH__CRYPTO__JWT__*)")?;

    let _telemetry = auth_telemetry::init(&cfg.telemetry).context("инициализация telemetry")?;

    let pool = auth_postgres::connect(&cfg.postgres)
        .await
        .context("подключение к postgres")?;
    auth_postgres::migrate(&pool).await.context("миграции")?;

    let users_repo = PgUserRepository::new(pool.clone());
    let roles_repo = PgRoleRepository::new(pool.clone());
    let hasher = Argon2PasswordHasher::new(&cfg.crypto.argon2).context("argon2")?;

    if let Some(Command::BootstrapAdmin {
        email,
        password,
        first_name,
        second_name,
    }) = cli.command
    {
        bootstrap_admin(
            &users_repo,
            &roles_repo,
            &PgAssignmentRepository::new(pool.clone()),
            &PgPermissionRepository::new(pool.clone()),
            &hasher,
            &email,
            &password,
            &first_name,
            &second_name,
        )
        .await?;
        println!("Готово: {email} теперь admin.");
        return Ok(());
    }

    let ports = Ports {
        users: Arc::new(users_repo),
        roles: Arc::new(roles_repo),
        assignments: Arc::new(PgAssignmentRepository::new(pool.clone())),
        permissions: Arc::new(PgPermissionRepository::new(pool.clone())),
        sessions: Arc::new(PgSessionRepository::new(pool.clone())),
        hasher: Arc::new(hasher),
        access_tokens: Arc::new(JwtCodec::new(&cfg.crypto.jwt)),
        refresh_tokens: Arc::new(Sha256RefreshTokenProvider),
        clock: Arc::new(auth_core::ports::SystemClock),
        settings: Arc::new(PgSettingsRepository::new(pool.clone())),
    };

    let policy = cfg.auth.build().context("auth policy")?;
    let state = ApiState::from_ports(&ports, policy);
    let app = auth_api::router(state, &cfg.api);

    let listener = TcpListener::bind(cfg.server.bind).await.context("bind")?;
    info!(addr = %cfg.server.bind, "auth-server слушает");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("сервер упал")?;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn bootstrap_admin(
    users: &PgUserRepository,
    roles: &PgRoleRepository,
    assignments: &PgAssignmentRepository,
    permissions: &PgPermissionRepository,
    hasher: &Argon2PasswordHasher,
    email: &str,
    password: &str,
    first_name: &str,
    second_name: &str,
) -> anyhow::Result<()> {
    use auth_core::ports::{AssignmentRepository, PermissionRepository};

    let admin_role = match roles
        .create(&NewRole {
            code: auth_core::domain::RoleCode::parse("admin")
                .or_else(|_| auth_core::domain::RoleCode::parse("admin"))?,
            name: "Admin".into(),
            scope: RoleScope::Global,
        })
        .await
    {
        Ok(r) => r,
        Err(AuthError::Conflict) => {
            let page = roles
                .list(&PageRequest::new(None, Some(100), Some("admin".into())))
                .await?;
            page.items
                .into_iter()
                .find(|r| r.code.as_str() == "admin")
                .context("роль admin в конфликте, но не найдена")?
        }
        Err(e) => bail!(e),
    };

    let all_perms = permissions.list().await?;
    let all_ids: Vec<_> = all_perms.iter().map(|p| p.id).collect();
    roles.set_permissions(admin_role.id, &all_ids).await?;
    let _ = perm::USERS_VIEW; // права уже сидируются миграцией 0002 — сверяем коды там же

    let hash = hasher
        .hash(&SecretString::from(password.to_owned()))
        .await?;
    let user = match users
        .create(&NewUser {
            email: Email::parse(email)?,
            password_hash: hash,
            first_name: first_name.to_owned(),
            second_name: second_name.to_owned(),
        })
        .await
    {
        Ok(u) => u,
        Err(AuthError::Conflict) => {
            users
                .find_credentials_by_email(&Email::parse(email)?)
                .await?
                .context("email в конфликте, но не найден")?
                .user
        }
        Err(e) => bail!(e),
    };

    match assignments.assign(user.id, admin_role.id, None).await {
        Ok(()) | Err(AuthError::Conflict) => {}
        Err(e) => bail!(e),
    }

    Ok(())
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("получен Ctrl+C, останавливаемся");
}
