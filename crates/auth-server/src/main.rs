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
    ports::{
        NewRole, NewUser, PageRequest, PasswordHasher, RoleRepository, SessionRepository,
        UserRepository,
    },
    service::Ports,
};
use auth_crypto::{Argon2PasswordHasher, Jwks, JwtCodec, Sha256RefreshTokenProvider};
use auth_postgres::{
    PgAssignmentRepository, PgPermissionRepository, PgPool, PgRoleRepository, PgSessionRepository,
    PgSettingsRepository, PgUserRepository,
};
use axum::{Json, Router, http::StatusCode, routing::get};
use chrono::{Duration as ChronoDuration, Utc};
use clap::{Parser, Subcommand};
use config::AppConfig;
use secrecy::SecretString;
use std::time::Duration;
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
    /// Сгенерировать новую пару ключей Ed25519 для crypto.jwt.*.
    /// Ничего не пишет в БД/конфиг — значения нужно положить в .env/config вручную.
    JwtKeygen,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();

    // Не требует конфига/БД — можно звать даже до первого запуска сервера.
    if matches!(cli.command, Some(Command::JwtKeygen)) {
        let (seed, public) = auth_crypto::generate_signing_key().context("генерация ключа")?;
        println!("Новый ключ Ed25519 сгенерирован.\n");
        println!("AUTH__CRYPTO__JWT__SIGNING_KEY={seed}");
        println!("AUTH__CRYPTO__JWT__KID=<придумай идентификатор, например дату>\n");
        println!(
            "Публичный ключ (x, base64url): {public}\n\
             При ротации положи его в crypto.jwt.extra_verification_keys под старым kid,\n\
             чтобы токены, выданные до смены ключа, ещё проходили проверку до истечения TTL."
        );
        return Ok(());
    }

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
    let jwt_codec = Arc::new(
        JwtCodec::new(&cfg.crypto.jwt)
            .context("ключ подписи JWT (проверь AUTH__CRYPTO__JWT__SIGNING_KEY/KID)")?,
    );
    let sessions = Arc::new(PgSessionRepository::new(pool.clone()));

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
        sessions: sessions.clone(),
        hasher: Arc::new(hasher),
        access_tokens: jwt_codec.clone(),
        refresh_tokens: Arc::new(Sha256RefreshTokenProvider),
        clock: Arc::new(auth_core::ports::SystemClock),
        settings: Arc::new(PgSettingsRepository::new(pool.clone())),
    };

    let cleanup_interval =
        Duration::from_secs(cfg.maintenance.session_cleanup_interval_secs.max(1));

    let retention_secs = i64::try_from(cfg.maintenance.session_retention_secs).unwrap_or(i64::MAX);

    let sessions_for_cleanup = sessions.clone();

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(cleanup_interval);

        interval.tick().await;

        loop {
            interval.tick().await;

            let before = Utc::now() - ChronoDuration::seconds(retention_secs);

            match sessions_for_cleanup.purge_stale(before).await {
                Ok(deleted) => {
                    tracing::info!(deleted, "Очистка устаревших сессий завершена");
                }
                Err(error) => {
                    tracing::error!(
                        error = %error,
                        "Не удалось очистить устаревшие сессии"
                    );
                }
            }
        }
    });

    let policy = cfg.auth.build().context("auth policy")?;
    let state = ApiState::from_ports(&ports, policy);
    let app = auth_api::router(state, &cfg.api)
        .merge(jwks_router(jwt_codec))
        .merge(health_router(pool.clone()));

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
            code: auth_core::domain::RoleCode::parse("admin")?,
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

/// Публикация публичных ключей проверки JWT — отдельно от `auth_api::router`,
/// чтобы auth-api не зависел от auth-crypto (гексагональная граница).
/// Без аутентификации: это ровно то, что сторонние сервисы должны уметь
/// забрать без привилегий, чтобы проверять токены локально (см. JwtVerifier).
fn jwks_router(codec: Arc<JwtCodec>) -> Router {
    async fn jwks(axum::extract::State(codec): axum::extract::State<Arc<JwtCodec>>) -> Json<Jwks> {
        Json(codec.jwks().clone())
    }

    Router::new()
        .route("/.well-known/jwks.json", get(jwks))
        .with_state(codec)
}

/// `/health/live` — процесс жив и отвечает, без походов во внешний мир.
/// Отдельно от `/health/ready`: оркестратор не должен убивать под из-за
/// временной недоступности БД, если сам процесс в порядке (live != ready).
///
/// `/health/ready` — живо ли соединение с Postgres. `503`, если нет: под
/// снимается с ротации трафика, но не перезапускается (это не live-check).
fn health_router(pool: PgPool) -> Router {
    async fn live() -> StatusCode {
        StatusCode::OK
    }

    async fn ready(axum::extract::State(pool): axum::extract::State<PgPool>) -> StatusCode {
        match auth_postgres::ping(&pool).await {
            Ok(()) => StatusCode::OK,
            Err(e) => {
                tracing::warn!(error = %e, "health/ready: postgres недоступен");
                StatusCode::SERVICE_UNAVAILABLE
            }
        }
    }

    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .with_state(pool)
}
