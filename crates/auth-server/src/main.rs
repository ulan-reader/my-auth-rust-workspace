//! Composition root: читает конфиг, собирает адаптеры (postgres/crypto) за
//! портами core, строит ApiState, поднимает axum и слушает до Ctrl+C / SIGTERM.
//! Первый администратор создаётся через `POST /setup` (см. auth-api).

mod config;

use std::{sync::Arc, time::Duration};

use anyhow::{Context, bail};
use auth_api::ApiState;
use auth_core::{
    AuthError,
    ports::{SessionRepository, UnitOfWork},
    service::Ports,
};
use auth_crypto::{Argon2PasswordHasher, Jwks, JwtCodec, Sha256RefreshTokenProvider};
use auth_postgres::{
    PgAssignmentRepository, PgPermissionRepository, PgPool, PgRoleRepository, PgSessionRepository,
    PgSettingsRepository, PgSetupRepository, PgUnitOfWork, PgUserRepository,
};
use axum::{Json, Router, http::StatusCode, routing::get};
use chrono::{TimeDelta, Utc};
use clap::{Parser, Subcommand};
use config::AppConfig;
use secrecy::ExposeSecret;
use tokio::{net::TcpListener, sync::watch, time::MissedTickBehavior};
use tracing::info;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
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
        setup: Arc::new(PgSetupRepository::new(pool.clone())),
        uow: Arc::new(PgUnitOfWork::new(pool.clone())),
    };

    let policy = cfg.auth.build().context("auth policy")?;
    if let Some(token) = &cfg.setup.token
        && token.expose_secret().len() < 32
    {
        bail!("setup.token: минимум 32 символа");
    }
    let state = ApiState::from_ports(&ports, policy, cfg.setup.token.clone());
    let app = auth_api::router(state, &cfg.api)
        .context("конфиг api")?
        .merge(jwks_router(jwt_codec))
        .merge(health_router(pool.clone()));

    // воркер — после проверки конфига, но до приёма запросов
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let cleanup = tokio::spawn(session_cleanup(
        ports.uow.clone(),
        sessions.clone(),
        cfg.maintenance.clone(),
        shutdown_rx,
    ));

    let listener = TcpListener::bind(cfg.server.bind).await.context("bind")?;
    info!(addr = %cfg.server.bind, "auth-server слушает");
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    })
    .await
    .context("сервер упал")?;

    let _ = cleanup.await;
    Ok(())
}

async fn session_cleanup(
    uow: Arc<dyn UnitOfWork>,
    sessions: Arc<PgSessionRepository>,
    cfg: config::MaintenanceConfig,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(
        cfg.session_cleanup_interval_secs.max(1),
    ));
    interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
    let retention = i64::try_from(cfg.session_retention_secs)
        .ok()
        .and_then(TimeDelta::try_seconds)
        .unwrap_or(TimeDelta::MAX);

    loop {
        tokio::select! {
            _ = interval.tick() => {}   // первый тик сразу — чистим и на старте
            _ = shutdown.changed() => break,
        }
        let Some(before) = Utc::now().checked_sub_signed(retention) else {
            continue; // retention длиннее эпохи — удалять нечего
        };
        let result = async {
            let mut tx = uow.begin().await?;
            let deleted = sessions.purge_stale(&mut *tx, before).await?;
            tx.commit().await?;
            Ok::<_, AuthError>(deleted)
        }
        .await;

        match result {
            Ok(deleted) => info!(deleted, "очистка устаревших сессий завершена"),
            Err(error) => tracing::error!(%error, "не удалось очистить устаревшие сессии"),
        }
    }
    info!("воркер очистки сессий остановлен");
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(error) => {
                tracing::error!(%error, "не удалось подписаться на SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => info!("получен Ctrl+C, останавливаемся"),
        () = terminate => info!("получен SIGTERM, останавливаемся"),
    }
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
