# syntax=docker/dockerfile:1.7
#
# Цели:
#   dev     — исходники монтируются с хоста, cargo-watch пересобирает и
#             перезапускает сервер при каждом сохранении (см. docker-compose.yml).
#   runtime — компактный прод-образ. Зависимости кешируются отдельным слоем
#             (cargo-chef), поэтому правка своего кода пересобирает только
#             крейты workspace, а не весь граф зависимостей.

ARG RUST_VERSION=1.98

# ---------- база: rust + cargo-chef ----------
FROM rust:${RUST_VERSION}-slim-bookworm AS chef
RUN cargo install cargo-chef --locked
WORKDIR /app

# ---------- dev: автопересборка при изменении файлов ----------
FROM chef AS dev
RUN rustup component add clippy rustfmt \
    && cargo install cargo-watch --locked
# target — в именованном томе, а не на bind-mount с Windows: так в разы быстрее
ENV CARGO_TARGET_DIR=/target
# --poll: события файловой системы с Windows-хоста в контейнер не доходят
CMD ["cargo", "watch", "--poll", "-w", "crates", "-w", "config", "-w", "Cargo.toml", "-x", "run -p auth-server"]

# ---------- рецепт зависимостей: меняется только с Cargo.toml / Cargo.lock ----------
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---------- сборка: сначала зависимости (кешируемый слой), потом свой код ----------
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked -p auth-server

# ---------- runtime ----------
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 auth
WORKDIR /app
# миграции зашиты в бинарь (sqlx::migrate!), отдельно копировать не нужно
COPY --from=builder /app/target/release/auth-server /usr/local/bin/auth-server
COPY config ./config
USER auth
ENV AUTH_ENV=prod \
    AUTH__SERVER__BIND=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["auth-server"]
