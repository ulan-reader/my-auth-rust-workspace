//! Требует Docker. Один контейнер Postgres поднимается на весь процесс тестов
//! (через `#[ctor]`-подобный ленивый старт заменён явным вызовом `spin_up`
//! в каждом тесте — так тесты можно гонять параллельно с изоляцией по схеме
//! не потребовалось: каждый тест сам создаёт нужные ему строки и не пересекается
//! с другими по PK/email, коллизий не будет).

use auth_core::{
    AuthError,
    domain::{Email, PasswordHash, RoleScope, ScopeId, TokenHash, UserId},
    ports::{
        AssignmentRepository, NewRole, NewSession, NewUser, PageRequest, PermissionRepository,
        RoleRepository, SessionRepository, UserRepository, UserUpdate,
    },
};
use auth_postgres::{
    PgAssignmentRepository, PgPermissionRepository, PgRoleRepository, PgSessionRepository,
    PgUserRepository,
};
use chrono::{TimeDelta, Utc};
use sqlx::PgPool;
use testcontainers_modules::{postgres::Postgres, testcontainers::runners::AsyncRunner};

/// Контейнер надо держать живым, пока используется пул — если он будет сброшен (Drop),
/// Postgres внутри остановится. Поэтому возвращаем оба и держим `_container` в scope теста.
async fn spin_up() -> (
    testcontainers_modules::testcontainers::ContainerAsync<Postgres>,
    PgPool,
) {
    let container = Postgres::default()
        .start()
        .await
        .expect("запустить контейнер Postgres");
    let host = container.get_host().await.expect("узнать host контейнера");
    let port = container
        .get_host_port_ipv4(5432)
        .await
        .expect("узнать проброшенный порт");
    let url = format!("postgres://postgres:postgres@{host}:{port}/postgres");

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await
        .expect("подключиться к Postgres");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("прогнать миграции");

    (container, pool)
}

fn new_user(email: &str) -> NewUser {
    NewUser {
        email: Email::parse(email).unwrap(),
        password_hash: PasswordHash::new("$argon2id$fake$hash"),
        first_name: "Test".into(),
        second_name: "User".into(),
    }
}

#[tokio::test]
async fn user_crud_and_email_conflict() {
    let (_c, pool) = spin_up().await;
    let users = PgUserRepository::new(pool);

    let created = users.create(&new_user("a@example.com")).await.unwrap();
    assert!(created.is_active);

    let dup = users.create(&new_user("a@example.com")).await;
    assert!(matches!(dup, Err(AuthError::Conflict)));

    let found = users.find_by_id(created.id).await.unwrap().unwrap();
    assert_eq!(found.email.as_str(), "a@example.com");

    let creds = users
        .find_credentials_by_email(&Email::parse("a@example.com").unwrap())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(creds.password_hash.as_str(), "$argon2id$fake$hash");

    let updated = users
        .update(
            created.id,
            &UserUpdate {
                email: Email::parse("renamed@example.com").unwrap(),
                first_name: "New".into(),
                second_name: "Name".into(),
            },
        )
        .await
        .unwrap();
    assert_eq!(updated.email.as_str(), "renamed@example.com");

    assert!(matches!(
        users
            .update(
                UserId(999_999),
                &UserUpdate {
                    email: Email::parse("x@example.com").unwrap(),
                    first_name: "X".into(),
                    second_name: "Y".into(),
                },
            )
            .await,
        Err(AuthError::NotFound)
    ));

    users.set_active(created.id, false).await.unwrap();
    assert!(
        !users
            .find_by_id(created.id)
            .await
            .unwrap()
            .unwrap()
            .is_active
    );

    users.delete(created.id).await.unwrap();
    assert!(users.find_by_id(created.id).await.unwrap().is_none());
    assert!(matches!(
        users.delete(created.id).await,
        Err(AuthError::NotFound)
    ));
}

#[tokio::test]
async fn user_list_pagination_and_search() {
    let (_c, pool) = spin_up().await;
    let users = PgUserRepository::new(pool);
    for email in ["anna@example.com", "boris@example.com", "carl@example.com"] {
        users.create(&new_user(email)).await.unwrap();
    }

    let page = users
        .list(&PageRequest::new(Some(1), Some(2), None))
        .await
        .unwrap();
    assert_eq!(page.total, 3);
    assert_eq!(page.items.len(), 2);
    assert_eq!(page.total_pages(), 2);

    let found = users
        .list(&PageRequest::new(None, None, Some("bor".into())))
        .await
        .unwrap();
    assert_eq!(found.total, 1);
    assert_eq!(found.items[0].email.as_str(), "boris@example.com");
}

#[tokio::test]
async fn session_rotate_and_replay_detection() {
    let (_c, pool) = spin_up().await;
    let users = PgUserRepository::new(pool.clone());
    let sessions = PgSessionRepository::new(pool);
    let user = users.create(&new_user("s@example.com")).await.unwrap();

    let now = Utc::now();
    let first = sessions
        .create(&NewSession {
            user_id: user.id,
            token_hash: TokenHash::new("hash-1"),
            created_at: now,
            expires_at: now + TimeDelta::try_days(30).unwrap(),
        })
        .await
        .unwrap();

    let rotated = sessions
        .rotate(
            first.id,
            &NewSession {
                user_id: user.id,
                token_hash: TokenHash::new("hash-2"),
                created_at: now,
                expires_at: now + TimeDelta::try_days(30).unwrap(),
            },
            now,
        )
        .await
        .unwrap();
    assert_ne!(rotated.id, first.id);

    // старая сессия уже отозвана -> повторная ротация того же id даёт Conflict
    let replay = sessions
        .rotate(
            first.id,
            &NewSession {
                user_id: user.id,
                token_hash: TokenHash::new("hash-3"),
                created_at: now,
                expires_at: now + TimeDelta::try_days(30).unwrap(),
            },
            now,
        )
        .await;
    assert!(matches!(replay, Err(AuthError::Conflict)));

    let revoked = sessions.revoke_all_for_user(user.id, now).await.unwrap();
    assert_eq!(revoked, 1); // только rotated ещё активна, first уже отозвана
}

#[tokio::test]
async fn assign_role_conflict_and_effective_permissions() {
    let (_c, pool) = spin_up().await;
    let users = PgUserRepository::new(pool.clone());
    let roles = PgRoleRepository::new(pool.clone());
    let permissions = PgPermissionRepository::new(pool.clone());
    let assignments = PgAssignmentRepository::new(pool);

    let user = users.create(&new_user("perm@example.com")).await.unwrap();
    let global_role = roles
        .create(&NewRole {
            code: auth_core::domain::RoleCode::parse("admin").unwrap(),
            name: "Admin".into(),
            scope: RoleScope::Global,
        })
        .await
        .unwrap();
    let scoped_role = roles
        .create(&NewRole {
            code: auth_core::domain::RoleCode::parse("dept_head").unwrap(),
            name: "Dept Head".into(),
            scope: RoleScope::Scoped,
        })
        .await
        .unwrap();

    // права ещё не привязаны к ролям — список должен быть пуст
    let perm_list = permissions.list().await.unwrap();
    assert!(perm_list.is_empty());

    let created_perm = roles.set_permissions(global_role.id, &[]).await.unwrap();
    assert!(created_perm.is_empty()); // пустой набор — валидный кейс, permissions таблица пуста

    assignments
        .assign(user.id, global_role.id, None)
        .await
        .unwrap();
    // повторное назначение той же глобальной роли -> Conflict благодаря PK на (user_id, role_id, scope)
    assert!(matches!(
        assignments.assign(user.id, global_role.id, None).await,
        Err(AuthError::Conflict)
    ));

    let dept1 = ScopeId::parse("department:1").unwrap();
    assignments
        .assign(user.id, scoped_role.id, Some(&dept1))
        .await
        .unwrap();

    let all = assignments.for_users(&[user.id]).await.unwrap();
    assert_eq!(all.get(&user.id).unwrap().len(), 2);

    let revoked = assignments.revoke_all_in_scope(&dept1).await.unwrap();
    assert_eq!(revoked, 1);
    let after = assignments.for_users(&[user.id]).await.unwrap();
    assert_eq!(after.get(&user.id).unwrap().len(), 1); // глобальная осталась
}
