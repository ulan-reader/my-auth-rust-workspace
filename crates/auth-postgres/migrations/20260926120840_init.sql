-- Сентинел '' вместо NULL в user_roles.scope: NULL в уникальном индексе Postgres
-- не конфликтует сам с собой, а нам нужно, чтобы повторное назначение одной и той
-- же глобальной роли давало Conflict.

create table users (
    id            bigserial primary key,
    email         text not null unique,
    password_hash text not null,
    first_name    text not null default '',
    second_name   text not null default '',
    is_active     boolean not null default true

);

create table roles (
    id    bigserial primary key,
    code  text not null unique,
    name  text not null,
    scope text not null check (scope in ('global', 'scoped'))
);

create table permissions (
    id          bigserial primary key,
    code        text not null unique,
    description text not null default ''
);

create table role_permissions (
    role_id       bigint not null references roles(id) on delete cascade,
    permission_id bigint not null references permissions(id) on delete cascade,
    primary key (role_id, permission_id)
);

create table user_roles (
    user_id bigint not null references users(id) on delete cascade,
    role_id bigint not null references roles(id) on delete cascade,
    -- '' для глобальных ролей, непустая строка для scoped (гарантируется доменом
    -- через RoleScope::check_assignment ещё до вызова репозитория)
    scope   text not null default '',
    primary key (user_id, role_id, scope)
);
create index user_roles_scope_idx on user_roles (scope) where scope <> '';

create table sessions (
    id         bigserial primary key,
    user_id    bigint not null references users(id) on delete cascade,
    token_hash text not null unique,
    created_at timestamptz not null,
    expires_at timestamptz not null,
    revoked_at timestamptz
);
create index sessions_user_id_idx on sessions (user_id);
