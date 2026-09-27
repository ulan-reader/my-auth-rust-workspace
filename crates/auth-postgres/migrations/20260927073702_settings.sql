-- Add migration script here
-- Синглтон-строка: id=1 гарантирует, что настройки всегда одни на весь сервис.
create table app_settings (
    id                      smallint primary key default 1 check (id = 1),
    allow_self_registration boolean not null default false
);
insert into app_settings (id) values (1);

insert into permissions (code, description) values
    ('settings.manage', 'Управление runtime-настройками (регистрация и т.д.)')
on conflict (code) do nothing;
