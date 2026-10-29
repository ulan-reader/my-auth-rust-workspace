-- Журнал аудита: кто и когда менял доступы. Пишут его use-case'ы в той же
-- транзакции, что и само изменение, поэтому записи есть ровно у закоммиченных операций.
--
-- actor_id без внешнего ключа: после удаления пользователя записи о его действиях
-- должны остаться с тем же id, а не обнулиться и не исчезнуть каскадом.
-- scope здесь NULL для глобального: уникальности по нему нет, сентинел '' не нужен.
create table audit_events (
    id          bigserial   primary key,
    at          timestamptz not null default now(),
    actor_id    bigint,
    action      text        not null,
    target_type text        not null,
    target_id   bigint,
    scope       text,
    details     jsonb       not null default '{}'
);
create index audit_events_at_idx on audit_events (at desc, id desc);
create index audit_events_actor_idx on audit_events (actor_id, at desc);
create index audit_events_target_idx on audit_events (target_type, target_id, at desc);

-- Журнал только дописывается. Если понадобится чистить старое — отдельной
-- миграцией/процедурой с явным `alter table ... disable trigger`.
create function audit_events_append_only() returns trigger
language plpgsql as $$
begin
    raise exception 'audit_events: записи нельзя менять или удалять';
end;
$$;

create trigger audit_events_append_only
    before update or delete on audit_events
    for each row execute function audit_events_append_only();

create trigger audit_events_no_truncate
    before truncate on audit_events
    for each statement execute function audit_events_append_only();

-- admin получит право сам: триггер из 20261029120000_admin_all_permissions.sql
select register_permission('audit.view', 'Просмотр журнала аудита');
