-- Роль admin всегда имеет все права: и существующие, и добавленные позже.
-- Раньше admin получал снимок прав один раз, в create_first_admin, и право,
-- добавленное позже миграцией, нельзя было выдать никому.

create function grant_new_permission_to_admin() returns trigger
language plpgsql as $$
begin
    insert into role_permissions (role_id, permission_id)
    select id, new.id from roles where code = 'admin'
    on conflict do nothing;
    return new;
end $$;

create trigger permissions_grant_admin
after insert on permissions
for each row execute function grant_new_permission_to_admin();

-- догоняем права, добавленные до этой миграции
insert into role_permissions (role_id, permission_id)
select r.id, p.id from roles r cross join permissions p where r.code = 'admin'
on conflict do nothing;

-- Регистрация права для миграций: идемпотентно, с той же проверкой кода, что
-- PermissionCode в auth-core. Невалидный код в таблице сломал бы list() у всей админки.
create function register_permission(p_code text, p_description text) returns void
language plpgsql as $$
begin
    if p_code !~ '^[a-z][a-z0-9._-]{0,63}$' then
        raise exception 'неверный код права: %', p_code;
    end if;
    insert into permissions (code, description) values (p_code, p_description)
    on conflict (code) do update set description = excluded.description;
end $$;