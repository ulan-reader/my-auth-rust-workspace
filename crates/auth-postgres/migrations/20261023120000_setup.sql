-- Одноразовая первоначальная настройка: после неё POST /setup закрыт навсегда.
alter table app_settings add column setup_completed_at timestamptz;

-- Базы, где админ уже есть (создан через bootstrap-admin), считаем настроенными.
update app_settings set setup_completed_at = now()
where exists (
    select 1 from user_roles ur join roles r on r.id = ur.role_id where r.code = 'admin'
);