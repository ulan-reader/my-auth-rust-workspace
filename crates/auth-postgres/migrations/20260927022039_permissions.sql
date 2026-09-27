insert into permissions (code, description) values
    ('users.view', 'Просмотр пользователей'),
    ('users.manage', 'Управление пользователями'),
    ('roles.view', 'Просмотр ролей'),
    ('roles.manage', 'Управление ролями'),
    ('roles.assign', 'Назначение ролей'),
    ('permissions.view', 'Просмотр прав')
on conflict (code) do nothing;
