
--create or replace function updated() returns trigger as $$
--begin
--   NEW.updated = now();
--   return NEW;
--end;
--$$ language 'plpgsql';


create table users (
    id                     uuid                     not null    primary key  default uuid_generate_v4(),
    login                  text                     not null,   -- unique on lower()

    is_enabled             boolean                  not null    default false,
    is_confirmed           boolean                  not null    default false,

    password_hash          text                     not null    default '',

    confirm_code           text                     NULL        unique,
    confirm_time           timestamp                NULL,

    name                   text                     not null    default '',

    facebook_user_id       text                     NULL        unique,
    facebook_access_token  text                     not null    default '',

    vk_user_id             text                     NULL        unique,
    vk_access_token        text                     not null    default '',

--    twitter_user_id        text                     NULL        unique,
--    twitter_access_token   text                     not null    default '',
--    twitter_access_secret  text                     not null    default '',

    registered             timestamp                not null    default current_timestamp,
    last_login             timestamp                NULL,
    last_activity          timestamp                NULL,

    comment                text                     not null    default ''
);

create unique index lower_login_idx ON users(lower(login));


create table roles (
    id                     text                     not null     primary key,
    name                   text                     not null,
    description            text                     not null     default ''
);

create table user_role_link (
    user_id               uuid                      not null    references users(id)
      on update cascade on delete cascade,
    role_id               text                      not null    references roles(id)
      on update cascade on delete cascade,

    primary key (user_id, role_id)
);

create table permissions (
    object_type            text                     not null    default '',
    permission             text                     not null,
    description            text                     not null    default '',

    primary key (object_type, permission)
);

create table role_permissions (
    role_id               text                      not null    references roles(id)
      on update cascade on delete cascade,
    object_type           text                      not null    default '',
    object_id             text                      not null    default '',  -- '' means no ID
    permission            text                      not null,

    primary key (role_id, permission),

    foreign key (object_type, permission) references permissions(object_type, permission)
      on update cascade on delete cascade
);

------------------------------------------------------------------------------------

--insert into roles (id, name, description) values
--  ('administrator', 'Администратор', 'доступ в панель управления');

--insert into permissions (object_type, permission) values
--  ('admin-panel', 'access'),
--  ('admin-panel', 'admin-only');

--insert into role_permissions (role_id, object_type, permission) values
--  ('administrator', 'admin-panel', 'access'),
--  ('administrator', 'admin-panel', 'admin-only');

--insert into users (login, email, password_hash, status, name) values (
--  'admin', 'admin@example.com',
--  '$pbkdf2-sha256$7377$RohxTsmZsxailNK6l5IyBg$lFds1glS9Yp18CfqC1CnRUpTV6FFG0ARSiRazTq94g4',
--  'ACTIVE', 'Admin'
--);

--insert into user_role_link values
--  ('admin', 'administrator');
