-- Grant permission to connect to the database
GRANT CONNECT ON DATABASE cas TO casuser;

-- Grant permission to the public schema
GRANT USAGE ON SCHEMA public TO casuser;

-- Grant permission to create objects in the public schema
GRANT CREATE ON SCHEMA public TO casuser;

-- Grant permission to all existing tables in the public schema
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO casuser;

-- Grant permission to all future tables in the public schema
ALTER DEFAULT PRIVILEGES IN SCHEMA public
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO casuser;

create table users
(
    user_id       serial primary key,
    username      varchar(20) not null,
    first_name    varchar(32),
    last_name     varchar(32),
    email         varchar(40) not null,
    mobile_number varchar(15) not null,
    password      varchar     not null
);

alter table users owner to casuser;

insert into public.users (user_id, username, first_name, last_name, email, mobile_number, password)
values  (1, 'testuser', 'Walter', 'White', 'heisenberg@gmail.com', '+420111111111', '$2a$08$.BZnkoB54Agki.I87yWB1.2g2gevZiXwrkxC9zqIUZN5ZDXbr4hSy'), --password: test1
        (2, 'testuser2', 'Josef', 'Bican', 'football@gmail.com', '+420222222222', '$2a$08$Y9AsO90wBO6oZiItRh8bEep87d8/7uWKEePp7JvBxnZxfguPqUKLO');   --password: test2

