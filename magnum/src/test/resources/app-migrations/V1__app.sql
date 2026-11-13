-- An app's own migration (in its own Flyway, schema public) that refers to the auth schema's users.
create table projects (
    id       uuid primary key,
    owner_id uuid not null references auth.users (id)
);
