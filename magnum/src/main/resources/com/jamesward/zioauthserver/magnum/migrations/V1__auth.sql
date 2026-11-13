-- zio-auth-server's tables. Flyway runs this in the store's own schema (default `auth`, see AuthSchema), so names
-- are unqualified. Secrets are stored only as HMACs (bytea); upstream tokens only sealed (text).

create table users (
    id         uuid        primary key,
    email      text        not null unique,
    status     text        not null default 'active',
    created_at timestamptz not null,
    updated_at timestamptz not null
);

create table email_login_challenges (
    id          uuid        primary key,
    email       text        not null,
    token_hash  bytea       not null unique,
    issued_at   timestamptz not null,
    expires_at  timestamptz not null,
    consumed_at timestamptz
);

create table email_otp_challenges (
    id          uuid        primary key,
    email       text        not null,
    code_hash   bytea       not null,
    issued_at   timestamptz not null,
    expires_at  timestamptz not null,
    consumed_at timestamptz,
    attempts    int         not null default 0
);
create index email_otp_challenges_email on email_otp_challenges (email, issued_at desc);

create table sessions (
    id_hash      bytea       primary key,
    user_id      uuid        not null references users (id) on delete cascade,
    csrf_hash    bytea       not null,
    expires_at   timestamptz not null,
    last_seen_at timestamptz not null,
    created_at   timestamptz not null
);
create index sessions_user on sessions (user_id);

-- Sets are stored as text: scopes and grant types space-separated (as in OAuth), redirect URIs newline-separated.
create table oauth_clients (
    id            text        primary key,
    kind          text        not null,
    profile       text        not null,
    name          text        not null,
    secret_hash   bytea,
    grants        text        not null,
    scopes        text        not null,
    registration  text        not null,
    registered_at timestamptz not null,
    created_at    timestamptz not null,
    redirect_uris text        not null
);

create table authorization_grants (
    code_hash        bytea       primary key,
    client_id        text        not null references oauth_clients (id) on delete cascade,
    user_id          uuid        not null references users (id) on delete cascade,
    redirect_uri     text        not null,
    scopes           text        not null,
    resource         text,
    code_challenge   text        not null,
    challenge_method text        not null,
    issued_at        timestamptz not null,
    expires_at       timestamptz not null,
    consumed_at      timestamptz
);

create table access_tokens (
    hash         bytea       primary key,
    client_id    text        not null references oauth_clients (id) on delete cascade,
    subject_kind text        not null,
    user_id      uuid        references users (id) on delete cascade,
    scopes       text        not null,
    resource     text,
    issued_at    timestamptz not null,
    expires_at   timestamptz not null,
    revoked_at   timestamptz
);

create table refresh_tokens (
    hash            bytea       primary key,
    root_hash       bytea       not null,
    parent_hash     bytea,
    client_id       text        not null references oauth_clients (id) on delete cascade,
    user_id         uuid        references users (id) on delete cascade,
    scopes          text        not null,
    resource        text,
    issued_at       timestamptz not null,
    expires_at      timestamptz not null,
    revoked_at      timestamptz,
    rotated_at      timestamptz,
    rotated_to_hash bytea
);
create index refresh_tokens_root on refresh_tokens (root_hash);

create table email_changes (
    id          uuid        primary key,
    user_id     uuid        not null references users (id) on delete cascade,
    new_email   text        not null,
    token_hash  bytea       not null unique,
    issued_at   timestamptz not null,
    expires_at  timestamptz not null,
    consumed_at timestamptz
);

create table passkeys (
    credential_id   text        primary key,
    user_id         uuid        not null references users (id) on delete cascade,
    user_handle     text        not null,
    public_key_cose text        not null,
    signature_count bigint      not null,
    name            text        not null,
    created_at      timestamptz not null,
    last_used_at    timestamptz
);
create index passkeys_user on passkeys (user_id);

create table passkey_ceremonies (
    id           uuid        primary key,
    kind         text        not null,
    user_id      uuid        references users (id) on delete cascade,
    request_json text        not null,
    expires_at   timestamptz not null
);

create table connection_states (
    state_hash    text        primary key,
    user_id       uuid        not null references users (id) on delete cascade,
    provider      text        not null,
    code_verifier text        not null,
    return_to     text,
    expires_at    timestamptz not null
);

create table connections (
    user_id       uuid        not null references users (id) on delete cascade,
    provider      text        not null,
    subject       text        not null,
    sealed_tokens text        not null,
    connected_at  timestamptz not null,
    updated_at    timestamptz not null,
    primary key (user_id, provider)
);
