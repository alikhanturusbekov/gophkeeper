CREATE TABLE IF NOT EXISTS users (
    id            TEXT        PRIMARY KEY,
    login         TEXT        UNIQUE NOT NULL,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS secrets (
    id             TEXT        PRIMARY KEY,
    user_id        TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name           TEXT        NOT NULL,
    kind           TEXT        NOT NULL
                               CHECK (kind IN ('credential','text','binary','card')),
    encrypted_data BYTEA       NOT NULL,
    metadata       TEXT        NOT NULL DEFAULT '',
    version        BIGINT      NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted        BOOLEAN     NOT NULL DEFAULT FALSE
);

CREATE INDEX IF NOT EXISTS idx_secrets_user    ON secrets (user_id);
CREATE INDEX IF NOT EXISTS idx_secrets_version ON secrets (user_id, version);
