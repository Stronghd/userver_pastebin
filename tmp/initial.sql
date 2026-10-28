CREATE TABLE IF NOT EXISTS secrets (
    id                UUID PRIMARY KEY,                     -- генерим в C++
    encrypted_payload BYTEA NOT NULL,                       -- сами данные (текст или файл)
    content_type      TEXT NOT NULL DEFAULT 'text/plain',   -- что за данные
    filename          TEXT,                                 -- имя файла, NULL для текста
    size_bytes        BIGINT NOT NULL,                      -- размер исходных данных
    passphrase_hash   TEXT,                                 -- хеш пароля, NULL если без пароля
    burn_after_read   BOOLEAN NOT NULL DEFAULT TRUE,
    read_count        INT NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL,

    CONSTRAINT chk_expires_after_created CHECK (expires_at > created_at),
    CONSTRAINT chk_read_count_non_negative CHECK (read_count >= 0),
    CONSTRAINT chk_size_positive CHECK (size_bytes > 0)
);

CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets (expires_at);