CREATE TABLE IF NOT EXISTS secrets (
    id                UUID PRIMARY KEY,                     -- генерим в C++
    encrypted_payload BYTEA,                       -- сами данные (текст или файл)
    text_size_bytes   BIGINT NOT NULL DEFAULT 0,                      -- размер исходных данных
    passphrase_hash   TEXT,                                 -- хеш пароля, NULL если без пароля
    burn_after_read   BOOLEAN NOT NULL DEFAULT TRUE,
    read_count        INT NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at        TIMESTAMPTZ NOT NULL,

    CONSTRAINT chk_expires_after_created CHECK (expires_at > created_at),
    CONSTRAINT chk_read_count_non_negative CHECK (read_count >= 0),
    CONSTRAINT chk_text_size_non_negative CHECK (text_size_bytes >= 0)
);

CREATE INDEX IF NOT EXISTS idx_secrets_expires_at ON secrets (expires_at);

CREATE TABLE IF NOT EXISTS attachments (
    id                UUID PRIMARY KEY,  --id файла для ссылки на скачивание
    secret_id         UUID NOT NULL, --к какой записке относится
    position          INT NOT NULL,  --порядок файлов: 0, 1, 2… как пришли в запросе
    filename          TEXT NOT NULL, --исходное имя
    content_type      TEXT NOT NULL,
    size_bytes        BIGINT NOT NULL,
    encrypted_payload BYTEA NOT NULL, --сами байты
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_attachments_secret FOREIGN KEY (secret_id) REFERENCES secrets (id) ON DELETE CASCADE,
    CONSTRAINT chk_attachment_size_positive CHECK (size_bytes > 0),
    CONSTRAINT uq_attachment_position UNIQUE (secret_id, position)
);