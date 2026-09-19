CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    totp_enabled BOOLEAN NOT NULL DEFAULT false,
    totp_secret_encrypted TEXT,
    totp_iv TEXT,
    totp_tag TEXT,
    last_totp_window INTEGER
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
