-- OAuth clients and grants are independent of manual MCP credentials so their
-- rotating tokens cannot replace or expose an administrator's existing token.
CREATE TABLE IF NOT EXISTS mcp_oauth_clients (
    id TEXT PRIMARY KEY, metadata JSONB NOT NULL, secret_hash BYTEA,
    expires_at TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS mcp_oauth_grants (
    id BIGSERIAL PRIMARY KEY, user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id TEXT NOT NULL, client_name TEXT NOT NULL, resource TEXT NOT NULL,
    name VARCHAR(120) NOT NULL, permissions JSONB NOT NULL DEFAULT '[]',
    enabled BOOLEAN NOT NULL DEFAULT TRUE, skip_browser_confirmation BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ, last_used_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (jsonb_typeof(permissions) = 'array')
);
CREATE UNIQUE INDEX IF NOT EXISTS mcp_oauth_live_grant_idx
    ON mcp_oauth_grants(user_id, client_id, resource) WHERE revoked_at IS NULL;
CREATE TABLE IF NOT EXISTS mcp_oauth_pending (
    id TEXT PRIMARY KEY, form JSONB NOT NULL, client JSONB NOT NULL,
    user_id BIGINT REFERENCES users(id) ON DELETE CASCADE, session_id TEXT,
    expires_at TIMESTAMPTZ NOT NULL, consumed BOOLEAN NOT NULL DEFAULT FALSE
);
CREATE TABLE IF NOT EXISTS mcp_oauth_sessions (
    kind TEXT NOT NULL CHECK (kind IN ('code','pkce','access','refresh')),
    signature TEXT NOT NULL, family_id TEXT NOT NULL,
    grant_id BIGINT NOT NULL REFERENCES mcp_oauth_grants(id) ON DELETE CASCADE,
    payload JSONB NOT NULL, expires_at TIMESTAMPTZ NOT NULL, active BOOLEAN NOT NULL DEFAULT TRUE,
    PRIMARY KEY (kind, signature)
);
CREATE INDEX IF NOT EXISTS mcp_oauth_sessions_family_idx ON mcp_oauth_sessions(family_id);
CREATE INDEX IF NOT EXISTS mcp_oauth_sessions_grant_idx ON mcp_oauth_sessions(grant_id);
CREATE INDEX IF NOT EXISTS mcp_oauth_sessions_expiry_idx ON mcp_oauth_sessions(expires_at);
