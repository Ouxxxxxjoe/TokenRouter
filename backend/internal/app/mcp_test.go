package app

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"

	"github.com/TokenFlux/TokenRouter/internal/config"
	identityprovider "github.com/TokenFlux/TokenRouter/internal/identity/provider"
	"github.com/TokenFlux/TokenRouter/internal/infra/crypto"
	"github.com/TokenFlux/TokenRouter/internal/settings"
)

// mcp_test.go verifies site configuration and durable MCP artifact encryption.
// The tests distinguish missing settings from failed storage, retain deployment
// frontend defaults, and check that backend restarts can decrypt surviving files
// while configured TOTP encryption keeps its existing key.

// mcpSettingsFixture implements the setting operations used by OAuth configuration.
type mcpSettingsFixture struct {
	settings.Repository                   // Unused storage methods reject accidental calls.
	values              map[string]string // Current persisted setting values.
	err                 error             // Injected storage read or write failure.
}

// TestMCPArtifactCipherUsesDurableOAuthKey recreates encryption after a backend restart.
// A different temporary TOTP key must not prevent reading files encrypted with
// the persisted OAuth key, while a configured TOTP cipher retains its identity.
func TestMCPArtifactCipherUsesDurableOAuthKey(t *testing.T) {
	first, err := crypto.NewAESEncryptor(bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	second, err := crypto.NewAESEncryptor(bytes.Repeat([]byte{2}, 32))
	require.NoError(t, err)
	cfg := &config.Config{MCPOAuthSigningSecret: strings.Repeat("ab", 32)}
	a, err := mcpArtifactCipher(first, cfg)
	require.NoError(t, err)
	b, err := mcpArtifactCipher(second, cfg)
	require.NoError(t, err)
	ciphertext, err := a.Encrypt("protected fixture")
	require.NoError(t, err)
	plaintext, err := b.Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, "protected fixture", plaintext)
	_, err = first.Decrypt(ciphertext)
	require.Error(t, err)
	cfg.Totp.EncryptionKeyConfigured = true
	original, err := mcpArtifactCipher(first, cfg)
	require.NoError(t, err)
	require.Same(t, first, original)
	cfg.Totp.EncryptionKeyConfigured = false
	cfg.MCPOAuthSigningSecret = ""
	_, err = mcpArtifactCipher(first, cfg)
	require.Error(t, err)
}

// GetValue reads one fixture setting and distinguishes absence from storage failure.
// Missing keys return the production absence sentinel, allowing the assembled
// browser-origin reader to skip unconfigured URLs while keeping saved addresses.
func (s *mcpSettingsFixture) GetValue(_ context.Context, key string) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if value, ok := s.values[key]; ok {
		return value, nil
	}
	return "", settings.ErrSettingNotFound
}

// TestMCPOAuthUsesFrontendSettings verifies the upgrade path with existing site configuration.
// Database frontend values override deployment defaults, API display URLs are
// ignored, and storage failure cannot activate a different fallback origin.
func TestMCPOAuthUsesFrontendSettings(t *testing.T) {
	repo := &mcpSettingsFixture{values: map[string]string{"api_base_url": "https://api.example"}}
	adapter := &mcpOAuthFrontend{store: settings.New(repo), frontendURL: "https://deployment.example"}
	frontend, err := adapter.FrontendURL(t.Context())
	require.NoError(t, err)
	require.Equal(t, "https://deployment.example", frontend)
	repo.values["frontend_url"] = " https://site.example "
	frontend, err = adapter.FrontendURL(t.Context())
	require.NoError(t, err)
	require.Equal(t, "https://site.example", frontend)
	repo.err = errors.New("database unavailable")
	_, err = adapter.FrontendURL(t.Context())
	require.ErrorIs(t, err, repo.err)
}

// TestMCPBrowserOriginUsesFrontendURL assembles the transport with a deployment site address.
// The configured browser must reach credential authentication, and the challenge
// must advertise discovery at that same public origin.
func TestMCPBrowserOriginUsesFrontendURL(t *testing.T) {
	repo := &mcpSettingsFixture{values: map[string]string{}}
	store := settings.New(repo)
	cfg := &config.Config{MCPOAuthSigningSecret: strings.Repeat("ab", 32)}
	cfg.Server.FrontendURL = "https://frontend.example"
	oauth := identityprovider.NewMCPOAuthServer(nil, nil, &mcpOAuthFrontend{store: store, frontendURL: cfg.Server.FrontendURL}, bytes.Repeat([]byte{4}, 32))
	handler, err := provideMCPHTTP(oauth, nil, nil, nil, nil, nil, nil, store, cfg)
	require.NoError(t, err)
	router := gin.New()
	require.NoError(t, handler.Mount(router, func(c *gin.Context) { c.Next() }, func(c *gin.Context) { c.Next() }))
	request := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	request.Header.Set("Origin", cfg.Server.FrontendURL)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	require.Equal(t, http.StatusUnauthorized, response.Code)
	require.Contains(t, response.Header().Get("WWW-Authenticate"), "https://frontend.example/.well-known/oauth-protected-resource/mcp")
}
