package app

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TokenFlux/TokenRouter/internal/settings"
)

// mcp_oauth_test.go verifies the frontend settings used for OAuth protocol origins.
// Database values take precedence over deployment defaults, while storage errors
// prevent a request from using a different address. The fixture distinguishes
// missing settings from unsuccessful reads through the production settings store.

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
