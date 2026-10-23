package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// mcp_test.go verifies canonical deployment origins and local development exceptions.
// OAuth discovery rejects path-bearing or insecure public issuers before the
// HTTP service starts, so request headers cannot repair invalid configuration.

// TestMCPIssuerValidation covers disabled, public HTTPS, and loopback development
// configurations. Credentials, paths, query strings, and public HTTP origins
// are rejected before any protocol endpoint can advertise them to clients.
func TestMCPIssuerValidation(t *testing.T) {
	for _, raw := range []string{"", "https://gateway.example", "https://gateway.example/", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080"} {
		cfg := MCPConfig{OAuth: MCPOAuthConfig{IssuerURL: raw}}
		require.NoError(t, cfg.Validate(), raw)
	}
	for _, raw := range []string{"https://gateway.example/path", "http://gateway.example", "https://a:b@gateway.example", "https://gateway.example?x=1", "https://gateway.example#x", "//gateway.example"} {
		cfg := MCPConfig{OAuth: MCPOAuthConfig{IssuerURL: raw}}
		require.Error(t, cfg.Validate(), raw)
	}
}
