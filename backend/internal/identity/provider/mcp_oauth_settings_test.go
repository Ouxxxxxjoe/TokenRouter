package provider

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// mcp_oauth_settings_test.go checks live frontend-derived protocol configuration.
// The settings fixture changes between requests while previously returned
// protocol instances keep their own origin. Invalid configuration and failed
// reads deny access before any OAuth credential storage can be consulted.

// TestOAuthFrontendAddressValidation covers public origins and local development.
// Paths and credentials cannot silently become another issuer; unavailable
// addresses produce actionable browser status without enabling protocol requests.
func TestOAuthFrontendAddressValidation(t *testing.T) {
	cases := []struct {
		url    string // Configured frontend URL fixture.
		issuer string // Expected normalized issuer origin.
		reason string // Expected unavailability reason code.
	}{
		{"", "", "frontend_url_missing"},
		{" https://Site.Example/ ", "https://site.example", ""},
		{"http://localhost:8080", "http://localhost:8080", ""},
		{"http://127.0.0.1:8080", "http://127.0.0.1:8080", ""},
		{"http://[::1]:8080", "http://[::1]:8080", ""},
		{"http://site.example", "", "frontend_url_invalid"},
		{"https://site.example/frontend", "", "frontend_url_invalid"},
		{"https://user:pass@site.example", "", "frontend_url_invalid"},
		{"https://site.example?", "", "frontend_url_invalid"},
		{"https://site.example?q=a", "", "frontend_url_invalid"},
		{"https://site.example#part", "", "frontend_url_invalid"},
		{"https://site.example#", "", "frontend_url_invalid"},
		{"https://:443", "", "frontend_url_invalid"},
		{"//site.example", "", "frontend_url_invalid"},
	}
	for _, tc := range cases {
		settings := &oauthFrontendFixture{url: tc.url}
		server := NewMCPOAuthServer(nil, nil, settings, bytes.Repeat([]byte{3}, 32))
		status, err := server.Status(t.Context())
		require.NoError(t, err, tc.url)
		require.Equal(t, tc.issuer, status.Issuer, tc.url)
		require.Equal(t, tc.reason, status.Reason, tc.url)
		require.Equal(t, tc.reason == "", status.Enabled, tc.url)
	}
}

// TestOAuthRequestsResolveCurrentFrontend captures a request before changing settings.
// New requests observe the new or missing origin, while the captured
// request retains internally consistent discovery and token metadata.
func TestOAuthRequestsResolveCurrentFrontend(t *testing.T) {
	settings := &oauthFrontendFixture{url: "https://first.example"}
	server := NewMCPOAuthServer(nil, nil, settings, bytes.Repeat([]byte{4}, 32))
	first, err := server.Current(t.Context())
	require.NoError(t, err)
	settings.url = "https://second.example"
	second, err := server.Current(t.Context())
	require.NoError(t, err)
	require.Equal(t, "https://first.example", first.Metadata()["issuer"])
	require.Equal(t, "https://second.example", second.Metadata()["issuer"])
	require.Equal(t, "https://second.example/mcp", second.Resource())
	settings.url = ""
	status, err := server.Status(t.Context())
	require.NoError(t, err)
	require.False(t, status.Enabled)
	require.Equal(t, "frontend_url_missing", status.Reason)
	_, err = server.Current(t.Context())
	require.Error(t, err)
	_, err = server.AuthorizeGrant(t.Context(), 1)
	require.Error(t, err)
	settings.err = errors.New("database unavailable")
	_, err = server.Status(t.Context())
	require.ErrorIs(t, err, settings.err)
	_, err = server.Current(t.Context())
	require.ErrorIs(t, err, settings.err)
}
