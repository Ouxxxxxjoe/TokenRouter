package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// mcp_oauth_test.go exercises protocol failures that occur before storage lookup.
// Malformed requests must return bounded OAuth errors locally without requiring
// a parsed Fosite requester or allowing a callback supplied by rejected input.

// oauthFrontendFixture supplies a mutable site address for isolated protocol checks.
type oauthFrontendFixture struct {
	url string // Current fixture frontend address.
	err error  // Injected settings read failure.
}

// TestOAuthMalformedAuthorizationReturnsLocalError covers invalid encoding and
// duplicate parameters before request parsing. Each response is an OAuth 400
// without a redirect, and the error writer must not panic on an absent requester.
func TestOAuthMalformedAuthorizationReturnsLocalError(t *testing.T) {
	root := NewMCPOAuthServer(nil, nil, &oauthFrontendFixture{url: "https://gateway.example"}, bytes.Repeat([]byte{3}, 32))
	server, err := root.Current(t.Context())
	require.NoError(t, err)
	for _, query := range []string{"client_id=a&client_id=b", "state=%zz", "state=" + strings.Repeat("x", 4097)} {
		request := httptest.NewRequest(http.MethodGet, "https://gateway.example/mcp/oauth/authorize", nil)
		request.URL.RawQuery = query
		response := httptest.NewRecorder()
		require.NotPanics(t, func() { server.Start(response, request) })
		require.Equal(t, http.StatusBadRequest, response.Code)
		require.Empty(t, response.Header().Get("Location"))
		var result map[string]any
		require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
		require.Equal(t, "invalid_request", result["error"])
	}
}

// TestOAuthForeignCredentialsFailBeforeStorage submits panel JWT-shaped values and
// oversized opaque values with no repository installed. Rejection must happen
// before persistence is consulted, preserving the MCP credential format boundary.
func TestOAuthForeignCredentialsFailBeforeStorage(t *testing.T) {
	root := NewMCPOAuthServer(nil, nil, &oauthFrontendFixture{url: "https://gateway.example"}, bytes.Repeat([]byte{3}, 32))
	server, err := root.Current(t.Context())
	require.NoError(t, err)
	for _, credential := range []string{"panel.jwt.signature", "refresh-token", "ory_at_" + strings.Repeat("x", 513)} {
		var err error
		require.NotPanics(t, func() { _, err = server.Authenticate(t.Context(), credential) })
		require.Error(t, err)
	}
}

// FrontendURL returns the fixture address or its injected storage failure.
func (s *oauthFrontendFixture) FrontendURL(context.Context) (string, error) {
	return s.url, s.err
}
