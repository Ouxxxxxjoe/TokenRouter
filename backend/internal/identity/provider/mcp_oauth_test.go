package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ory/fosite"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/TokenFlux/TokenRouter/internal/identity"
)

// mcp_oauth_test.go exercises protocol rejection and revocation persistence failures.
// Malformed authorization requests receive local OAuth errors, while revocation uses
// client-owned credential records independently of current application admission and
// reports unavailable persistence without publishing a successful transaction outcome.

// oauthFrontendFixture supplies a mutable site address for isolated protocol checks.
type oauthFrontendFixture struct {
	url string // Current fixture frontend address.
	err error  // Injected settings read failure.
}

// revocationRepository injects transaction and storage failures into the real Fosite handlers.
type revocationRepository struct {
	identity.MCPOAuthRepository                           // unused persistence fixture methods
	client                      *identity.MCPOAuthClient  // authenticated fixture client registration
	record                      *identity.MCPOAuthSession // persisted credential ownership record
	fail                        string                    // selected failing persistence stage
	writes                      int                       // attempted family revocation writes
	committed                   bool                      // successful transaction completion marker
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

// TestOAuthRevocationStorageFailures exercises failures before, within, and after the
// revocation callback. OAuth 503 responses preserve retryability and failed transactions
// never publish success, including when alternate-kind discovery succeeds after failure.
func TestOAuthRevocationStorageFailures(t *testing.T) {
	for _, stage := range []string{"begin", "client", "refresh", "access", "decode", "revoke_first", "revoke_second", "commit"} {
		t.Run(stage, func(t *testing.T) {
			repo, server := newRevocationFixture(t)
			repo.fail = stage
			if stage == "decode" {
				repo.record.Payload = []byte("invalid JSON")
			}
			response := httptest.NewRecorder()
			hint := "refresh_token"
			if stage == "access" {
				hint = "access_token"
			}
			server.Revoke(response, revocationRequest("client", "credential.signature", hint))
			require.Equal(t, http.StatusServiceUnavailable, response.Code, response.Body.String())
			var body map[string]any
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
			require.Equal(t, "temporarily_unavailable", body["error"])
			require.Equal(t, "no-store", response.Header().Get("Cache-Control"))
			require.False(t, repo.committed)
		})
	}
}

// TestOAuthRevocationOwnershipAndClientAuthentication revokes stored ownership without
// consulting grant or account admission. Unknown credentials remain successful while
// foreign ownership, issuer, resource, and confidential authentication prevent mutation.
func TestOAuthRevocationOwnershipAndClientAuthentication(t *testing.T) {
	for _, scenario := range []string{"active", "inactive", "expired", "unknown", "other_client", "foreign_issuer", "foreign_resource", "unknown_client", "missing_secret", "wrong_secret", "valid_secret"} {
		t.Run(scenario, func(t *testing.T) {
			repo, server := newRevocationFixture(t)
			expectedStatus, expectedWrites := http.StatusOK, 2
			clientID := "client"
			switch scenario {
			case "inactive":
				repo.record.Active = false
			case "expired":
				repo.record.ExpiresAt = time.Now().Add(-time.Hour)
			case "unknown":
				repo.record = nil
				expectedWrites = 0
			case "other_client":
				clientID = "other"
				expectedWrites = 0
			case "foreign_issuer", "foreign_resource":
				var stored map[string]any
				require.NoError(t, json.Unmarshal(repo.record.Payload, &stored))
				field := strings.TrimPrefix(scenario, "foreign_")
				session, ok := stored["session"].(map[string]any)
				require.True(t, ok)
				session[field] = "https://foreign.example"
				var err error
				repo.record.Payload, err = json.Marshal(stored)
				require.NoError(t, err)
				expectedWrites = 0
			case "unknown_client":
				clientID = "unknown"
				expectedStatus, expectedWrites = http.StatusUnauthorized, 0
			case "missing_secret", "wrong_secret", "valid_secret":
				repo.client.AuthMethod = "client_secret_basic"
				secret, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
				require.NoError(t, err)
				repo.client.SecretHash = secret
				if scenario != "valid_secret" {
					expectedStatus, expectedWrites = http.StatusUnauthorized, 0
				}
			}
			request := revocationRequest(clientID, "credential.signature", "refresh_token")
			if scenario == "wrong_secret" {
				request.SetBasicAuth("client", "wrong")
			}
			if scenario == "valid_secret" {
				request.SetBasicAuth("client", "secret")
			}
			response := httptest.NewRecorder()
			server.Revoke(response, request)
			require.Equal(t, expectedStatus, response.Code, response.Body.String())
			require.Equal(t, expectedWrites, repo.writes)
		})
	}
}

// newRevocationFixture builds a valid ownership payload and production OAuth protocol.
// Unimplemented grant and user readers panic if revocation accidentally requires current
// admission, making ownership-only behavior independent from a permissive account fixture.
func newRevocationFixture(t *testing.T) (*revocationRepository, *MCPOAuthServer) {
	t.Helper()
	client := &identity.MCPOAuthClient{ID: "client", AuthMethod: "none", GrantTypes: []string{"authorization_code", "refresh_token"}}
	request := &fosite.Request{ID: "family", Client: &fosite.DefaultClient{ID: "client"}, Session: &oauthSession{GrantID: 1, Issuer: "https://gateway.example", Resource: "https://gateway.example/mcp"}}
	payload, err := json.Marshal(request)
	require.NoError(t, err)
	repo := &revocationRepository{client: client, record: &identity.MCPOAuthSession{GrantID: 1, FamilyID: "family", Payload: payload, Active: true, ExpiresAt: time.Now().Add(time.Hour)}}
	root := NewMCPOAuthServer(repo, nil, &oauthFrontendFixture{url: "https://gateway.example"}, bytes.Repeat([]byte{3}, 32))
	server, err := root.Current(t.Context())
	require.NoError(t, err)
	return repo, server
}

// revocationRequest creates the encoded form consumed by real revocation handlers.
func revocationRequest(clientID, token, hint string) *http.Request {
	values := url.Values{"client_id": {clientID}, "token": {token}, "token_type_hint": {hint}}
	request := httptest.NewRequest(http.MethodPost, "https://gateway.example/mcp/oauth/revoke", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return request
}

// Transaction records success only after callback execution and simulated commit.
// Begin and commit failures are independent of callback errors, exposing protocol
// responses that incorrectly publish success before persistence has finished.
func (r *revocationRepository) Transaction(ctx context.Context, fn func(context.Context) error) error {
	if r.fail == "begin" {
		return errors.New("begin unavailable")
	}
	if err := fn(ctx); err != nil {
		return err
	}
	if r.fail == "commit" {
		return errors.New("commit unavailable")
	}
	r.committed = true
	return nil
}

// GetClient returns public fixture registrations or the selected client-storage failure.
func (r *revocationRepository) GetClient(_ context.Context, id string) (*identity.MCPOAuthClient, error) {
	if r.fail == "client" {
		return nil, errors.New("client storage unavailable")
	}
	if id == "unknown" {
		return nil, identity.ErrMCPTokenNotFound
	}
	client := *r.client
	client.ID = id
	return &client, nil
}

// GetSession returns matching ownership records with deterministic token-kind failures.
// Access normally falls through to refresh, allowing the fixture to exercise both
// a failed initial lookup followed by success and a failed fallback lookup.
func (r *revocationRepository) GetSession(_ context.Context, kind, _ string) (*identity.MCPOAuthSession, error) {
	if r.fail == kind {
		return nil, errors.New("session storage unavailable")
	}
	if r.record == nil || kind == "access" && r.fail != "refresh" {
		return nil, identity.ErrMCPTokenNotFound
	}
	return r.record, nil
}

// RevokeFamily counts family writes and fails the selected invalidation attempt.
func (r *revocationRepository) RevokeFamily(context.Context, string) error {
	r.writes++
	if r.fail == "revoke_first" && r.writes == 1 || r.fail == "revoke_second" && r.writes == 2 {
		return errors.New("revocation storage unavailable")
	}
	return nil
}
