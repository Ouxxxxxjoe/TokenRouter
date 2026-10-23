package provider

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"time"

	"github.com/ory/fosite"

	"github.com/TokenFlux/TokenRouter/internal/identity"
)

// mcp_oauth_store.go adapts sanitized Fosite requests to OAuth persistence.
// Credential records retain the stable application grant and family identity;
// raw credentials, PKCE verifiers, and confidential client secrets are excluded.
// Loading reconstructs the concrete session before Fosite performs expiration,
// signature, redirect, and PKCE validation. Current application permissions are
// checked separately from the protocol's granted scopes and audience.
//
// Replay errors must commit family revocation even though no token is issued.
// The request-local outcome marks that exceptional transaction result. Other
// protocol failures roll back consumed codes, PKCE state, and partially created
// tokens together, so a failed validation cannot publish reusable credentials.

// oauthExchangeKey carries request-local exchange metadata into Fosite storage calls.
type oauthExchangeKey struct{}

// oauthExchange records client binding and the decision to commit replay revocation.
type oauthExchange struct {
	clientID string // authenticated request client identifier
	replay   bool   // commit detected replay revocation
}

// oauthSession binds Fosite expiration data to one canonical application grant.
type oauthSession struct {
	fosite.DefaultSession        // OAuth subject and expiry values
	GrantID               int64  `json:"grant_id"` // stable application grant identifier
	Issuer                string `json:"issuer"`   // original exact issuer identifier
	Resource              string `json:"resource"` // original canonical protected resource
}

// oauthStore connects Fosite's credential operations with the owning OAuth service.
type oauthStore struct {
	server *MCPOAuthServer // immutable OAuth service reference
}

// Clone copies session maps before refresh changes expiration or granted claims.
func (s *oauthSession) Clone() fosite.Session {
	cloned := *s
	cloned.ExpiresAt = maps.Clone(s.ExpiresAt)
	cloned.Extra = maps.Clone(s.Extra)
	return &cloned
}

// GetClient resolves validated metadata and returns Fosite's client authentication representation.
func (s *oauthStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	client, err := s.server.client(ctx, id)
	if err != nil {
		return nil, fosite.ErrInvalidClient
	}
	return &fosite.DefaultOpenIDConnectClient{DefaultClient: &fosite.DefaultClient{
		ID:            client.ID,
		Secret:        client.SecretHash,
		RedirectURIs:  client.RedirectURIs,
		GrantTypes:    client.GrantTypes,
		ResponseTypes: []string{"code"},
		Scopes: []string{
			"mcp",
			"offline_access",
		},
		Audience: []string{s.server.Resource()},
		Public:   client.AuthMethod == "none",
	}, TokenEndpointAuthMethod: client.AuthMethod}, nil
}

// ClientAssertionJWTValid rejects unsupported client assertion authentication before accepting state.
func (s *oauthStore) ClientAssertionJWTValid(context.Context, string) error {
	return fosite.ErrInvalidClient
}

// SetClientAssertionJWT rejects assertion persistence because JWT client authentication is disabled.
func (s *oauthStore) SetClientAssertionJWT(context.Context, string, time.Time) error {
	return fosite.ErrInvalidClient
}

// save removes sensitive form members before serializing protocol request state.
// The session type is owned by this service. Each credential's expiry is persisted
// while family cleanup retains older consumed records for replay detection.
//
// The request keeps its redirect and PKCE challenge for subsequent verification,
// while raw codes, refresh tokens, client secrets, and verifiers are excluded.
// Only the client identifier is stored in the serialized client value; loading
// resolves current registration metadata instead of restoring authentication keys
// or stale client policy from an earlier exchange.
func (s *oauthStore) save(ctx context.Context, kind, signature string, request fosite.Requester) error {
	session, ok := request.GetSession().(*oauthSession)
	if !ok {
		return fosite.ErrServerError
	}
	clean, ok := request.Sanitize([]string{"redirect_uri", "code_challenge", "code_challenge_method"}).(*fosite.Request)
	if !ok {
		return fosite.ErrServerError
	}
	clean.Client = &fosite.DefaultClient{ID: request.GetClient().GetID()}
	payload, err := json.Marshal(clean)
	if err != nil {
		return err
	}
	tokenType := fosite.AccessToken
	if kind == "refresh" {
		tokenType = fosite.RefreshToken
	}
	if kind == "code" || kind == "pkce" {
		tokenType = fosite.AuthorizeCode
	}
	return s.server.repo.PutSession(ctx, &identity.MCPOAuthSession{
		Kind:      kind,
		Signature: signature,
		FamilyID:  request.GetID(),
		GrantID:   session.GrantID,
		Payload:   payload,
		ExpiresAt: session.GetExpiresAt(tokenType),
		Active:    true,
	})
}

// load reconstructs a credential request and checks its client, issuer, and grant.
// Storage acquires the application and family locks during an exchange before
// returning current state. The concrete session is restored before Fosite verifies
// its signature, expiration, redirect, and PKCE requirements.
//
// Inactive code and refresh records return the original requester with Fosite's
// replay error so revocation can identify the complete family. Other inactive
// records are unavailable. Active records require an unexpired deadline and a
// currently authorized administrator, then resolve current client metadata.
func (s *oauthStore) load(ctx context.Context, kind, signature string) (fosite.Requester, error) {
	record, err := s.server.repo.GetSession(ctx, kind, signature)
	if errors.Is(err, identity.ErrMCPTokenNotFound) {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	request := &fosite.Request{Client: &fosite.DefaultClient{}, Session: &oauthSession{}}
	if err := json.Unmarshal(record.Payload, request); err != nil {
		return nil, err
	}
	session, ok := request.Session.(*oauthSession)
	if !ok || session == nil || request.Client == nil || session.GrantID != record.GrantID || request.ID != record.FamilyID {
		return nil, fosite.ErrNotFound
	}
	exchange, _ := ctx.Value(oauthExchangeKey{}).(*oauthExchange)
	if session.Issuer != s.server.issuer || session.Resource != s.server.Resource() || exchange != nil && exchange.clientID != request.Client.GetID() {
		return nil, fosite.ErrNotFound
	}
	if !record.Active {
		if kind == "refresh" || kind == "code" {
			if exchange != nil {
				exchange.replay = true
			}
			if kind == "code" {
				return request, fosite.ErrInvalidatedAuthorizeCode
			}
			return request, fosite.ErrInactiveToken
		}
		return nil, fosite.ErrNotFound
	}
	if !time.Now().Before(record.ExpiresAt) {
		return nil, fosite.ErrNotFound
	}
	if _, err := s.server.AuthorizeGrant(ctx, record.GrantID); err != nil {
		return nil, fosite.ErrNotFound
	}
	client, err := s.GetClient(ctx, request.Client.GetID())
	if err != nil {
		return nil, err
	}
	request.Client = client
	return request, nil
}

// CreateAuthorizeCodeSession persists a sanitized code request under its irreversible signature.
func (s *oauthStore) CreateAuthorizeCodeSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.save(ctx, "code", signature, request)
}

// GetAuthorizeCodeSession reconstructs the stored code request after current authorization checks.
func (s *oauthStore) GetAuthorizeCodeSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	return s.load(ctx, "code", signature)
}

// InvalidateAuthorizeCodeSession retains the code record while marking its credential inactive.
func (s *oauthStore) InvalidateAuthorizeCodeSession(ctx context.Context, signature string) error {
	return s.server.repo.InvalidateSession(ctx, "code", signature)
}

// CreateAccessTokenSession persists a sanitized access request under its irreversible signature.
func (s *oauthStore) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.save(ctx, "access", signature, request)
}

// GetAccessTokenSession reconstructs the stored access request after current authorization checks.
func (s *oauthStore) GetAccessTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	return s.load(ctx, "access", signature)
}

// DeleteAccessTokenSession retains the access record while marking its credential inactive.
func (s *oauthStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return s.server.repo.InvalidateSession(ctx, "access", signature)
}

// CreateRefreshTokenSession persists a sanitized refresh request under its irreversible signature.
func (s *oauthStore) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, request fosite.Requester) error {
	return s.save(ctx, "refresh", signature, request)
}

// GetRefreshTokenSession reconstructs the stored refresh request after current authorization checks.
func (s *oauthStore) GetRefreshTokenSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	return s.load(ctx, "refresh", signature)
}

// DeleteRefreshTokenSession retains the refresh record while marking its credential inactive.
func (s *oauthStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return s.server.repo.InvalidateSession(ctx, "refresh", signature)
}

// CreatePKCERequestSession persists a sanitized pkce request under its irreversible signature.
func (s *oauthStore) CreatePKCERequestSession(ctx context.Context, signature string, request fosite.Requester) error {
	return s.save(ctx, "pkce", signature, request)
}

// GetPKCERequestSession reconstructs the stored pkce request after current authorization checks.
func (s *oauthStore) GetPKCERequestSession(ctx context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	return s.load(ctx, "pkce", signature)
}

// DeletePKCERequestSession retains the pkce record while marking its credential inactive.
func (s *oauthStore) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return s.server.repo.InvalidateSession(ctx, "pkce", signature)
}

// RotateRefreshToken consumes the previous credential before its replacement is persisted.
// The exchange holds the family's transaction lock from its first read through
// commit, so another refresh observes this transition before it can issue tokens.
func (s *oauthStore) RotateRefreshToken(ctx context.Context, _ string, signature string) error {
	return s.server.repo.InvalidateSession(ctx, "refresh", signature)
}

// RevokeRefreshToken invalidates every credential belonging to the supplied family identifier.
func (s *oauthStore) RevokeRefreshToken(ctx context.Context, id string) error {
	return s.server.repo.RevokeFamily(ctx, id)
}

// RevokeAccessToken invalidates every credential belonging to the supplied family identifier.
func (s *oauthStore) RevokeAccessToken(ctx context.Context, id string) error {
	return s.server.repo.RevokeFamily(ctx, id)
}
