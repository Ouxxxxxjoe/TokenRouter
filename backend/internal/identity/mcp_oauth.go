package identity

import (
	"context"
	"encoding/json"
	"net/url"
	"time"
)

// mcp_oauth.go defines persisted application grants and OAuth exchange records.
// Application identity survives access-token rotation, allowing confirmations
// and files to reference the same permission owner throughout a connection.
// Credential signatures and protocol payloads remain separate from browser DTOs.
// The repository serializes exchanges within a credential family and makes each
// authorization decision conditional on its authenticated browser session.
//
// Manual credentials keep their existing numeric identifiers. OAuth references
// add a source discriminator so equal identifiers from independent tables cannot
// share permissions, rate limits, confirmations, or downloaded results. Empty
// source values identify manual credentials in existing temporary Redis records.

// MCPOAuthResolver verifies OAuth credentials and resolves stable application grants.
type MCPOAuthResolver interface {
	// Authenticate checks a complete access credential and its current application grant.
	Authenticate(context.Context, string) (*MCPToken, error)
	// AuthorizeGrant reads live application permissions for a previously verified identifier.
	AuthorizeGrant(context.Context, int64) (*MCPToken, error)
}

// MCPOAuthClient contains registered or HTTPS-discovered client metadata and authentication material.
type MCPOAuthClient struct {
	ID           string   `json:"client_id"`                  // exact registered client identifier
	Name         string   `json:"client_name"`                // untrusted application display name
	RedirectURIs []string `json:"redirect_uris"`              // permitted exact callback addresses
	GrantTypes   []string `json:"grant_types"`                // permitted OAuth grant types
	AuthMethod   string   `json:"token_endpoint_auth_method"` // registered client authentication method
	SecretHash   []byte   `json:"-"`                          // irreversible confidential client verifier
	// ExpiresAt is absent for immutable dynamic registrations. Discovered client
	// documents may be reused only while this cached metadata deadline is unexpired.
	ExpiresAt *time.Time `json:"-"` // discovered metadata cache expiry
}

// MCPOAuthGrant joins application metadata to the shared MCP permission representation.
type MCPOAuthGrant struct {
	MCPToken                       // stable application authorization settings
	ClientID            string     `json:"client_id"`             // exact authorized client identifier
	ClientName          string     `json:"client_name"`           // latest consented application name
	Resource            string     `json:"resource"`              // authorized canonical MCP resource
	ConnectionExpiresAt *time.Time `json:"connection_expires_at"` // latest active credential expiry
}

// MCPOAuthPending retains a validated authorization request until one browser decides it.
type MCPOAuthPending struct {
	ID        string         `json:"id"`         // opaque browser request identifier
	Form      url.Values     `json:"-"`          // validated noncredential authorization parameters
	Client    MCPOAuthClient `json:"client"`     // validated public client metadata
	UserID    int64          `json:"-"`          // bound approving administrator identifier
	SessionID string         `json:"-"`          // bound authenticated browser session
	ExpiresAt time.Time      `json:"expires_at"` // absolute authorization request deadline
	Consumed  bool           `json:"-"`          // permanently completed decision marker
}

// MCPOAuthSession stores a protocol request under an irreversible credential signature.
type MCPOAuthSession struct {
	Kind      string          // code pkce access or refresh
	Signature string          // irreversible protocol credential signature
	FamilyID  string          // shared credential family identifier
	GrantID   int64           // stable application grant identifier
	Payload   json.RawMessage // sanitized serialized protocol request
	ExpiresAt time.Time       // validation and cleanup deadline
	Active    bool            // unused or unrevoked credential state
}

// MCPOAuthRepository owns atomic exchanges, consent decisions, and uncached grant reads.
type MCPOAuthRepository interface {
	// Transaction commits the callback on success and rolls back every returned error.
	// Implementations propagate the transaction through context; callbacks must keep
	// all exchange mutations on that context and publish credentials after commit.
	Transaction(context.Context, func(context.Context) error) error
	// PutClient persists verified metadata, preserving an existing client's immutable registration.
	PutClient(context.Context, *MCPOAuthClient) error
	// GetClient reads a registered or unexpired discovered client by exact identifier.
	GetClient(context.Context, string) (*MCPOAuthClient, error)
	// PutPending saves one validated authorization request before browser navigation begins.
	PutPending(context.Context, *MCPOAuthPending) error
	// BindPending binds and reads an unconsumed request for this browser session.
	BindPending(context.Context, string, int64, string) (*MCPOAuthPending, error)
	// ConsumePending locks and consumes a request belonging to the supplied browser session.
	ConsumePending(context.Context, string, int64, string) (*MCPOAuthPending, error)
	// SaveGrant creates or updates this client's live grant and invalidates previous credentials.
	SaveGrant(context.Context, int64, *MCPOAuthClient, string, []string) (*MCPOAuthGrant, error)
	// GetGrant reads current grant metadata including its latest active connection expiry.
	GetGrant(context.Context, int64) (*MCPOAuthGrant, error)
	// ListGrants reads application authorizations owned by one authenticated administrator.
	ListGrants(context.Context, int64) ([]MCPOAuthGrant, error)
	// UpdateGrant conditionally replaces settings on an owned, permanently unrevoked grant.
	UpdateGrant(context.Context, int64, int64, MCPTokenInput) (*MCPOAuthGrant, error)
	// RevokeGrant permanently revokes an owned grant and its credential families.
	RevokeGrant(context.Context, int64, int64) error
	// PutSession persists one sanitized request under its protocol credential signature.
	PutSession(context.Context, *MCPOAuthSession) error
	// GetSession reads credential state and serializes its family inside exchange transactions.
	GetSession(context.Context, string, string) (*MCPOAuthSession, error)
	// InvalidateSession marks a credential consumed while retaining its replay detection record.
	InvalidateSession(context.Context, string, string) error
	// RevokeFamily invalidates every credential belonging to this exact exchange family.
	RevokeFamily(context.Context, string) error
	// TouchGrant records admission without changing the application configuration version.
	TouchGrant(context.Context, int64) error
	// Cleanup removes expired requests and families with no unexpired credentials.
	Cleanup(context.Context) error
}
