package provider

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"

	"github.com/TokenFlux/TokenRouter/internal/identity"
	"github.com/TokenFlux/TokenRouter/internal/pkg/apperror"
)

// mcp_oauth.go issues application-bound credentials through the authorization-code
// and refresh flows. Fosite validates protocol credentials; this service owns
// canonical resource binding, administrator eligibility, browser consent, and
// transaction publication. The account's panel JWT is used only to approve a
// request and is never returned to an OAuth client as an MCP credential.
//
// A decision consumes its browser ticket, updates the stable application grant,
// invalidates earlier families, and creates a code in one SQL transaction.
// Token responses are written after commit. Replay detection is the exceptional
// error that commits revocation, while other failed exchanges roll back all
// mutations and return no usable credentials to the caller.

// MCPOAuthServer connects protocol validation to administrator grants and durable storage.
// @project-doc docs/interfaces/mcp_management.md#oauth_authorization
type MCPOAuthServer struct {
	repo   identity.MCPOAuthRepository // durable OAuth exchange repository
	users  identity.MCPUserReader      // current administrator account reader
	issuer string                      // canonical frontend origin for this request
	// frontend belongs to the root service; request instances clear it after
	// binding an origin so nested storage calls retain the same configuration.
	frontend   MCPOAuthFrontend
	secret     []byte                // independent persisted signing secret
	protocol   fosite.OAuth2Provider // enabled OAuth protocol handlers
	clientHTTP *http.Client          // bounded SSRF-protected metadata client
}

// MCPOAuthReview contains browser-safe request details and session-bound decision proof.
type MCPOAuthReview struct {
	Request *identity.MCPOAuthPending `json:"request"` // pending browser authorization request
	Nonce   string                    `json:"nonce"`   // session-bound one-time decision proof
	Grant   *identity.MCPOAuthGrant   `json:"grant"`   // previous live application authorization
}

// NewMCPOAuthServer binds the frontend address reader and persistent OAuth credentials.
// Current resolves an immutable protocol instance for each incoming request.
// The address reader must remain available throughout the server lifetime;
// failed reads deny OAuth access while grant management remains available.
func NewMCPOAuthServer(repo identity.MCPOAuthRepository, users identity.MCPUserReader, frontend MCPOAuthFrontend, secret []byte) *MCPOAuthServer {
	return &MCPOAuthServer{repo: repo, users: users, frontend: frontend, secret: append([]byte(nil), secret...), clientHTTP: newCIMDHTTPClient()}
}

// enableProtocol binds Fosite to this request's resolved frontend origin.
// Only Current calls this method on a private copy before publishing it.
// Credential stores therefore retain the same issuer through the complete exchange.
func (s *MCPOAuthServer) enableProtocol() {
	// Short access and code lifetimes bound leaked credentials; rotating refresh
	// families keep unattended connections usable until thirty days pass without renewal.
	config := &fosite.Config{
		GlobalSecret: s.secret, AccessTokenLifespan: 15 * time.Minute,
		AuthorizeCodeLifespan: 5 * time.Minute, RefreshTokenLifespan: 30 * 24 * time.Hour,
		EnforcePKCE: true, RefreshTokenScopes: []string{}, ScopeStrategy: fosite.ExactScopeStrategy,
	}
	s.protocol = compose.Compose(config, &oauthStore{server: s}, compose.NewOAuth2HMACStrategy(config), compose.OAuth2AuthorizeExplicitFactory, compose.OAuth2RefreshTokenGrantFactory, compose.OAuth2PKCEFactory, compose.OAuth2TokenRevocationFactory, compose.OAuth2TokenIntrospectionFactory)
}

// Enabled reports whether this request has a complete, resolved OAuth protocol.
func (s *MCPOAuthServer) Enabled() bool { return s != nil && s.protocol != nil && len(s.secret) >= 32 }

// Issuer returns the resolved frontend origin used for discovery and callbacks.
func (s *MCPOAuthServer) Issuer() string { return s.issuer }

// Resource returns the canonical MCP audience bound to every OAuth credential.
func (s *MCPOAuthServer) Resource() string { return s.issuer + "/mcp" }

// ListGrants reads application authorizations for a current administrator owner.
// This remains available when the frontend address is missing or invalid so
// administrators can inspect and revoke previously established application connections.
func (s *MCPOAuthServer) ListGrants(ctx context.Context, userID int64) ([]identity.MCPOAuthGrant, error) {
	if err := s.administrator(ctx, userID); err != nil {
		return nil, err
	}
	return s.repo.ListGrants(ctx, userID)
}

// UpdateGrant validates and conditionally replaces an administrator's application permissions.
// Callers validate operation identifiers against their mounted catalogue. An observed
// configuration version is required, and permanent revocation cannot be undone here.
func (s *MCPOAuthServer) UpdateGrant(ctx context.Context, userID, id int64, input identity.MCPTokenInput) (*identity.MCPOAuthGrant, error) {
	if err := s.administrator(ctx, userID); err != nil {
		return nil, err
	}
	if err := identity.ValidateMCPGrantInput(input); err != nil {
		return nil, err
	}
	if input.ExpectedUpdatedAt == nil {
		return nil, apperror.BadRequest("MCP_OAUTH_VERSION_REQUIRED", "Reload the application before saving")
	}
	input.Name = strings.TrimSpace(input.Name)
	if input.Permissions == nil {
		input.Permissions = []string{}
	}
	return s.repo.UpdateGrant(ctx, userID, id, input)
}

// RevokeGrant permanently disables an application owned by the current administrator.
// Existing access and refresh families are revoked together. An unavailable
// frontend URL does not prevent this owner-authorized management action.
func (s *MCPOAuthServer) RevokeGrant(ctx context.Context, userID, id int64) error {
	if err := s.administrator(ctx, userID); err != nil {
		return err
	}
	return s.repo.RevokeGrant(ctx, userID, id)
}

// Metadata returns the enabled flows and public endpoints advertised to OAuth clients.
func (s *MCPOAuthServer) Metadata() map[string]any {
	return map[string]any{
		"issuer":                   s.issuer,
		"authorization_endpoint":   s.issuer + "/mcp/oauth/authorize",
		"token_endpoint":           s.issuer + "/mcp/oauth/token",
		"registration_endpoint":    s.issuer + "/mcp/oauth/register",
		"revocation_endpoint":      s.issuer + "/mcp/oauth/revoke",
		"response_types_supported": []string{"code"},
		"response_modes_supported": []string{"query"},
		"grant_types_supported": []string{
			"authorization_code",
			"refresh_token",
		},
		"code_challenge_methods_supported": []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{
			"none",
			"client_secret_basic",
			"client_secret_post",
		},
		"scopes_supported": []string{
			"mcp",
			"offline_access",
		},
		"client_id_metadata_document_supported":          true,
		"authorization_response_iss_parameter_supported": true,
	}
}

// Start validates client parameters before saving a ticket and navigating to consent.
// Invalid redirect URIs receive a local protocol error. A validated callback can
// receive an OAuth error with state and issuer, never arbitrary request headers.
//
// The stored form retains the original PKCE challenge, resource, redirect, and
// state across the administrator login. Only the fields needed to reconstruct
// that validated request are persisted; unrelated query members cannot become
// credentials or change the later browser decision. The effective callback is
// stored separately so an omitted redirect parameter keeps its token-exchange
// meaning while the browser still sees the address selected during validation.
func (s *MCPOAuthServer) Start(w http.ResponseWriter, r *http.Request) {
	form, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !singleOAuthValues(form) {
		s.authorizeError(w, r, nil, fosite.ErrInvalidRequest)
		return
	}
	if form.Get("scope") == "" {
		form.Set("scope", "mcp")
	}
	r.URL.RawQuery = form.Encode()
	request, err := s.protocol.NewAuthorizeRequest(r.Context(), r)
	if err == nil {
		challenge, decodeErr := base64.RawURLEncoding.DecodeString(form.Get("code_challenge"))
		if form.Get("resource") != s.Resource() || form.Get("response_type") != "code" || form.Get("response_mode") != "" && form.Get("response_mode") != "query" || form.Get("code_challenge_method") != "S256" || decodeErr != nil || len(challenge) != 32 || !request.GetRequestedScopes().Has("mcp") || form.Get("request") != "" || form.Get("request_uri") != "" {
			err = fosite.ErrInvalidRequest
		}
	}
	if err != nil {
		s.authorizeError(w, r, request, err)
		return
	}
	client, err := s.client(r.Context(), request.GetClient().GetID())
	if err != nil {
		s.authorizeError(w, r, request, fosite.ErrInvalidClient)
		return
	}
	id, err := oauthRandom()
	if err != nil {
		s.authorizeError(w, r, request, fosite.ErrServerError)
		return
	}
	// Retain only the validated authorization fields. An attacker cannot smuggle
	// credential-shaped query values into persistent payloads or later browser responses.
	clean := url.Values{}
	for _, key := range []string{"client_id", "redirect_uri", "response_type", "scope", "state", "code_challenge", "code_challenge_method", "resource"} {
		if value := form.Get(key); value != "" {
			clean.Set(key, value)
		}
	}
	pending := &identity.MCPOAuthPending{ID: id, Form: clean, RedirectURI: request.GetRedirectURI().String(), Client: *client, ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}
	if err := s.repo.PutPending(r.Context(), pending); err != nil {
		s.authorizeError(w, r, request, fosite.ErrServerError)
		return
	}
	http.Redirect(w, r, s.issuer+"/admin/mcp/authorize?request="+url.QueryEscape(id), http.StatusFound)
}

// authorizeError sends a protocol error only to a previously validated callback.
// Invalid client or redirect inputs stay on the authorization server. Query
// encoding preserves the registered callback's existing parameters while adding
// the request state and the exact configured issuer identifier.
//
// The callback is taken from Fosite's validated request rather than directly
// from a query parameter. This distinction prevents validation failures from
// turning the authorization endpoint into an arbitrary redirect service.
func (s *MCPOAuthServer) authorizeError(w http.ResponseWriter, r *http.Request, request fosite.AuthorizeRequester, err error) {
	if request == nil {
		// Fosite's authorization-error writer requires a requester even before
		// parsing succeeds; an empty request keeps malformed input on this server.
		request = fosite.NewAuthorizeRequest()
	}
	if !request.IsRedirectURIValid() {
		s.protocol.WriteAuthorizeError(r.Context(), w, request, err)
		return
	}
	target := *request.GetRedirectURI()
	query := target.Query()
	query.Set("error", fosite.ErrorToRFC6749Error(err).ErrorField)
	query.Set("state", request.GetState())
	query.Set("iss", s.issuer)
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

// Review binds a pending request to the authenticated administrator's browser session.
// Repeated reads in the same session return the same nonce and current grants.
// Account switching or a different browser cannot claim an already bound request.
// Reconnecting after a site address change shows the same client's existing
// permissions; only a new decision can bind them to the current resource.
func (s *MCPOAuthServer) Review(ctx context.Context, id string, userID int64, sessionID string) (*MCPOAuthReview, error) {
	if err := s.administrator(ctx, userID); err != nil {
		return nil, err
	}
	if sessionID == "" {
		return nil, identity.ErrMCPTokenInvalid
	}
	request, err := s.repo.BindPending(ctx, id, userID, sessionID)
	if err != nil {
		return nil, err
	}
	if request.Form.Get("resource") != s.Resource() {
		return nil, apperror.BadRequest("MCP_OAUTH_REQUEST_INVALID", "Site address changed; reconnect")
	}
	grants, err := s.repo.ListGrants(ctx, userID)
	if err != nil {
		return nil, err
	}
	review := &MCPOAuthReview{Request: request, Nonce: s.nonce(id, userID, sessionID)}
	for _, grant := range grants {
		if grant.ClientID == request.Client.ID && grant.RevokedAt == nil {
			review.Grant = &grant
			break
		}
	}
	return review, nil
}

// Decide consumes browser consent and returns a validated client callback.
// The HTTP adapter validates selected operation IDs and recent TOTP beforehand.
// The administrator and nonce are checked before entering the decision transaction.
//
// Inside that transaction, consuming the ticket, updating the application grant,
// revoking earlier families, and storing the new code succeed together. Callback
// publication follows commit, so a persistence error cannot disclose a code for
// an incomplete grant. Denial consumes the same ticket and returns access_denied
// without creating an application authorization. Revalidation uses the callback
// selected at request creation, while code storage retains whether the client
// supplied redirect_uri so omission remains valid at the token endpoint.
func (s *MCPOAuthServer) Decide(ctx context.Context, id string, userID int64, sessionID, nonce string, approve bool, permissions []string) (string, error) {
	if err := s.administrator(ctx, userID); err != nil {
		return "", err
	}
	if sessionID == "" || !hmac.Equal([]byte(nonce), []byte(s.nonce(id, userID, sessionID))) {
		return "", apperror.BadRequest("MCP_OAUTH_NONCE_INVALID", "Authorization request changed; reload before approving")
	}
	var callback string
	err := s.repo.Transaction(ctx, func(ctx context.Context) error {
		pending, err := s.repo.ConsumePending(ctx, id, userID, sessionID)
		if err != nil {
			return err
		}
		if pending.Form.Get("resource") != s.Resource() {
			return apperror.BadRequest("MCP_OAUTH_REQUEST_INVALID", "Site address changed; reconnect")
		}
		// Pin the previously selected callback while checking current client metadata.
		// A changed sole registered callback must not silently replace the consent destination.
		form := maps.Clone(pending.Form)
		form.Set("redirect_uri", pending.RedirectURI)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.issuer+"/mcp/oauth/authorize?"+form.Encode(), nil)
		if err != nil {
			return err
		}
		request, err := s.protocol.NewAuthorizeRequest(ctx, req)
		if err != nil {
			return apperror.BadRequest("MCP_OAUTH_REQUEST_INVALID", "Application configuration changed; reconnect")
		}
		// Fosite compares the stored form during code redemption. Restore parameter
		// presence so clients that omitted redirect_uri can also omit it when exchanging.
		if values, exists := pending.Form["redirect_uri"]; exists {
			request.GetRequestForm()["redirect_uri"] = values
		} else {
			request.GetRequestForm().Del("redirect_uri")
		}
		target := *request.GetRedirectURI()
		query := target.Query()
		query.Set("iss", s.issuer)
		query.Set("state", request.GetState())
		if !approve {
			query.Set("error", "access_denied")
		} else {
			grant, err := s.repo.SaveGrant(ctx, userID, &pending.Client, s.Resource(), permissions)
			if err != nil {
				return err
			}
			for _, scope := range request.GetRequestedScopes() {
				request.GrantScope(scope)
			}
			request.GrantAudience(s.Resource())
			session := &oauthSession{GrantID: grant.ID, Issuer: s.issuer, Resource: s.Resource(), DefaultSession: fosite.DefaultSession{Subject: strconv.FormatInt(userID, 10)}}
			// The consumed ticket, new grant, and authorization code share this
			// transaction. Publishing the callback happens only after all three commit.
			response, err := s.protocol.NewAuthorizeResponse(ctx, request, session)
			if err != nil {
				return err
			}
			maps.Copy(query, response.GetParameters())
		}
		target.RawQuery = query.Encode()
		callback = target.String()
		return nil
	})
	return callback, err
}

// nonce derives browser decision proof from the request, administrator, and session.
// The separators keep those inputs distinct, and the independent OAuth secret
// prevents another browser from constructing proof for a session it does not own.
func (s *MCPOAuthServer) nonce(id string, userID int64, session string) string {
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(id + "\x00" + strconv.FormatInt(userID, 10) + "\x00" + session))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Token exchanges a code or refresh credential and publishes its response after commit.
// Normal protocol errors roll back mutations. Storage failures override a prepared
// successful response, and no access or refresh credential is returned before the
// exchange transaction commits.
//
// Storage serializes the application and family before Fosite consumes credentials.
// An inactive code or refresh token marks a request-local replay outcome; only a
// completed invalid-grant replay response commits its family revocation despite
// being an OAuth error. Other failures retain the callback's rollback behavior.
func (s *MCPOAuthServer) Token(w http.ResponseWriter, r *http.Request) {
	// Refresh requests may omit resource because their stored family already binds
	// the canonical audience. An explicit resource still has to match this deployment.
	err := r.ParseForm()
	resourceOK := r.PostForm.Get("resource") == s.Resource() || r.PostForm.Get("grant_type") == "refresh_token" && r.PostForm.Get("resource") == ""
	if err != nil || !singleOAuthValues(r.Form) || !resourceOK {
		s.protocol.WriteAccessError(r.Context(), w, nil, fosite.ErrInvalidRequest.WithHint("resource must match the MCP resource"))
		return
	}
	clientID := r.PostForm.Get("client_id")
	if id, _, ok := r.BasicAuth(); ok {
		decoded, err := url.QueryUnescape(id)
		if err != nil {
			s.protocol.WriteAccessError(r.Context(), w, nil, fosite.ErrInvalidClient)
			return
		}
		clientID = decoded
	}
	exchange := &oauthExchange{clientID: clientID}
	ctx := context.WithValue(r.Context(), oauthExchangeKey{}, exchange)
	var request fosite.AccessRequester
	var response fosite.AccessResponder
	var protocolErr error
	err = s.repo.Transaction(ctx, func(ctx context.Context) error {
		request, protocolErr = s.protocol.NewAccessRequest(ctx, r.WithContext(ctx), &oauthSession{})
		if protocolErr == nil {
			response, protocolErr = s.protocol.NewAccessResponse(ctx, request)
		}
		if protocolErr != nil && exchange.replay && errors.Is(protocolErr, fosite.ErrInvalidGrant) {
			return nil
		}
		return protocolErr
	})
	if err != nil {
		protocolErr = err
	}
	if protocolErr != nil {
		s.protocol.WriteAccessError(ctx, w, request, protocolErr)
		return
	}
	s.protocol.WriteAccessResponse(ctx, w, request, response)
}

// Revoke validates client ownership and atomically invalidates the submitted credential family.
// Unknown credentials retain OAuth's successful revocation response. The request-local
// outcome preserves storage errors even when Fosite's alternate token lookup succeeds.
//
// Client authentication still precedes credential discovery, but revocation does not
// require current application or administrator admission. Callback failures roll back
// mutations; storage failures receive OAuth 503, including failures before the callback
// or during commit. Responses are published only after the transaction returns so
// clients can retry revocation without assuming a credential was removed when the
// database did not confirm the final outcome.
func (s *MCPOAuthServer) Revoke(w http.ResponseWriter, r *http.Request) {
	revocation := &oauthRevocation{}
	ctx := context.WithValue(r.Context(), oauthRevocationKey{}, revocation)
	var protocolErr error
	err := s.repo.Transaction(ctx, func(ctx context.Context) error {
		protocolErr = s.protocol.NewRevocationRequest(ctx, r.WithContext(ctx))
		if revocation.err != nil {
			return revocation.err
		}
		return protocolErr
	})
	if err != nil {
		// Fosite's revocation writer treats most errors as successful revocations.
		// Preserve its client errors, but report persistence failures through its OAuth JSON writer.
		clientError := errors.Is(protocolErr, fosite.ErrInvalidRequest) || errors.Is(protocolErr, fosite.ErrInvalidClient) || errors.Is(protocolErr, fosite.ErrUnauthorizedClient)
		if revocation.err != nil || !clientError || !errors.Is(err, protocolErr) {
			s.protocol.WriteAccessError(ctx, w, nil, fosite.ErrTemporarilyUnavailable)
			return
		}
	}
	s.protocol.WriteRevocationResponse(ctx, w, protocolErr)
}

// Authenticate verifies an access credential and resolves its current application permissions.
// Issuer and resource are checked by storage before introspection. Refresh tokens
// cannot authenticate MCP even when Fosite identifies their credential type.
func (s *MCPOAuthServer) Authenticate(ctx context.Context, credential string) (*identity.MCPToken, error) {
	// Reject foreign credential formats before database lookup; the bounded length
	// also prevents oversized invalid Bearer values from reaching the protocol store.
	if len(credential) > 512 || !strings.HasPrefix(credential, "ory_at_") {
		return nil, identity.ErrMCPTokenInvalid
	}
	current, err := s.Current(ctx)
	if err != nil {
		return nil, identity.ErrMCPTokenInvalid
	}
	s = current
	kind, request, err := s.protocol.IntrospectToken(ctx, credential, fosite.AccessToken, &oauthSession{}, "mcp")
	if err != nil || kind != fosite.AccessToken {
		return nil, identity.ErrMCPTokenInvalid
	}
	session, ok := request.GetSession().(*oauthSession)
	if !ok {
		return nil, identity.ErrMCPTokenInvalid
	}
	token, err := s.AuthorizeGrant(ctx, session.GrantID)
	if err != nil {
		return nil, err
	}
	// Usage recording is observational; a failed timestamp write does not replace
	// successful credential validation or alter the configuration version used by confirmations.
	_ = s.repo.TouchGrant(ctx, session.GrantID)
	return token, nil
}

// AuthorizeGrant reloads application permissions and the current administrator account.
// Disabled, expired, revoked, or demoted owners cannot authorize later requests.
// Reading a stable grant does not require a particular rotating access credential.
// The account eligibility read uses the repository transaction context, allowing
// credential exchanges to complete using their already-held database connection.
func (s *MCPOAuthServer) AuthorizeGrant(ctx context.Context, id int64) (*identity.MCPToken, error) {
	current, err := s.Current(ctx)
	if err != nil {
		return nil, identity.ErrMCPTokenInvalid
	}
	s = current
	grant, err := s.repo.GetGrant(ctx, id)
	if err != nil || grant.Resource != s.Resource() || !grant.Enabled || grant.RevokedAt != nil || grant.ExpiresAt != nil && !time.Now().Before(*grant.ExpiresAt) {
		return nil, identity.ErrMCPTokenInvalid
	}
	allowed, err := s.repo.IsAdministrator(ctx, grant.UserID)
	if err != nil || !allowed {
		return nil, identity.ErrMCPTokenInvalid
	}
	return &grant.MCPToken, nil
}

// administrator rejects unavailable, disabled, deleted, or nonadministrator account owners.
func (s *MCPOAuthServer) administrator(ctx context.Context, id int64) error {
	user, err := s.users.GetByID(ctx, id)
	if err != nil || user == nil || !user.IsActive() || !user.IsAdmin() {
		return identity.ErrMCPTokenInvalid
	}
	return nil
}

// oauthRandom produces a URL-safe high-entropy request or registration credential.
func oauthRandom() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

// singleOAuthValues rejects ambiguous duplicate parameters and oversized parameter collections.
func singleOAuthValues(values url.Values) bool {
	if len(values) > 24 {
		return false
	}
	for _, items := range values {
		if len(items) != 1 || len(items[0]) > 4096 {
			return false
		}
	}
	return true
}

// WriteOAuthJSON writes a noncacheable OAuth response outside the management envelope.
func WriteOAuthJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	// Headers have already been sent, so a broken connection cannot safely
	// receive a replacement response or another registration attempt from this handler.
	_ = json.NewEncoder(w).Encode(value)
}
