package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/TokenFlux/TokenRouter/internal/identity"
	"github.com/TokenFlux/TokenRouter/internal/identity/httpapi/authctx"
	"github.com/TokenFlux/TokenRouter/internal/identity/provider"
	"github.com/TokenFlux/TokenRouter/internal/server/adminapi"
	"github.com/TokenFlux/TokenRouter/internal/server/httpx"
)

// oauth.go mounts public OAuth protocol endpoints and administrator consent APIs.
// Protocol endpoints return OAuth JSON directly, while browser administration
// uses the existing authenticated envelope, permission catalogue, and audit chain.
// A real administrator JWT session is required for every browser operation;
// neither an MCP credential nor a management API key can approve an application.
//
// Public exchange limits are independent from authenticated MCP request limits.
// The configured issuer supplies every discovery URL and audience. Browser
// requests refer to a stored authorization request and session-bound nonce, so
// submitted client names, callback URLs, or permission strings cannot replace
// the protocol parameters validated before the consent page was opened.

// Browser-only OAuth operations participate in catalogue coverage and OpenAPI
// while rejecting internal MCP dispatch even when a caller holds their identifiers.
var oauthOperations = map[string]*adminapi.Operation{
	"status": adminapi.Define(adminapi.Operation{
		ID:          "mcp.oauth.status",
		Module:      "mcp",
		Title:       "Read OAuth connection settings",
		TitleZH:     "查看 OAuth 连接配置",
		Description: "Read OAuth availability and the canonical MCP endpoint in the administrator browser.",
		Method:      "GET",
		Path:        "/api/v1/admin/mcp/oauth/status",
		ReadOnly:    true,
		Response:    adminapi.ResponseBrowser,
		BrowserPath: "/admin/mcp",
		Input:       adminapi.Arguments("/api/v1/admin/mcp/oauth/status", nil, nil),
	}),
	"requests.get": adminapi.Define(adminapi.Operation{
		ID:          "mcp.oauth.requests.get",
		Module:      "mcp",
		Title:       "Review application authorization",
		TitleZH:     "查看应用授权请求",
		Description: "Review a session-bound application authorization request in the administrator browser.",
		Method:      "GET",
		Path:        "/api/v1/admin/mcp/oauth/requests/:id",
		Response:    adminapi.ResponseBrowser,
		BrowserPath: "/admin/mcp",
		Input:       adminapi.Arguments("/api/v1/admin/mcp/oauth/requests/:id", nil, nil),
	}),
	"requests.decide": adminapi.Define(adminapi.Operation{
		ID:          "mcp.oauth.requests.decide",
		Module:      "mcp",
		Title:       "Authorize an application",
		TitleZH:     "决定应用授权",
		Description: "Approve or reject an OAuth application using the current administrator browser session.",
		Method:      "POST",
		Path:        "/api/v1/admin/mcp/oauth/requests/:id/decision",
		Sensitive:   true,
		Response:    adminapi.ResponseBrowser,
		BrowserPath: "/admin/mcp",
		Input:       adminapi.Arguments("/api/v1/admin/mcp/oauth/requests/:id/decision", nil, (*oauthDecision)(nil)),
	}),
	"grants.list": adminapi.Define(adminapi.Operation{
		ID:          "mcp.oauth.grants.list",
		Module:      "mcp",
		Title:       "List authorized applications",
		TitleZH:     "查询已授权应用",
		Description: "List this administrator's application grants in the browser.",
		Method:      "GET",
		Path:        "/api/v1/admin/mcp/oauth/grants",
		ReadOnly:    true,
		Response:    adminapi.ResponseBrowser,
		BrowserPath: "/admin/mcp",
		Input:       adminapi.Arguments("/api/v1/admin/mcp/oauth/grants", nil, nil),
	}),
	"grants.update": adminapi.Define(adminapi.Operation{
		ID:          "mcp.oauth.grants.update",
		Module:      "mcp",
		Title:       "Update application authorization",
		TitleZH:     "修改应用授权",
		Description: "Replace an owned application's permissions and confirmation policy after browser verification.",
		Method:      "PUT",
		Path:        "/api/v1/admin/mcp/oauth/grants/:id",
		Sensitive:   true,
		Response:    adminapi.ResponseBrowser,
		BrowserPath: "/admin/mcp",
		Input:       adminapi.Arguments("/api/v1/admin/mcp/oauth/grants/:id", nil, (*identity.MCPTokenInput)(nil)),
	}),
	"grants.revoke": adminapi.Define(adminapi.Operation{
		ID:          "mcp.oauth.grants.revoke",
		Module:      "mcp",
		Title:       "Revoke application authorization",
		TitleZH:     "撤销应用授权",
		Description: "Permanently revoke an owned application and its credential families.",
		Method:      "DELETE",
		Path:        "/api/v1/admin/mcp/oauth/grants/:id",
		Sensitive:   true,
		Response:    adminapi.ResponseBrowser,
		BrowserPath: "/admin/mcp",
		Input:       adminapi.Arguments("/api/v1/admin/mcp/oauth/grants/:id", nil, nil),
	}),
}

// oauthDecision carries the browser's permission choice and session-bound decision proof.
type oauthDecision struct {
	Approve     bool     `json:"approve"`     // approval or denial choice
	Nonce       string   `json:"nonce"`       // session-bound one-time decision proof
	Permissions []string `json:"permissions"` // selected exact operation identifiers
}

// mountOAuth registers discovery and exchange routes when OAuth is configured.
// Browser management remains mounted while disabled so administrators can inspect
// and revoke previous grants. Protocol routes never fall through to the SPA.
func (h *Handler) mountOAuth(router *gin.Engine, group *gin.RouterGroup) {
	adminapi.Register(group, oauthOperations["status"], h.oauthStatus)
	adminapi.Register(group, oauthOperations["requests.get"], h.oauthReview)
	adminapi.Register(group, oauthOperations["requests.decide"], h.oauthDecide)
	adminapi.Register(group, oauthOperations["grants.list"], h.oauthGrants)
	adminapi.Register(group, oauthOperations["grants.update"], h.oauthUpdate)
	adminapi.Register(group, oauthOperations["grants.revoke"], h.oauthRevokeGrant)
	if h.options.OAuth == nil || !h.options.OAuth.Enabled() {
		return
	}
	server := h.options.OAuth
	resource := func(c *gin.Context) {
		provider.WriteOAuthJSON(c.Writer, 200, gin.H{
			"resource":                 server.Resource(),
			"authorization_servers":    []string{server.Issuer()},
			"scopes_supported":         []string{"mcp"},
			"bearer_methods_supported": []string{"header"},
		})
	}
	router.GET("/.well-known/oauth-protected-resource", resource)
	router.GET("/.well-known/oauth-protected-resource/mcp", resource)
	router.GET("/.well-known/oauth-authorization-server", func(c *gin.Context) { provider.WriteOAuthJSON(c.Writer, 200, server.Metadata()) })
	router.GET("/mcp/oauth/authorize", h.oauthLimit("authorize", 30), func(c *gin.Context) {
		base := h.browserLink(c.Request.Context(), "")
		server.Start(c.Writer, c.Request, base)
	})
	router.POST("/mcp/oauth/register", h.oauthLimit("register", 10), func(c *gin.Context) { server.Register(c.Writer, c.Request) })
	router.POST("/mcp/oauth/token", h.oauthLimit("token", 60), func(c *gin.Context) { server.Token(c.Writer, c.Request) })
	router.POST("/mcp/oauth/revoke", h.oauthLimit("revoke", 60), func(c *gin.Context) { server.Revoke(c.Writer, c.Request) })
}

// oauthLimit bounds unauthenticated protocol traffic by trusted client address and route.
// Missing or failed shared limits reject the request. Request bodies and URLs
// have smaller bounds than management tool payloads, and responses forbid caching.
func (h *Handler) oauthLimit(operation string, limit int) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Header("Referrer-Policy", "no-referrer")
		if len(c.Request.URL.RawQuery) > 16384 {
			provider.WriteOAuthJSON(c.Writer, 400, gin.H{"error": "invalid_request"})
			c.Abort()
			return
		}
		if c.Request.Method == http.MethodPost {
			expected := "application/x-www-form-urlencoded"
			if operation == "register" {
				expected = "application/json"
			}
			mediaType, _, mediaErr := mime.ParseMediaType(c.GetHeader("Content-Type"))
			if mediaErr != nil || mediaType != expected || c.Request.URL.RawQuery != "" {
				provider.WriteOAuthJSON(c.Writer, 400, gin.H{"error": "invalid_request"})
				c.Abort()
				return
			}
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 32768)
		digest := sha256.Sum256([]byte(c.ClientIP()))
		if h.options.Limiter == nil {
			provider.WriteOAuthJSON(c.Writer, 503, gin.H{"error": "temporarily_unavailable"})
			c.Abort()
			return
		}
		allowed, _, retry, err := h.options.Limiter.Allow(c.Request.Context(), "oauth:"+operation+":"+hex.EncodeToString(digest[:]), limit, time.Minute)
		if err != nil {
			provider.WriteOAuthJSON(c.Writer, 503, gin.H{"error": "temporarily_unavailable"})
			c.Abort()
			return
		}
		if !allowed {
			c.Header("Retry-After", strconv.Itoa(max(1, int(retry.Seconds())+1)))
			provider.WriteOAuthJSON(c.Writer, 429, gin.H{"error": "temporarily_unavailable"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// oauthBrowser checks a real browser session before exposing OAuth management state.
func (h *Handler) oauthBrowser(c *gin.Context) bool {
	if !browserSession(c) {
		return false
	}
	c.Header("Cache-Control", "no-store")
	if h.options.OAuth == nil {
		httpx.ErrorWithDetails(c, 503, "OAuth is unavailable", "MCP_OAUTH_UNAVAILABLE", nil)
		return false
	}
	return true
}

// oauthStatus returns configured connection information without exposing any signing material.
func (h *Handler) oauthStatus(c *gin.Context) {
	if !browserSession(c) {
		return
	}
	result := gin.H{"enabled": false, "issuer": "", "resource": ""}
	if server := h.options.OAuth; server != nil && server.Enabled() {
		result = gin.H{"enabled": true, "issuer": server.Issuer(), "resource": server.Resource()}
	}
	httpx.Success(c, result)
}

// oauthReview returns a validated request, existing grants, and available operation choices.
func (h *Handler) oauthReview(c *gin.Context) {
	if !h.oauthBrowser(c) {
		return
	}
	if !h.options.OAuth.Enabled() {
		httpx.ErrorWithDetails(c, 503, "OAuth is disabled", "MCP_OAUTH_UNAVAILABLE", nil)
		return
	}
	principal, _ := authctx.GetPrincipal(c)
	review, err := h.options.OAuth.Review(c.Request.Context(), c.Param("id"), principal.UserID, principal.SessionID)
	if err != nil {
		httpx.ErrorFrom(c, err)
		return
	}
	httpx.Success(c, gin.H{
		"request":      review.Request,
		"nonce":        review.Nonce,
		"grant":        review.Grant,
		"operations":   h.catalog.Operations(),
		"redirect_uri": review.Request.Form.Get("redirect_uri"),
	})
}

// oauthDecide consumes an administrator's approval after validating every chosen operation.
// Approval follows the existing recent-TOTP policy; denial remains available
// without step-up. The returned callback comes exclusively from the stored request.
func (h *Handler) oauthDecide(c *gin.Context) {
	if !h.oauthBrowser(c) {
		return
	}
	if !h.options.OAuth.Enabled() {
		httpx.ErrorWithDetails(c, 503, "OAuth is disabled", "MCP_OAUTH_UNAVAILABLE", nil)
		return
	}
	var input oauthDecision
	if httpx.BindJSONStrict(c, &input) != nil {
		httpx.BadRequest(c, "Invalid authorization decision")
		return
	}
	if input.Approve {
		if len(input.Permissions) == 0 {
			httpx.BadRequest(c, "Select at least one permission")
			return
		}
		for _, id := range input.Permissions {
			if _, ok := h.catalog.Get(id); !ok {
				httpx.BadRequest(c, "Unknown operation permission")
				return
			}
		}
		if !h.checkBrowserStepUp(c) {
			return
		}
	}
	principal, _ := authctx.GetPrincipal(c)
	target, err := h.options.OAuth.Decide(c.Request.Context(), c.Param("id"), principal.UserID, principal.SessionID, input.Nonce, input.Approve, input.Permissions)
	if err != nil {
		httpx.ErrorFrom(c, err)
		return
	}
	httpx.Success(c, gin.H{"redirect_uri": target})
}

// oauthGrants lists application metadata belonging to the authenticated browser administrator.
func (h *Handler) oauthGrants(c *gin.Context) {
	if !h.oauthBrowser(c) {
		return
	}
	items, err := h.options.OAuth.ListGrants(c.Request.Context(), administrator(c))
	if err != nil {
		httpx.ErrorFrom(c, err)
		return
	}
	httpx.Success(c, items)
}

// oauthUpdate conditionally replaces an owned application's validated authorization settings.
func (h *Handler) oauthUpdate(c *gin.Context) {
	if !h.oauthBrowser(c) || !h.checkBrowserStepUp(c) {
		return
	}
	id, ok := tokenID(c)
	if !ok {
		return
	}
	input, ok := h.tokenInput(c)
	if !ok {
		return
	}
	grant, err := h.options.OAuth.UpdateGrant(c.Request.Context(), administrator(c), id, input)
	if err != nil {
		httpx.ErrorFrom(c, err)
		return
	}
	traceRelatedToken(c, &grant.MCPToken, "mcp.oauth.grants.update")
	httpx.Success(c, grant)
}

// oauthRevokeGrant permanently revokes the selected application's grants and credential families.
func (h *Handler) oauthRevokeGrant(c *gin.Context) {
	if !h.oauthBrowser(c) || !h.checkBrowserStepUp(c) {
		return
	}
	id, ok := tokenID(c)
	if !ok {
		return
	}
	if err := h.options.OAuth.RevokeGrant(c.Request.Context(), administrator(c), id); err != nil {
		httpx.ErrorFrom(c, err)
		return
	}
	c.Set("mcp_related_token_prefix", "oauth:"+strconv.FormatInt(id, 10))
	c.Set("mcp_related_operation_id", "mcp.oauth.grants.revoke")
	c.Set("mcp_related_source", "oauth")
	c.Set("mcp_related_token_id", id)
	httpx.Success(c, gin.H{"revoked": true})
}
