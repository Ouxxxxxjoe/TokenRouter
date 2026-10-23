package httpapi

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/TokenFlux/TokenRouter/internal/identity"
	"github.com/TokenFlux/TokenRouter/internal/identity/httpapi/authctx"
)

// mcp_auth.go admits server-created MCP dispatches through the ordinary
// administrator route chain. Fresh token and owner reads keep permissions
// consistent with revocation and account changes between discovery and execution.
// Public requests without the private context record use normal authentication,
// so MCP credentials do not become REST administrator credentials.

// MCPAdminAuth accepts a route-bound internal dispatch or delegates public
// requests to normal administrator authentication. Approval sessions belong to
// the validated token owner and remain subject to the existing step-up middleware.
func MCPAdminAuth(tokens *identity.MCPTokenService, normal gin.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		dispatch, internal := authctx.GetMCPDispatch(c.Request.Context())
		if !internal {
			normal(c)
			return
		}
		if dispatch.Route != c.FullPath() || dispatch.Method != c.Request.Method {
			AbortWithError(c, 403, "MCP_ROUTE_MISMATCH", "Operation does not match the selected route")
			return
		}
		token, user, err := tokens.AuthorizeReference(c.Request.Context(), dispatch.Source, dispatch.TokenID, dispatch.Credential)
		if err != nil || !token.Allows(dispatch.OperationID) {
			AbortWithError(c, 403, "MCP_OPERATION_FORBIDDEN", "Operation is not authorized")
			return
		}
		if dispatch.TokenVersion != "" && token.UpdatedAt.UTC().Format(time.RFC3339Nano) != dispatch.TokenVersion {
			AbortWithError(c, 403, "MCP_APPROVAL_STALE", "Token settings changed before execution")
			return
		}
		authctx.SetPrincipal(c, identity.Principal{UserID: user.ID, Role: user.Role, CredentialKind: "mcp_token", SessionID: dispatch.SessionID}, user.Concurrency, user.Email)
		c.Set("auth_method", "mcp_token")
		c.Set("mcp_token_prefix", token.Prefix)
		c.Next()
	}
}
