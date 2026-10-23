package authctx

import "context"

// mcp.go carries server-created dispatch identity through an internal HTTP
// request. External headers cannot populate the private context key. The
// administrator middleware rechecks the token and matched route before it
// installs the ordinary Gin principal consumed by existing handlers.

// mcpDispatchKey prevents external text headers from representing an internal dispatch.
type mcpDispatchKey struct{}

// MCPDispatch binds a verified MCP credential to one canonical administrative route.
type MCPDispatch struct {
	Source      string // credential authorization source discriminator
	Credential  string // request-local OAuth access credential
	TokenID     int64  // verified credential identifier
	OperationID string // authorized operation identifier
	Method      string // expected HTTP method
	Route       string // expected Gin route pattern
	SessionID   string // approved browser session identifier
	// TokenVersion pins approved and direct sensitive calls to their admitted
	// configuration. Ordinary dispatches leave it empty and still recheck current grants.
	TokenVersion string
	// ConfirmationSkipped marks sensitive calls admitted by the token's opt-in
	// preference. Ordinary routes and calls with browser approval leave it false.
	ConfirmationSkipped bool
}

// WithMCPDispatch attaches server-verified dispatch metadata to a derived request context.
// Callers supply metadata after token authorization; the receiving middleware
// still checks live grants and the selected route before admitting the request.
func WithMCPDispatch(ctx context.Context, dispatch MCPDispatch) context.Context {
	return context.WithValue(ctx, mcpDispatchKey{}, dispatch)
}

// GetMCPDispatch returns dispatch metadata installed by the in-process MCP executor.
func GetMCPDispatch(ctx context.Context) (MCPDispatch, bool) {
	dispatch, ok := ctx.Value(mcpDispatchKey{}).(MCPDispatch)
	return dispatch, ok
}
