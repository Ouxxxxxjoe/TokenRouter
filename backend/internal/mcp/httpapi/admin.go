package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/TokenFlux/TokenRouter/internal/identity"
	"github.com/TokenFlux/TokenRouter/internal/identity/httpapi/authctx"
	control "github.com/TokenFlux/TokenRouter/internal/mcp"
	"github.com/TokenFlux/TokenRouter/internal/server/adminapi"
	"github.com/TokenFlux/TokenRouter/internal/server/httpx"
)

// admin.go manages dedicated MCP credentials and completes browser-only
// confirmations and file downloads. Existing administrator authentication runs
// before these handlers. Each stored object is also checked against the current
// administrator and live token grants, so knowing an opaque workflow identifier
// cannot authorize approval or disclosure.
//
// Confirmation endpoints require an actual JWT browser session and never accept
// the internal MCP credential kind as proof of human review. They validate the
// same request digest and token configuration that execution will consume.
// Downloads recheck those grants again; backup streams use the existing HTTP
// handler after owner verification instead of staging archive bytes in memory.

// managementOperations registers the MCP control page's own permissions in
// the same directory as ordinary administrative business operations.
var managementOperations = map[string]*adminapi.Operation{
	"tokens.credential": adminapi.Define(adminapi.Operation{
		ID: "mcp.tokens.credential", Module: "mcp", Title: "Copy MCP access token", TitleZH: "复制 MCP 访问令牌",
		Description: "Use the copy button beside this token in MCP management. The complete credential is available only to its owner's browser session.",
		Method:      "GET", Path: "/api/v1/admin/mcp/tokens/:id/credential", ReadOnly: true, Sensitive: true,
		Response: adminapi.ResponseBrowser, BrowserPath: "/admin/mcp",
		Input: adminapi.Arguments("/api/v1/admin/mcp/tokens/:id/credential", nil, nil),
	}),
	"tokens.list": adminapi.Define(adminapi.Operation{
		ID:          "mcp.tokens.list",
		Module:      "mcp",
		Title:       "List MCP tokens",
		TitleZH:     "查询 MCP 令牌",
		Description: "List the current administrator's token metadata. Credential values are never returned.",
		Method:      "GET",
		Path:        "/api/v1/admin/mcp/tokens",
		ReadOnly:    true,
		Input:       adminapi.Arguments("/api/v1/admin/mcp/tokens", nil, nil),
	}),
	"tokens.create": adminapi.Define(adminapi.Operation{
		ID:      "mcp.tokens.create",
		Module:  "mcp",
		Title:   "Create MCP token",
		TitleZH: "创建 MCP 令牌",
		Description: "Create a token for the current administrator. Delegated creation cannot grant operations " +
			"absent from the calling token.",
		Method:    "POST",
		Path:      "/api/v1/admin/mcp/tokens",
		Sensitive: true,
		Response:  adminapi.ResponseFile,
		Input:     adminapi.Arguments("/api/v1/admin/mcp/tokens", nil, (*identity.MCPTokenInput)(nil)),
	}),
	"tokens.update": adminapi.Define(adminapi.Operation{
		ID:      "mcp.tokens.update",
		Module:  "mcp",
		Title:   "Update MCP token",
		TitleZH: "修改 MCP 令牌",
		Description: "Replace an owned token's name, expiry, enabled state and exact permissions. Revoked tokens " +
			"cannot be restored.",
		Method:    "PUT",
		Path:      "/api/v1/admin/mcp/tokens/:id",
		Sensitive: true,
		Input:     adminapi.Arguments("/api/v1/admin/mcp/tokens/:id", nil, (*identity.MCPTokenInput)(nil)),
	}),
	"tokens.revoke": adminapi.Define(adminapi.Operation{
		ID:          "mcp.tokens.revoke",
		Module:      "mcp",
		Title:       "Revoke MCP token",
		TitleZH:     "撤销 MCP 令牌",
		Description: "Permanently revoke an owned token. Subsequent requests and file downloads are rejected.",
		Method:      "DELETE",
		Path:        "/api/v1/admin/mcp/tokens/:id",
		Sensitive:   true,
		Input:       adminapi.Arguments("/api/v1/admin/mcp/tokens/:id", nil, nil),
	}),
	"operations": adminapi.Define(adminapi.Operation{
		ID:      "mcp.operations.list",
		Module:  "mcp",
		Title:   "List management operations",
		TitleZH: "查询管理操作目录",
		Description: "Read the operation catalogue used by the permission selector. MCP callers see their current " +
			"granted subset.",
		Method:   "GET",
		Path:     "/api/v1/admin/mcp/operations",
		ReadOnly: true,
		Input:    adminapi.Arguments("/api/v1/admin/mcp/operations", nil, nil),
	}),
	"openapi": adminapi.Define(adminapi.Operation{
		ID:          "mcp.openapi.get",
		Module:      "mcp",
		Title:       "Export management Open API",
		TitleZH:     "导出管理 API 说明",
		Description: "Download the current management API description in the administrator browser.",
		Method:      "GET",
		Path:        "/api/v1/admin/mcp/openapi",
		ReadOnly:    true,
		Response:    adminapi.ResponseBrowser,
		BrowserPath: "/admin/mcp?connection=1",
		Input:       adminapi.Arguments("/api/v1/admin/mcp/openapi", nil, nil),
	}),
	"confirmation.get": adminapi.Define(adminapi.Operation{
		ID:          "mcp.confirmations.get",
		Module:      "mcp",
		Title:       "Review MCP confirmation",
		TitleZH:     "查看待确认请求",
		Description: "Read the redacted review and current confirmation state for this token. Approval requires the token owner's logged-in browser.",
		Method:      "GET",
		Path:        "/api/v1/admin/mcp/confirmations/:id",
		ReadOnly:    true,
		Response:    adminapi.ResponseJSON,
		BrowserPath: "/admin/mcp",
		Input:       adminapi.Arguments("/api/v1/admin/mcp/confirmations/:id", nil, nil),
	}),
	"confirmation.approve": adminapi.Define(adminapi.Operation{
		ID:      "mcp.confirmations.approve",
		Module:  "mcp",
		Title:   "Approve MCP confirmation",
		TitleZH: "在浏览器中批准请求",
		Description: "The token owner reviews the exact action in a JWT browser session and confirms it, with " +
			"recent TOTP when required.",
		Method:      "POST",
		Path:        "/api/v1/admin/mcp/confirmations/:id/approve",
		Response:    adminapi.ResponseBrowser,
		BrowserPath: "/admin/mcp",
		Input:       adminapi.Arguments("/api/v1/admin/mcp/confirmations/:id/approve", nil, nil),
	}),
	"files.upload": adminapi.Define(adminapi.Operation{
		ID:      "mcp.files.upload",
		Module:  "mcp",
		Title:   "Upload MCP request file",
		TitleZH: "上传请求文件",
		Description: "Upload a JSON body as base64 for a granted operation. MCP calls use the current authorization; " +
			"browser calls supply token_id and its source. The resulting file_id can replace body in the operation call.",
		Method: "POST",
		Path:   "/api/v1/admin/mcp/files",
		Input:  adminapi.Arguments("/api/v1/admin/mcp/files", nil, (*fileInput)(nil)),
	}),
	"files.download": adminapi.Define(adminapi.Operation{
		ID:      "mcp.files.download",
		Module:  "mcp",
		Title:   "Download protected MCP file",
		TitleZH: "下载受保护文件",
		Description: "Download an owned result through the administrator browser. Current originating-token " +
			"permissions are rechecked.",
		Method:      "GET",
		Path:        "/api/v1/admin/mcp/files/:id",
		ReadOnly:    true,
		Response:    adminapi.ResponseBrowser,
		BrowserPath: "/admin/mcp",
		Input:       adminapi.Arguments("/api/v1/admin/mcp/files/:id", nil, nil),
	}),
}

// fileInput supplies an owned JSON request body through the shared file workflow.
type fileInput struct {
	// Source and TokenID select a browser upload target. Internal MCP uploads
	// infer both from verified dispatch identity when omitted and cannot select another grant.
	Source      string `json:"source,omitempty"`                // empty identifies manual credentials
	TokenID     int64  `json:"token_id,omitempty"`              // owned target token
	OperationID string `json:"operation_id" binding:"required"` // permitted target operation
	Name        string `json:"name"`                            // suggested file display name
	Data        string `json:"data" binding:"required"`         // base64 encoded JSON
}

// registerManagement attaches every MCP control endpoint with its permission description.
func (h *Handler) registerManagement(group *gin.RouterGroup) {
	adminapi.Register(group, managementOperations["tokens.credential"], h.copyCredential)
	adminapi.Register(group, managementOperations["tokens.list"], h.listTokens)
	adminapi.Register(group, managementOperations["tokens.create"], h.createToken)
	adminapi.Register(group, managementOperations["tokens.update"], h.updateToken)
	adminapi.Register(group, managementOperations["tokens.revoke"], h.revokeToken)
	adminapi.Register(group, managementOperations["operations"], h.listOperations)
	adminapi.Register(group, managementOperations["openapi"], h.openAPI)
	adminapi.Register(group, managementOperations["confirmation.get"], h.getConfirmation)
	adminapi.Register(group, managementOperations["confirmation.approve"], h.approveConfirmation)
	adminapi.Register(group, managementOperations["files.upload"], h.uploadFile)
	adminapi.Register(group, managementOperations["files.download"], h.downloadFile)
}

// copyCredential reveals a complete token only to its current browser owner.
// Metadata lists remain secret-free, and internal MCP identities cannot use
// this endpoint. Responses forbid caching and audit the copied token's identity
// without recording the credential value returned to the browser.
func (h *Handler) copyCredential(c *gin.Context) {
	if !browserSession(c) {
		return
	}
	id, ok := tokenID(c)
	if !ok {
		return
	}
	token, credential, err := h.tokens.Credential(c.Request.Context(), administrator(c), id)
	if err != nil {
		httpx.ErrorFrom(c, err)
		return
	}
	traceRelatedToken(c, token, "mcp.tokens.credential")
	c.Header("Cache-Control", "no-store")
	httpx.Success(c, gin.H{"credential": credential})
}

// administrator returns the authenticated owning administrator supplied by route admission.
func administrator(c *gin.Context) int64 {
	principal, _ := authctx.GetPrincipal(c)
	return principal.UserID
}

// listTokens returns this administrator's metadata without reusable credential values.
func (h *Handler) listTokens(c *gin.Context) {
	items, err := h.tokens.List(c.Request.Context(), administrator(c))
	if err != nil {
		httpx.ErrorFrom(c, err)
		return
	}
	httpx.Success(c, items)
}

// tokenInput decodes and validates grants against the mounted operation catalogue.
// Internal MCP callers cannot delegate permissions they do not currently hold;
// normal administrator sessions choose any operation available in the directory.
func (h *Handler) tokenInput(c *gin.Context) (identity.MCPTokenInput, bool) {
	var input identity.MCPTokenInput
	if err := httpx.BindJSONStrict(c, &input); err != nil {
		httpx.BadRequest(c, "Invalid token settings")
		return input, false
	}
	var parent *identity.MCPToken
	if dispatch, ok := authctx.GetMCPDispatch(c.Request.Context()); ok {
		var err error
		parent, _, err = h.tokens.AuthorizeReference(c.Request.Context(), dispatch.Source, dispatch.TokenID, dispatch.Credential)
		if err != nil {
			httpx.ErrorFrom(c, err)
			return input, false
		}
	}
	seen := map[string]bool{}
	permissions := []string{}
	for _, id := range input.Permissions {
		if _, ok := h.catalog.Get(id); !ok || parent != nil && !parent.Allows(id) {
			httpx.BadRequest(c, "Permission is unknown or exceeds the calling token's grants")
			return input, false
		}
		if !seen[id] {
			permissions = append(permissions, id)
			seen[id] = true
		}
	}
	input.Permissions = permissions
	return input, true
}

// createToken returns the persisted credential for immediate client setup after creation.
func (h *Handler) createToken(c *gin.Context) {
	input, ok := h.tokenInput(c)
	if !ok {
		return
	}
	token, credential, err := h.tokens.Create(c.Request.Context(), administrator(c), input)
	if err != nil {
		httpx.ErrorFrom(c, err)
		return
	}
	c.Header("Cache-Control", "no-store")
	httpx.Success(c, gin.H{"token": token, "credential": credential})
}

// tokenID parses a positive route identifier before an owned token mutation.
func tokenID(c *gin.Context) (int64, bool) {
	id, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil || id <= 0 {
		httpx.BadRequest(c, "Invalid token identifier")
		return 0, false
	}
	return id, true
}

// updateToken replaces complete settings while retaining permanent revocation state.
func (h *Handler) updateToken(c *gin.Context) {
	id, ok := tokenID(c)
	if !ok {
		return
	}
	input, ok := h.tokenInput(c)
	if !ok {
		return
	}
	token, err := h.tokens.Update(c.Request.Context(), administrator(c), id, input)
	if err != nil {
		httpx.ErrorFrom(c, err)
		return
	}
	httpx.Success(c, token)
}

// revokeToken permanently revokes an owned credential through the identity service.
func (h *Handler) revokeToken(c *gin.Context) {
	id, ok := tokenID(c)
	if !ok {
		return
	}
	if err := h.tokens.Revoke(c.Request.Context(), administrator(c), id); err != nil {
		httpx.ErrorFrom(c, err)
		return
	}
	httpx.Success(c, gin.H{"revoked": true})
}

// listOperations supplies shared permission-selector data with internal-call filtering.
func (h *Handler) listOperations(c *gin.Context) {
	operations := h.catalog.Operations()
	if dispatch, ok := authctx.GetMCPDispatch(c.Request.Context()); ok {
		token, _, err := h.tokens.AuthorizeReference(c.Request.Context(), dispatch.Source, dispatch.TokenID, dispatch.Credential)
		if err != nil {
			httpx.ErrorFrom(c, err)
			return
		}
		filtered := []*adminapi.Operation{}
		for _, op := range operations {
			if token.Allows(op.ID) {
				filtered = append(filtered, op)
			}
		}
		operations = filtered
	}
	httpx.Success(c, operations)
}

// openAPI exposes the mounted API description to authenticated browser administrators.
func (h *Handler) openAPI(c *gin.Context) {
	if !browserSession(c) {
		return
	}
	c.JSON(http.StatusOK, h.catalog.OpenAPI())
}

// browserSession requires actual JWT authentication for human-only workflow endpoints.
// Internal dispatch identities and administrator API keys cannot satisfy this
// check even when their operation permission includes the corresponding route.
func browserSession(c *gin.Context) bool {
	principal, ok := authctx.GetPrincipal(c)
	if !ok || principal.CredentialKind != "jwt" || principal.SessionID == "" {
		httpx.Error(c, http.StatusForbidden, "Use the token owner's logged-in browser session")
		return false
	}
	return true
}

// ownedApproval loads an unexpired confirmation with current owner and grant checks.
// It rejects stale token settings before exposing even the redacted preview;
// callers separately require the JWT browser credential for approval itself.
func (h *Handler) ownedApproval(c *gin.Context) (*control.Approval, *adminapi.Operation, bool) {
	approval, err := h.state.GetApproval(c.Request.Context(), c.Param("id"))
	if err != nil || approval.UserID != administrator(c) || !time.Now().Before(approval.ExpiresAt) {
		httpx.NotFound(c, "Confirmation is unavailable")
		return nil, nil, false
	}
	// An administrator can own several delegated credentials. Restrict SDK reads
	// to the originating token so another agent cannot inspect its pending parameters.
	if dispatch, internal := authctx.GetMCPDispatch(c.Request.Context()); internal && (dispatch.Source != approval.Source || dispatch.TokenID != approval.TokenID) {
		httpx.NotFound(c, "Confirmation is unavailable")
		return nil, nil, false
	}
	token, _, err := h.tokens.AuthorizeReference(c.Request.Context(), approval.Source, approval.TokenID, "")
	op, exists := h.catalog.Get(approval.OperationID)
	if err != nil || !exists || !token.Allows(approval.OperationID) || token.UpdatedAt.UTC().Format(time.RFC3339Nano) != approval.TokenVersion {
		httpx.Error(c, http.StatusForbidden, "Token grants changed or were revoked")
		return nil, nil, false
	}
	traceRelatedToken(c, token, op.ID)
	return approval, op, true
}

// getConfirmation returns a redacted review to its browser owner or originating token.
// Internal callers need the status operation grant as well as the target grant;
// session identifiers and approval digests remain private to the workflow store.
func (h *Handler) getConfirmation(c *gin.Context) {
	if _, internal := authctx.GetMCPDispatch(c.Request.Context()); !internal && !browserSession(c) {
		return
	}
	approval, op, ok := h.ownedApproval(c)
	if !ok {
		return
	}
	httpx.Success(c, gin.H{"id": approval.ID, "token_id": approval.TokenID, "source": approval.Source, "operation": op, "preview": approval.Preview, "state": approval.State, "expires_at": approval.ExpiresAt})
}

// approveConfirmation validates the owner's browser and records its current session.
// Required TOTP policy is evaluated before the atomic state transition. The
// original request is executed later by a matching authenticated MCP retry.
func (h *Handler) approveConfirmation(c *gin.Context) {
	if !browserSession(c) {
		return
	}
	approval, _, ok := h.ownedApproval(c)
	if !ok || approval.StepUp && !h.checkBrowserStepUp(c) {
		return
	}
	principal, _ := authctx.GetPrincipal(c)
	if err := h.state.Approve(c.Request.Context(), approval, principal.SessionID); err != nil {
		httpx.Error(c, http.StatusConflict, "Confirmation changed or expired")
		return
	}
	httpx.Success(c, gin.H{"state": "approved"})
}

// uploadFile stores a bounded JSON body for an owned token and granted operation.
// File references do not accept local paths or remote URLs; uploaded content
// is encrypted by StateStore and revalidated against the operation on execution.
func (h *Handler) uploadFile(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxRequestBytes)
	var input fileInput
	if err := httpx.BindJSONStrict(c, &input); err != nil {
		httpx.BadRequest(c, "Invalid file upload")
		return
	}
	if dispatch, internal := authctx.GetMCPDispatch(c.Request.Context()); internal {
		if input.TokenID != 0 && input.TokenID != dispatch.TokenID || input.Source != "" && input.Source != dispatch.Source {
			httpx.Error(c, http.StatusForbidden, "Upload must use the calling authorization")
			return
		}
		input.TokenID = dispatch.TokenID
		input.Source = dispatch.Source
	} else if input.TokenID <= 0 {
		httpx.BadRequest(c, "Browser uploads require a token or application identifier")
		return
	}
	token, _, err := h.tokens.AuthorizeReference(c.Request.Context(), input.Source, input.TokenID, "")
	if err != nil || token.UserID != administrator(c) || !token.Allows(input.OperationID) {
		httpx.Error(c, http.StatusForbidden, "Token or operation is not available")
		return
	}
	if dispatch, ok := authctx.GetMCPDispatch(c.Request.Context()); ok && (dispatch.Source != token.Source || dispatch.TokenID != token.ID) {
		httpx.Error(c, http.StatusForbidden, "Upload must use the calling token")
		return
	}
	data, err := base64.StdEncoding.DecodeString(input.Data)
	if err != nil || !json.Valid(data) {
		httpx.BadRequest(c, "Upload must contain base64 encoded JSON")
		return
	}
	file := h.newArtifact(token, input.OperationID)
	file.Name = filepath.Base(input.Name)
	file.ContentType = "application/json"
	file.Data = data
	if err := h.state.SaveArtifact(c.Request.Context(), file); err != nil {
		httpx.Error(c, http.StatusServiceUnavailable, "Temporary file storage is unavailable")
		return
	}
	httpx.Success(c, gin.H{"file_id": file.ID, "expires_at": file.ExpiresAt})
}

// downloadFile delivers a protected result to its owner's authenticated
// browser. It rechecks the artifact lifetime and current token permission
// before exposing stored bytes. Buffered results keep their original content
// type, while archive references reconstruct the registered download request.
//
// Streaming archives use the downloading browser's session through the
// ordinary route chain. Renewing TOTP in that session can therefore satisfy
// the current policy even if approval happened in another session. The
// approved token configuration version still prevents stale archive requests
// from executing after grant changes.
func (h *Handler) downloadFile(c *gin.Context) {
	if !browserSession(c) {
		return
	}
	file, err := h.state.GetArtifact(c.Request.Context(), c.Param("id"))
	if err != nil || file.UserID != administrator(c) || !time.Now().Before(file.ExpiresAt) {
		httpx.NotFound(c, "File is unavailable")
		return
	}
	token, _, err := h.tokens.AuthorizeReference(c.Request.Context(), file.Source, file.TokenID, "")
	if err != nil || !token.Allows(file.OperationID) {
		httpx.Error(c, http.StatusForbidden, "Token grants changed or were revoked")
		return
	}
	traceRelatedToken(c, token, file.OperationID)
	if file.Download != nil {
		op, exists := h.catalog.Get(file.OperationID)
		if !exists || op.Method != http.MethodGet {
			httpx.BadRequest(c, "Download operation is unavailable")
			return
		}
		principal, _ := authctx.GetPrincipal(c)
		approval := &control.Approval{SessionID: principal.SessionID, TokenVersion: file.TokenVersion}
		request, err := h.request(c.Request.Context(), token, op, op, *file.Download, approval)
		if err != nil {
			httpx.BadRequest(c, "Download request is invalid")
			return
		}
		h.router.ServeHTTP(c.Writer, request)
		return
	}
	c.Header("Cache-Control", "no-store")
	c.Header("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": filepath.Base(file.Name)}))
	c.Data(http.StatusOK, file.ContentType, file.Data)
}

// traceRelatedToken attaches the originating credential to browser workflow audit events.
// The shared audit middleware retains the actual JWT authentication method while
// making approvals and downloads searchable alongside that token's MCP executions.
func traceRelatedToken(c *gin.Context, token *identity.MCPToken, operation string) {
	c.Set("mcp_related_source", token.Source)
	c.Set("mcp_related_token_id", token.ID)
	c.Set("mcp_related_operation_id", operation)
	c.Set("mcp_related_token_prefix", token.Prefix)
}
