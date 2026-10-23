package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/TokenFlux/TokenRouter/internal/identity"
	"github.com/TokenFlux/TokenRouter/internal/identity/httpapi/authctx"
	control "github.com/TokenFlux/TokenRouter/internal/mcp"
	"github.com/TokenFlux/TokenRouter/internal/server/adminapi"
)

// execute.go validates discovered operations and dispatches them through the
// existing administrative HTTP chain. Request identity is fixed by the mounted
// catalogue; callers supply parameter values but cannot replace the method,
// destination, credentials, or expected route. Inputs are normalized before
// confirmation hashing so map ordering does not alter an approved request.
//
// Execution requiring browser review consumes one approval immediately before dispatch.
// The approval binds both the request digest and token configuration version,
// and the route middleware rechecks live grants again. A timeout or incomplete
// response after dispatch reports an unknown outcome for mutations. The executor
// does not compensate or repeat a write whose business effects may already
// have completed in the existing handler.

// call validates a granted operation and dispatches its canonical HTTP
// request. Query calls reject mutations, and browser-only operations return a
// continuation before business execution. Sensitive calls follow the token's
// review preference and the route's recent-TOTP policy for those arguments.
//
// Approval is consumed immediately before dispatch, so concurrent retries
// cannot execute the same approved request twice. Handler or delivery
// interruption may leave committed side effects; callers receive an unknown
// outcome and must inspect state before deciding whether to submit another
// action.
func (h *Handler) call(ctx context.Context, req *mcp.CallToolRequest, readOnly bool) *mcp.CallToolResult {
	var input control.Call
	if err := decodeArguments(req.Params.Arguments, &input); err != nil {
		return toolFailure(err)
	}
	token, _, err := h.current(ctx)
	if err != nil {
		return toolFailure(err)
	}
	op, exists := h.catalog.Get(input.OperationID)
	if !exists || !token.Allows(input.OperationID) {
		return toolFailure(errors.New("operation is not authorized"))
	}
	if readOnly && !op.ReadOnly {
		return toolFailure(errors.New("this operation requires execute_operation"))
	}
	if input.FileID != "" {
		if len(input.Body) != 0 {
			return toolFailure(errors.New("supply body or file_id, not both"))
		}
		file, err := h.state.GetArtifact(ctx, input.FileID)
		if err != nil || file.Source != token.Source || file.TokenID != token.ID || file.UserID != token.UserID || file.OperationID != op.ID || file.Download != nil {
			return toolFailure(errors.New("uploaded file is unavailable for this token and operation"))
		}
		input.Body = json.RawMessage(file.Data)
	}
	arguments, err := callArguments(input)
	if err != nil {
		return toolFailure(err)
	}
	if err := op.Validate(arguments); err != nil {
		return toolFailure(err)
	}
	if input.IdempotencyKey != "" && (!op.Idempotent || len(input.IdempotencyKey) > 128 || strings.ContainsAny(input.IdempotencyKey, "\r\n")) {
		return toolFailure(errors.New("operation does not accept this idempotency key"))
	}
	if op.Response == adminapi.ResponseBrowser {
		destination := op.BrowserPath
		if strings.HasPrefix(op.ID, "mcp.confirmations.") {
			destination += "?confirmation_id=" + url.QueryEscape(input.Path["id"])
		} else if op.ID == "mcp.files.download" {
			destination += "?file_id=" + url.QueryEscape(input.Path["id"])
		}
		result := map[string]any{"status": "interaction_required", "url": h.browserLink(ctx, destination), "message": "Continue this operation in the administrator browser session."}
		if destination == "/admin/providers" {
			result["message"] = "Use Add provider or Reauthorize in provider management to complete this upstream authorization. The browser saves the provider; query providers.list afterward to continue configuration."
			result["follow_up_operation"] = "providers.list"
		}
		return toolResult(result)
	}
	var approved *control.Approval
	if h.requiresConfirmation(ctx, token, op, arguments) {
		approved, err = h.confirmation(ctx, token, op, input, arguments)
		if err != nil {
			return toolFailure(err)
		}
		if approved.State != "approved" {
			return toolResult(map[string]any{"status": "confirmation_required", "confirmation_id": approved.ID, "url": h.browserLink(ctx, "/admin/mcp?confirmation_id="+approved.ID), "expires_at": approved.ExpiresAt, "message": "The token owner must open this URL, review the operation, and approve it. Retry identical arguments with confirmation_id after approval."})
		}
	}
	target := op
	if op.Alias != "" {
		target, _ = h.catalog.Get(op.Alias)
	}
	request, err := h.request(ctx, token, op, target, input, approved)
	if err != nil {
		return toolFailure(err)
	}
	if approved != nil {
		// Claim after constructing the canonical request, but before executing any
		// business handler; concurrent tool retries cannot share this browser approval.
		if err := h.state.Consume(ctx, approved); err != nil {
			return toolFailure(errors.New("confirmation was consumed, changed, or expired"))
		}
	}
	// Existing backup downloads stream directly to the authenticated browser.
	// Retaining the bodyless request avoids buffering arbitrarily large archives in Redis or model context.
	if target.Response == adminapi.ResponseFile && target.Method == http.MethodGet && strings.HasSuffix(target.Path, "/download") {
		file := h.newArtifact(token, op.ID)
		file.Download = &input
		if approved != nil {
			file.TokenVersion = approved.TokenVersion
		}
		if err := h.state.SaveArtifact(ctx, file); err != nil {
			return toolFailure(errors.New("could not prepare the protected download"))
		}
		return h.artifactResult(ctx, file)
	}
	ctx, cancel := context.WithTimeout(request.Context(), operationTimeout)
	defer cancel()
	request = request.WithContext(ctx)
	capture := newCapture(ctx, cancel)
	defer capture.close()
	h.router.ServeHTTP(capture, request)
	if capture.err != nil || ctx.Err() != nil {
		return uncertainResult(op.ReadOnly, "The operation response was interrupted; do not automatically retry a write.")
	}
	return h.operationResult(ctx, token, op, capture)
}

// requiresConfirmation combines the token's opt-in policy with existing route security.
// Sensitive calls can skip MCP review only when no enabled recent-TOTP policy
// needs a browser session. Browser-only authorization workflows retain their own
// continuation path before this decision, and live route middleware rechecks TOTP.
//
// A missing settings reader keeps strong authentication required. Permission and
// owner checks still happen independently, and direct sensitive dispatch binds
// the observed token version so a concurrent preference change cannot be ignored.
// Nil arguments are discovery queries and conservatively report conditional verification.
func (h *Handler) requiresConfirmation(ctx context.Context, token *identity.MCPToken, op *adminapi.Operation, arguments any) bool {
	if !op.Sensitive || op.Response == adminapi.ResponseBrowser {
		return false
	}
	return !token.SkipBrowserConfirmation || op.RequiresStepUp(arguments) && (h.settings == nil || h.settings.IsStepUpEnabled(ctx))
}

// callArguments builds the path, query, and body objects consumed by schema
// validation. Omitted bodies remain absent and explicit JSON null remains
// present. URL arguments are strings because the existing handlers parse their
// URL representation.
//
// JSON normalization supplies ordinary maps and float64 values to the
// validator. The original RawMessage is retained separately for HTTP dispatch,
// and confirmation hashing decodes its numbers again with UseNumber so
// validation normalization cannot merge distinct large integer identities.
func callArguments(input control.Call) (map[string]any, error) {
	value := map[string]any{"path": input.Path, "query": input.Query}
	if input.Path == nil {
		value["path"] = map[string]string{}
	}
	if input.Query == nil {
		value["query"] = map[string]string{}
	}
	if len(input.Body) > 0 {
		var body any
		if err := json.Unmarshal(input.Body, &body); err != nil {
			return nil, errors.New("body must contain valid JSON")
		}
		value["body"] = body
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var normalized map[string]any
	if err := json.Unmarshal(encoded, &normalized); err != nil {
		return nil, err
	}
	return normalized, nil
}

// confirmation reads or creates the shared approval for an exact operation
// request. The digest includes the operation description, normalized
// arguments, file identity, and idempotency key. Body numbers retain their
// original decimal representation, so adjacent integers beyond float64
// precision cannot reuse one approval.
//
// Existing records must match the current owner, permission, token version,
// and digest. Approved records also recheck any required TOTP grant;
// consumption remains with call after request construction and immediately
// before dispatch.
//
// @project-doc docs/interfaces/mcp_management.md#browser_confirmation
func (h *Handler) confirmation(ctx context.Context, token *identity.MCPToken, op *adminapi.Operation, input control.Call, arguments map[string]any) (*control.Approval, error) {
	// Schema validation accepts ordinary JSON numbers, but approval identity must
	// retain their exact decimal representation so distinct large integers cannot share a digest.
	if len(input.Body) > 0 {
		decoder := json.NewDecoder(bytes.NewReader(input.Body))
		decoder.UseNumber()
		var exactBody any
		if err := decoder.Decode(&exactBody); err != nil {
			return nil, errors.New("body must contain valid JSON")
		}
		arguments["body"] = exactBody
	}
	encoded, err := json.Marshal(map[string]any{"operation": op, "arguments": arguments, "idempotency_key": input.IdempotencyKey, "file_id": input.FileID})
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(encoded)
	digest := hex.EncodeToString(hash[:])
	version := token.UpdatedAt.UTC().Format(time.RFC3339Nano)
	if input.ConfirmationID == "" {
		previewData, _ := json.Marshal(arguments)
		preview := h.redactor.RedactBody(previewData, "application/json")
		// Indent the redacted bytes without decoding numbers again. Oversized-body
		// omission markers remain readable even though they are deliberately not JSON documents.
		var formatted bytes.Buffer
		if json.Indent(&formatted, []byte(preview), "", "  ") == nil {
			preview = formatted.String()
		}
		now := time.Now().UTC()
		approval := &control.Approval{ID: uuid.NewString(), UserID: token.UserID, TokenID: token.ID, Source: token.Source, OperationID: op.ID, TokenVersion: version, Digest: digest, Preview: preview, StepUp: op.RequiresStepUp(arguments), State: "pending", CreatedAt: now, ExpiresAt: now.Add(confirmationTTL)}
		if err := h.state.CreateApproval(ctx, approval); err != nil {
			return nil, errors.New("confirmation storage is unavailable")
		}
		return approval, nil
	}
	approval, err := h.state.GetApproval(ctx, input.ConfirmationID)
	if err != nil || approval.Source != token.Source || approval.TokenID != token.ID || approval.UserID != token.UserID || approval.OperationID != op.ID || approval.Digest != digest || approval.TokenVersion != version || !time.Now().Before(approval.ExpiresAt) {
		return nil, errors.New("confirmation does not match this request or has expired")
	}
	if approval.State == "consumed" {
		return nil, errors.New("confirmation was already consumed; the earlier operation may have executed")
	}
	if approval.State == "approved" && approval.StepUp && (h.settings == nil || h.settings.IsStepUpEnabled(ctx)) {
		granted, err := h.totp.HasStepUpGrant(ctx, token.UserID, approval.SessionID)
		if err != nil || !granted {
			return nil, errors.New("recent two-factor verification expired; request a new confirmation")
		}
	}
	return approval, nil
}

// request constructs the internal HTTP request selected by the catalogue. Path
// arguments reject separators and escapes that could change which Gin route
// matches. Query values are encoded independently, and the original JSON bytes
// reach the existing handler without a numeric round trip.
//
// The private dispatch record carries the requested permission and the
// resolved target route separately for aliases. Administrator middleware
// rechecks both the live grants and final method/path before admitting the
// handler. Caller-controlled authentication headers are never copied into that
// identity.
func (h *Handler) request(ctx context.Context, token *identity.MCPToken, operation, target *adminapi.Operation, input control.Call, approval *control.Approval) (*http.Request, error) {
	segments := strings.Split(target.Path, "/")
	for i, segment := range segments {
		if !strings.HasPrefix(segment, ":") {
			continue
		}
		value := input.Path[segment[1:]]
		if value == "" || value == "." || value == ".." || strings.ContainsAny(value, "/\\%?#\x00\r\n") {
			return nil, fmt.Errorf("invalid path argument: %s", segment[1:])
		}
		segments[i] = url.PathEscape(value)
	}
	query := make(url.Values, len(input.Query))
	for name, value := range input.Query {
		query.Set(name, value)
	}
	dispatch := authctx.MCPDispatch{TokenID: token.ID, Source: token.Source, Credential: token.Credential, OperationID: operation.ID, Method: target.Method, Route: target.Path}
	dispatch.ConfirmationSkipped = operation.Sensitive && token.SkipBrowserConfirmation && approval == nil
	if dispatch.ConfirmationSkipped {
		// Bind direct execution to the opt-in version just observed, so disabling
		// confirmation skipping before route admission rejects an already constructed request.
		dispatch.TokenVersion = token.UpdatedAt.UTC().Format(time.RFC3339Nano)
	}
	if approval != nil {
		dispatch.SessionID = approval.SessionID
		dispatch.TokenVersion = approval.TokenVersion
	}
	ctx = authctx.WithMCPDispatch(ctx, dispatch)
	request, err := http.NewRequestWithContext(ctx, target.Method, strings.Join(segments, "/")+"?"+query.Encode(), bytes.NewReader(input.Body))
	if err != nil {
		return nil, errors.New("could not construct operation request")
	}
	request.Header.Set("Content-Type", "application/json")
	if input.IdempotencyKey != "" {
		request.Header.Set("Idempotency-Key", input.IdempotencyKey)
	}
	if caller, ok := ctx.Value(requestIdentityKey{}).(requestIdentity); ok {
		request.RemoteAddr = caller.RemoteAddr
		request.Header.Set("User-Agent", caller.UserAgent)
	}
	return request, nil
}

// newArtifact assigns a fresh identifier and ten-minute lifetime to one owned
// file. Callers fill its bytes or streaming request and persist it
// successfully before returning a download link.
func (h *Handler) newArtifact(token *identity.MCPToken, operation string) *control.Artifact {
	return &control.Artifact{ID: uuid.NewString(), UserID: token.UserID, TokenID: token.ID, Source: token.Source, OperationID: operation, ExpiresAt: time.Now().UTC().Add(artifactTTL)}
}

// artifactResult returns the browser delivery link for an already persisted
// file. The identifier carries no download authority; the administrator
// endpoint rechecks the owner and current token permissions when opened.
func (h *Handler) artifactResult(ctx context.Context, file *control.Artifact) *mcp.CallToolResult {
	return toolResult(map[string]any{"status": "file_ready", "file_id": file.ID, "url": h.browserLink(ctx, "/admin/mcp?file_id="+file.ID), "expires_at": file.ExpiresAt, "message": "Open the link in the token owner's administrator session to download the protected result."})
}

// uncertainResult reports failed queries and unknown mutation outcomes after
// interruption. Callers use it when response delivery cannot prove business
// completion; clients must inspect state before retrying an affected write.
func uncertainResult(readOnly bool, message string) *mcp.CallToolResult {
	status := "outcome_unknown"
	if readOnly {
		status = "failed"
	}
	result := toolResult(map[string]any{"status": status, "message": message})
	result.IsError = true
	return result
}

// redact copies JSON output and masks sensitive values using the shared audit
// key policy. Credential containers retain safe configuration fields, while
// nested keys such as api_key are replaced. Boolean presence markers and
// numeric usage counters remain readable because existing administrator DTOs
// expose them as operational metadata.
//
// The input objects remain unchanged so file delivery and other response
// consumers keep their own representation. Excessive nesting produces an
// omission marker instead of recursively expanding unbounded model content.
func (h *Handler) redact(value any, depth int) any {
	if depth > 24 {
		return "[nested value omitted]"
	}
	switch current := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(current))
		for key, child := range current {
			_, number := child.(float64)
			if _, exact := child.(json.Number); exact {
				number = true
			}
			_, boolean := child.(bool)
			if h.redactor.IsSensitiveKey(key) && !number && !boolean {
				result[key] = "***"
			} else {
				result[key] = h.redact(child, depth+1)
			}
		}
		return result
	case []any:
		result := make([]any, len(current))
		for i, child := range current {
			result[i] = h.redact(child, depth+1)
		}
		return result
	default:
		return value
	}
}
