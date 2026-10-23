package mcp

import (
	"context"
	"encoding/json"
	"time"
)

// state.go defines temporary browser confirmations and protected result files
// shared by MCP and administrator HTTP callers. Confirmation records contain
// request digests and redacted previews; original sensitive arguments arrive
// again with the approved tool retry. File ownership includes both the token
// source and administrator so equal IDs from different authorization stores
// cannot share protected results. Existing records with no source use manual tokens.

// Call identifies one operation and separates URL arguments from its JSON body.
type Call struct {
	OperationID    string            `json:"operation_id"`              // exact catalogue permission identity
	Path           map[string]string `json:"path,omitempty"`            // named URL path arguments
	Query          map[string]string `json:"query,omitempty"`           // textual URL query arguments
	Body           json.RawMessage   `json:"body,omitempty"`            // optional JSON request body
	IdempotencyKey string            `json:"idempotency_key,omitempty"` // existing API replay identity
	ConfirmationID string            `json:"confirmation_id,omitempty"` // browser approval record identifier
	FileID         string            `json:"file_id,omitempty"`         // owned uploaded JSON body
}

// Approval binds one administrator's confirmation to a token configuration and request.
type Approval struct {
	Source       string    `json:"source,omitempty"` // empty identifies manual credentials
	ID           string    `json:"id"`               // opaque confirmation identifier
	UserID       int64     `json:"user_id"`          // required approving administrator
	TokenID      int64     `json:"token_id"`         // requesting credential identifier
	OperationID  string    `json:"operation_id"`     // confirmed operation permission
	TokenVersion string    `json:"token_version"`    // token settings timestamp
	Digest       string    `json:"digest"`           // normalized request SHA256
	Preview      string    `json:"preview"`          // redacted JSON argument display
	StepUp       bool      `json:"step_up"`          // verification required for this request
	State        string    `json:"state"`            // pending approved or consumed
	SessionID    string    `json:"session_id"`       // verified approving browser session
	CreatedAt    time.Time `json:"created_at"`       // confirmation creation instant
	ExpiresAt    time.Time `json:"expires_at"`       // absolute confirmation expiry
}

// Artifact stores encrypted temporary result bytes or an authenticated streaming request.
type Artifact struct {
	Source       string    `json:"source,omitempty"`        // empty identifies manual credentials
	ID           string    `json:"id"`                      // opaque owned file identifier
	UserID       int64     `json:"user_id"`                 // owning administrator identifier
	TokenID      int64     `json:"token_id"`                // originating credential identifier
	OperationID  string    `json:"operation_id"`            // permission rechecked on download
	Name         string    `json:"name"`                    // safe suggested download filename
	ContentType  string    `json:"content_type"`            // stored response media type
	Data         []byte    `json:"data,omitempty"`          // stored encrypted payload plaintext
	Download     *Call     `json:"download,omitempty"`      // bodyless streaming download request
	TokenVersion string    `json:"token_version,omitempty"` // approved token configuration timestamp
	ExpiresAt    time.Time `json:"expires_at"`              // absolute file expiry
}

// StateStore maintains bounded temporary records with atomic confirmation transitions.
type StateStore interface {
	// CreateApproval stores a unique pending record until its absolute expiry.
	CreateApproval(context.Context, *Approval) error
	// GetApproval returns a fresh record or an error for absent state.
	GetApproval(context.Context, string) (*Approval, error)
	// Approve conditionally replaces the observed pending record with session-bound approval.
	Approve(context.Context, *Approval, string) error
	// Consume atomically marks the observed approved record consumed before dispatch.
	Consume(context.Context, *Approval) error
	// SaveArtifact encrypts temporary bytes and ownership metadata before shared storage.
	SaveArtifact(context.Context, *Artifact) error
	// GetArtifact decrypts a temporary record whose ownership callers must verify.
	GetArtifact(context.Context, string) (*Artifact, error)
}

// Cipher encrypts shared file payloads using the deployment's persistent secret key.
type Cipher interface {
	// Encrypt produces authenticated ciphertext for the supplied temporary plaintext.
	Encrypt(string) (string, error)
	// Decrypt authenticates ciphertext before exposing its original temporary plaintext.
	Decrypt(string) (string, error)
}
