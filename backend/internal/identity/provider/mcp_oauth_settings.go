package provider

import (
	"context"
	"net"
	"net/url"
	"strings"

	"github.com/TokenFlux/TokenRouter/internal/pkg/apperror"
)

// mcp_oauth_settings.go resolves OAuth availability from the current frontend URL.
// The stored site address is the sole public address source. Missing or invalid
// addresses prevent protocol access while retaining browser grant management.
// A validated address supplies discovery, consent navigation, and resource binding;
// administrators manage it through the site's existing frontend address setting.
//
// Each request receives a private protocol instance bound to one address read.
// Discovery, resource checks, browser callbacks, and credential storage therefore
// agree within that request. Later requests read the address again, so changing
// or removing the frontend origin affects existing access credentials and stable
// grant checks used by browser confirmations and protected file downloads.

// MCPOAuthFrontend supplies the authoritative frontend address for OAuth requests.
type MCPOAuthFrontend interface {
	// FrontendURL resolves the existing site address or its deployment default.
	// Storage failures remain errors; callers must not substitute request headers
	// or cached addresses when the authoritative setting cannot be read.
	FrontendURL(context.Context) (string, error)
}

// MCPOAuthStatus exposes availability and configuration feedback without credential material.
type MCPOAuthStatus struct {
	Enabled  bool   `json:"enabled"`  // Validated OAuth endpoint availability.
	Reason   string `json:"reason"`   // Missing or invalid address reason.
	Issuer   string `json:"issuer"`   // Validated frontend origin when available.
	Resource string `json:"resource"` // Canonical public MCP endpoint.
}

// Status reads the current frontend address and explains unavailable OAuth access.
// A missing or invalid address produces a successful status with a reason code.
// Storage failures remain errors so administrators can distinguish a failed read
// from an address needing correction. A valid origin supplies the resource URL
// and enables protocol access automatically. Availability also requires initialized
// signing material; failing that requirement returns an error rather than
// advertising a protocol that cannot issue credentials.
func (s *MCPOAuthServer) Status(ctx context.Context) (MCPOAuthStatus, error) {
	if s.frontend == nil {
		return MCPOAuthStatus{Enabled: s.Enabled(), Issuer: s.issuer, Resource: s.Resource()}, nil
	}
	value, err := s.frontend.FrontendURL(ctx)
	if err != nil {
		return MCPOAuthStatus{}, err
	}
	status := MCPOAuthStatus{}
	raw := strings.TrimSpace(value)
	if raw == "" {
		status.Reason = "frontend_url_missing"
		return status, nil
	}
	issuer, valid := mcpFrontendOrigin(raw)
	if !valid {
		status.Reason = "frontend_url_invalid"
		return status, nil
	}
	status.Issuer = issuer
	status.Resource = issuer + "/mcp"
	status.Enabled = len(s.secret) == 32
	if !status.Enabled {
		return MCPOAuthStatus{}, apperror.ServiceUnavailable("MCP_OAUTH_UNAVAILABLE", "OAuth signing key is unavailable")
	}
	return status, nil
}

// Current resolves an immutable protocol instance for a single OAuth operation.
// The root service reads current settings on each call; an already bound instance
// returns itself so Fosite storage uses the same origin throughout a transaction.
// An unavailable frontend address rejects the operation before protocol
// parsing. The copy shares durable repositories, signing material, and the HTTP
// client while owning its protocol handlers, so concurrent requests cannot mutate
// each other's issuer or redirect configuration.
func (s *MCPOAuthServer) Current(ctx context.Context) (*MCPOAuthServer, error) {
	if s.frontend == nil && s.Enabled() {
		return s, nil
	}
	status, err := s.Status(ctx)
	if err != nil {
		return nil, err
	}
	if !status.Enabled {
		return nil, apperror.ServiceUnavailable("MCP_OAUTH_UNAVAILABLE", "OAuth is unavailable")
	}
	current := *s
	current.frontend = nil
	current.issuer = status.Issuer
	current.enableProtocol()
	return &current, nil
}

// mcpFrontendOrigin validates the site URL without guessing a missing public origin.
// Production addresses require HTTPS and no path, query, fragment, or userinfo.
// Loopback HTTP supports local development; a trailing root slash is normalized.
func mcpFrontendOrigin(raw string) (string, bool) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", false
	}
	ip := net.ParseIP(u.Hostname())
	loopback := strings.EqualFold(u.Hostname(), "localhost") || ip != nil && ip.IsLoopback()
	secure := u.Scheme == "https" || u.Scheme == "http" && loopback
	if u.Hostname() == "" || strings.Contains(raw, "#") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.RawPath != "" || u.Path != "" && u.Path != "/" || !secure {
		return "", false
	}
	u.Host = strings.ToLower(u.Host)
	u.Path = ""
	return u.String(), true
}
