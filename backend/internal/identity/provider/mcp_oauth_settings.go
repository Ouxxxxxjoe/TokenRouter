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
// addresses disable protocol access while retaining browser grant management.
// The separate switch controls availability and defaults at the settings adapter;
// it never supplies another address or changes existing application permissions.
//
// Each request receives a private protocol instance bound to one settings read.
// Discovery, resource checks, browser callbacks, and credential storage therefore
// agree within that request. Later requests read settings again, so disabling
// OAuth or changing the frontend origin affects existing access credentials and
// stable grant checks used by confirmations and file downloads.

// MCPOAuthConfiguration carries the site's public address and independent connection switch.
type MCPOAuthConfiguration struct {
	FrontendURL string // Effective configured frontend address.
	Enabled     bool   // Administrator permits OAuth connections.
}

// MCPOAuthSettings supplies live site configuration and persists the OAuth switch.
type MCPOAuthSettings interface {
	// Read returns one coherent view of the current frontend address and switch.
	// Storage failures remain errors; callers must not substitute request headers
	// or cached addresses when the authoritative settings cannot be read.
	Read(context.Context) (MCPOAuthConfiguration, error)
	// SetEnabled persists the administrator's connection switch for subsequent requests.
	// Changing this switch leaves the frontend URL and individual grants untouched.
	// A failed write must leave the previously saved switch in effect.
	SetEnabled(context.Context, bool) error
}

// MCPOAuthStatus exposes availability and configuration feedback without credential material.
type MCPOAuthStatus struct {
	Enabled  bool   `json:"enabled"`  // Valid address and allowed connections.
	Allowed  bool   `json:"allowed"`  // Saved administrator connection preference.
	Reason   string `json:"reason"`   // Disabled or invalid address reason.
	Issuer   string `json:"issuer"`   // Validated frontend origin when available.
	Resource string `json:"resource"` // Canonical public MCP endpoint.
}

// Status reads the current site settings and explains unavailable OAuth access.
// A missing or invalid address produces a successful status with a reason code.
// Storage failures remain errors so administrators can distinguish a failed read
// from a deliberate disabled setting or an address needing correction. A valid
// origin remains available in disabled status for connection guidance. Availability
// also requires initialized signing material; failing that requirement returns an
// error rather than advertising a protocol that cannot issue credentials.
func (s *MCPOAuthServer) Status(ctx context.Context) (MCPOAuthStatus, error) {
	if s.settings == nil {
		return MCPOAuthStatus{Enabled: s.Enabled(), Allowed: true, Issuer: s.issuer, Resource: s.Resource()}, nil
	}
	config, err := s.settings.Read(ctx)
	if err != nil {
		return MCPOAuthStatus{}, err
	}
	status := MCPOAuthStatus{Allowed: config.Enabled}
	raw := strings.TrimSpace(config.FrontendURL)
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
	if !config.Enabled {
		status.Reason = "disabled"
		return status, nil
	}
	status.Enabled = len(s.secret) == 32
	if !status.Enabled {
		return MCPOAuthStatus{}, apperror.ServiceUnavailable("MCP_OAUTH_UNAVAILABLE", "OAuth signing key is unavailable")
	}
	return status, nil
}

// SetEnabled saves connection availability and returns its current validated status.
// This method requires a live settings source and is called after administrator
// session and step-up checks. An immutable request instance cannot change settings.
func (s *MCPOAuthServer) SetEnabled(ctx context.Context, enabled bool) (MCPOAuthStatus, error) {
	if s.settings == nil {
		return MCPOAuthStatus{}, apperror.ServiceUnavailable("MCP_OAUTH_UNAVAILABLE", "OAuth settings are unavailable")
	}
	if err := s.settings.SetEnabled(ctx, enabled); err != nil {
		return MCPOAuthStatus{}, err
	}
	return s.Status(ctx)
}

// Current resolves an immutable protocol instance for a single OAuth operation.
// The root service reads current settings on each call; an already bound instance
// returns itself so Fosite storage uses the same origin throughout a transaction.
// An unavailable address or disabled switch rejects the operation before protocol
// parsing. The copy shares durable repositories, signing material, and the HTTP
// client while owning its protocol handlers, so concurrent requests cannot mutate
// each other's issuer or redirect configuration.
func (s *MCPOAuthServer) Current(ctx context.Context) (*MCPOAuthServer, error) {
	if s.settings == nil && s.Enabled() {
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
	current.settings = nil
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
