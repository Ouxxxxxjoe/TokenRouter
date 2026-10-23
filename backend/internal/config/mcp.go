package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// mcp.go validates the canonical OAuth issuer configured by the deployment.
// Discovery and redirect responses use this value rather than request headers,
// so a reverse proxy or untrusted Host cannot change the authority issuing MCP
// credentials. An empty issuer leaves OAuth disabled while manual tokens work.

// MCPConfig groups process settings for the management protocol's authorization service.
type MCPConfig struct {
	OAuth MCPOAuthConfig `mapstructure:"oauth"` // optional OAuth issuer configuration
}

// MCPOAuthConfig supplies the public issuer and bootstrap-resolved independent signing key.
type MCPOAuthConfig struct {
	IssuerURL     string `mapstructure:"issuer_url"` // empty disables OAuth endpoints
	SigningSecret string `mapstructure:"-" json:"-"` // persisted bootstrap signing secret
}

// Validate canonicalizes a configured issuer and rejects insecure public origins.
// Only root origins are supported. HTTP is reserved for loopback development;
// production URLs require HTTPS and cannot contain credentials, query, or fragment.
func (c *MCPConfig) Validate() error {
	raw := strings.TrimSpace(c.OAuth.IssuerURL)
	c.OAuth.IssuerURL = raw
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("mcp.oauth.issuer_url: invalid origin")
	}
	ip := net.ParseIP(u.Hostname())
	loopback := u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()
	secure := u.Scheme == "https" || u.Scheme == "http" && loopback
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.ForceQuery || u.RawPath != "" || u.Path != "" && u.Path != "/" || !secure {
		return fmt.Errorf("mcp.oauth.issuer_url: expected HTTPS origin or loopback HTTP origin")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = ""
	c.OAuth.IssuerURL = u.String()
	return nil
}
