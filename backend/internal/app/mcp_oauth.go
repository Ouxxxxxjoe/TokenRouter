package app

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/TokenFlux/TokenRouter/internal/app/lifecycle"
	"github.com/TokenFlux/TokenRouter/internal/config"
	"github.com/TokenFlux/TokenRouter/internal/identity"
	identitypostgres "github.com/TokenFlux/TokenRouter/internal/identity/postgres"
	identityprovider "github.com/TokenFlux/TokenRouter/internal/identity/provider"
	"github.com/TokenFlux/TokenRouter/internal/settings"
)

// mcp_oauth.go assembles the OAuth protocol service and expired-state cleanup.
// Bootstrap supplies an independent persisted signing secret so backend
// restarts can verify existing opaque credentials. The existing
// frontend URL controls the public issuer, and the saved connection switch
// controls availability. Grant management remains available while disabled.
//
// Cleanup starts under the application lifecycle and stops before database
// shutdown. Each pass has a bounded context, and shutdown cancels an active
// pass before waiting for its worker. Family cleanup retains consumed refresh
// records while another family member remains unexpired, preserving replay
// detection across access-token renewal and process restarts.

// mcpOAuthSettings reads the site address and connection switch as one database view.
// The deployment frontend URL supplies the existing default when no nonblank
// database address exists. Read errors remain failures rather than changing origins.
type mcpOAuthSettings struct {
	store       *settings.Store // Authoritative site settings store.
	frontendURL string          // Deployment frontend address default.
}

// provideMCPOAuth constructs OAuth services and registers bounded expired-state cleanup.
// Missing or malformed persistent signing material fails service assembly.
// The repository and user reader share the application's existing database resources.
//
// The lifecycle starts one worker, which owns its ticker and pass-specific timeout.
// Shutdown cancels the worker context before waiting for its completion channel,
// so an active SQL cleanup can stop before the database pool closes. Failed passes
// are logged and retried on the next hourly tick; they do not authorize requests
// or remove still-live replay detection records.
func provideMCPOAuth(db *sql.DB, users *identity.UserService, cfg *config.Config, store *settings.Store, manager *lifecycle.Manager) (*identityprovider.MCPOAuthServer, error) {
	repo := identitypostgres.NewMCPOAuthStore(db)
	secret, err := hex.DecodeString(cfg.MCPOAuthSigningSecret)
	if err != nil || len(secret) != 32 {
		return nil, fmt.Errorf("MCP OAuth signing secret is unavailable")
	}
	server := identityprovider.NewMCPOAuthServer(repo, users, &mcpOAuthSettings{store: store, frontendURL: cfg.Server.FrontendURL}, secret)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	manager.Register(lifecycle.Hook{
		Name: "MCPOAuthCleanup", StartOrder: 100, StopOrder: 100,
		Start: func(context.Context) error {
			// The lifecycle starts this worker before serving traffic. Cancellation reaches
			// the active SQL pass, and the completion channel joins it before database shutdown.
			go func() {
				defer close(done)
				ticker := time.NewTicker(time.Hour)
				defer ticker.Stop()
				for {
					pass, stop := context.WithTimeout(ctx, 30*time.Second)
					err := repo.Cleanup(pass)
					stop()
					if err != nil && ctx.Err() == nil {
						slog.Warn("MCP OAuth cleanup failed", "error", err)
					}
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
					}
				}
			}()
			return nil
		},
		Stop: func(ctx context.Context) error {
			cancel()
			select {
			case <-done:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		},
	})
	return server, nil
}

// Read resolves the existing frontend address and default-enabled OAuth switch.
// Both stored values come from one read; database failures prevent protocol
// admission. An absent switch permits connections once a valid address exists.
func (s *mcpOAuthSettings) Read(ctx context.Context) (identityprovider.MCPOAuthConfiguration, error) {
	values, err := s.store.GetMultiple(ctx, []string{"frontend_url", "mcp_oauth_enabled"})
	if err != nil {
		return identityprovider.MCPOAuthConfiguration{}, err
	}
	frontend := strings.TrimSpace(values["frontend_url"])
	if frontend == "" {
		frontend = s.frontendURL
	}
	enabled := true
	if raw, exists := values["mcp_oauth_enabled"]; exists {
		enabled, err = strconv.ParseBool(raw)
		if err != nil {
			return identityprovider.MCPOAuthConfiguration{}, fmt.Errorf("invalid OAuth connection setting: %w", err)
		}
	}
	return identityprovider.MCPOAuthConfiguration{FrontendURL: frontend, Enabled: enabled}, nil
}

// SetEnabled persists the browser administrator's OAuth connection preference.
// Protocol requests read this value directly on their next admission, so a
// successful write takes effect without restarting the backend or changing addresses.
func (s *mcpOAuthSettings) SetEnabled(ctx context.Context, enabled bool) error {
	return s.store.Set(ctx, "mcp_oauth_enabled", strconv.FormatBool(enabled))
}
