package app

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/TokenFlux/TokenRouter/internal/app/lifecycle"
	"github.com/TokenFlux/TokenRouter/internal/config"
	"github.com/TokenFlux/TokenRouter/internal/identity"
	identitypostgres "github.com/TokenFlux/TokenRouter/internal/identity/postgres"
	identityprovider "github.com/TokenFlux/TokenRouter/internal/identity/provider"
)

// mcp_oauth.go assembles the OAuth protocol service and expired-state cleanup.
// Bootstrap supplies an independent persisted signing secret so application
// instances can issue and verify the same opaque credentials. Configuration
// keeps OAuth disabled until its canonical public issuer is supplied, while
// application metadata remains available for browser management and revocation.
//
// Cleanup starts under the application lifecycle and stops before database
// shutdown. Each pass has a bounded context, and shutdown cancels an active
// pass before waiting for its worker. Family cleanup retains consumed refresh
// records while another family member remains unexpired, preserving replay
// detection across access-token renewal and process restarts.

// provideMCPOAuth constructs OAuth services and registers bounded expired-state cleanup.
// Missing or malformed signing material for an enabled issuer fails assembly.
// The repository and user reader share the application's existing database resources.
//
// The lifecycle starts one worker, which owns its ticker and pass-specific timeout.
// Shutdown cancels the worker context before waiting for its completion channel,
// so an active SQL cleanup can stop before the database pool closes. Failed passes
// are logged and retried on the next hourly tick; they do not authorize requests
// or remove still-live replay detection records.
func provideMCPOAuth(db *sql.DB, users *identity.UserService, cfg *config.Config, manager *lifecycle.Manager) (*identityprovider.MCPOAuthServer, error) {
	repo := identitypostgres.NewMCPOAuthStore(db)
	var secret []byte
	if cfg.MCP.OAuth.IssuerURL != "" {
		var err error
		secret, err = hex.DecodeString(cfg.MCP.OAuth.SigningSecret)
		if err != nil || len(secret) != 32 {
			return nil, fmt.Errorf("MCP OAuth signing secret is unavailable")
		}
	}
	server := identityprovider.NewMCPOAuthServer(repo, users, cfg.MCP.OAuth.IssuerURL, secret)
	if !server.Enabled() {
		return server, nil
	}
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
