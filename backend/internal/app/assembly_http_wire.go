//go:build wireinject

package app

import (
	"github.com/google/wire"

	"github.com/TokenFlux/TokenRouter/internal/server"
	serverhttp "github.com/TokenFlux/TokenRouter/internal/server/httpapi"
)

// assembly_http_wire.go registers HTTP server construction, route mounts, and
// runtime settings readers with Wire.
// Panel, authentication, payment, and gateway routes are mounted on the
// application HTTP server. The graph resolves each mount with its handlers and
// supplies runtime panel settings, forwarded-header settings, and request
// logging before server construction.

// httpAssemblyProviders supplies server construction, route mounts, and the
// runtime settings handlers used by the HTTP application.
var httpAssemblyProviders = wire.NewSet(
	nativeHTTPProviders,
	server.ProviderSet,
	provideHTTPOptions,
	provideHTTPRouteMount,
	provideAuthRouteMount,
	provideUserRouteMount,
	provideAdminRouteMount,
	provideGatewayRouteMount,
	providePaymentRouteMount,
	provideForwardedSettings,
	providePanelSettings,
	serverhttp.NewPanelSettingsHandler,
	provideRouterRuntime,
	provideRequestLog,
	provideMCPOAuth,
	provideMCPTokens,
	provideMCPHTTP,
)
