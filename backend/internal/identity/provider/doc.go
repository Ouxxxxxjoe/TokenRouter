// Package provider implements external identity verification and MCP OAuth protocols.
// It translates provider responses into identity domain values and adapts the
// OAuth authorization server to persistent administrator-owned application grants.
//
// Start here:
//   - mcp_oauth.go: administrator consent, authorization codes, refresh, and revocation.
//   - oidc_oauth.go: discovery, token exchange, and external OIDC identity verification.
//   - passkey.go: WebAuthn registration and authentication verification.
//
// File groups:
//   - mcp_oauth*.go: frontend-derived settings, protocol service, client metadata, and Fosite storage.
//   - email_oauth.go, linuxdo_oauth.go, and wechat_oauth.go: external login exchanges.
//   - oidc_oauth.go, settings_oidc_discovery.go, and google_one_tap.go: verified claims and discovery.
//   - dingtalk*.go: enterprise identity and department queries.
//   - aliyun_captcha_verifier.go, tencent_captcha_service.go, and turnstile_service.go: challenge verification.
//   - passkey.go: WebAuthn verification using identity-owned challenge state.
package provider
