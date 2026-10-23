package app

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/TokenFlux/TokenRouter/internal/config"
	"github.com/TokenFlux/TokenRouter/internal/infra/crypto"
)

// mcp_test.go verifies artifact encryption across OAuth application instances.
// The tests use independent encryptors with shared persisted key material and
// preserve configured TOTP encryption for existing manual-token deployments.

// TestMCPArtifactCipherUsesDurableOAuthKey constructs two instances whose temporary
// TOTP keys differ. Shared OAuth signing material must yield interoperable file
// encryption, while a configured TOTP cipher retains its original identity.
func TestMCPArtifactCipherUsesDurableOAuthKey(t *testing.T) {
	first, err := crypto.NewAESEncryptor(bytes.Repeat([]byte{1}, 32))
	require.NoError(t, err)
	second, err := crypto.NewAESEncryptor(bytes.Repeat([]byte{2}, 32))
	require.NoError(t, err)
	cfg := &config.Config{MCP: config.MCPConfig{OAuth: config.MCPOAuthConfig{IssuerURL: "https://gateway.example", SigningSecret: strings.Repeat("ab", 32)}}}
	a, err := mcpArtifactCipher(first, cfg)
	require.NoError(t, err)
	b, err := mcpArtifactCipher(second, cfg)
	require.NoError(t, err)
	ciphertext, err := a.Encrypt("protected fixture")
	require.NoError(t, err)
	plaintext, err := b.Decrypt(ciphertext)
	require.NoError(t, err)
	require.Equal(t, "protected fixture", plaintext)
	_, err = first.Decrypt(ciphertext)
	require.Error(t, err)
	cfg.Totp.EncryptionKeyConfigured = true
	original, err := mcpArtifactCipher(first, cfg)
	require.NoError(t, err)
	require.Same(t, first, original)
	cfg.Totp.EncryptionKeyConfigured = false
	cfg.MCP.OAuth.IssuerURL = ""
	original, err = mcpArtifactCipher(first, cfg)
	require.NoError(t, err)
	require.Same(t, first, original)
}
