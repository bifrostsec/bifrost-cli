// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bifrostsec/bifrost-cli/internal/config"
	"github.com/bifrostsec/bifrost-cli/internal/testutil"
)

func TestMain(m *testing.M) {
	cleanup := testutil.IsolateEnvironment()
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func testChain(apiKey, accessToken, expiresAt string) *Chain {
	chain := &Chain{
		profile:              "test",
		apiKey:               config.Resolved{Setting: config.Setting{Name: "api_key"}, Source: config.SourceNotSet},
		accessToken:          config.Resolved{Setting: config.Setting{Name: config.AccessTokenSetting}, Source: config.SourceNotSet},
		accessTokenExpiresAt: config.Resolved{Setting: config.Setting{Name: config.AccessTokenExpiresAtSetting}, Source: config.SourceNotSet},
		now:                  func() time.Time { return time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC) },
		output:               &bytes.Buffer{},
	}
	if apiKey != "" {
		chain.apiKey.Value, chain.apiKey.Source, chain.apiKey.Location = apiKey, config.SourceEnvironment, "BIFROST_API_KEY"
	}
	if accessToken != "" {
		chain.accessToken.Value, chain.accessToken.Source, chain.accessToken.Location = accessToken, config.SourceCredentialsFile, "/tmp/credentials"
	}
	if expiresAt != "" {
		chain.accessTokenExpiresAt.Value, chain.accessTokenExpiresAt.Source, chain.accessTokenExpiresAt.Location = expiresAt, config.SourceCredentialsFile, "/tmp/credentials"
	}
	return chain
}

func TestChain_APIKeyTakesPrecedence(t *testing.T) {
	chain := testChain("api-key", "cached-token", "2026-11-16T13:00:00Z")

	credentials, err := chain.Resolve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "api-key", credentials.Token)
	assert.Equal(t, "environment variable BIFROST_API_KEY", credentials.Source)
	assert.True(t, credentials.ExpiresAt.IsZero())
}

func TestChain_UsesCachedAccessTokenUntilExpiry(t *testing.T) {
	chain := testChain("", "cached-token", "2026-11-16T12:05:00Z")

	credentials, err := chain.Resolve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "cached-token", credentials.Token)
	assert.Equal(t, "credentials-file /tmp/credentials", credentials.Source)
	assert.Equal(t, time.Date(2026, 11, 16, 12, 5, 0, 0, time.UTC), credentials.ExpiresAt)

	chain = testChain("", "cached-token", "")
	credentials, err = chain.Resolve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "cached-token", credentials.Token, "a token without expiry never expires")
}

func TestChain_RejectsExpiredOrExpiringCachedAccessToken(t *testing.T) {
	for name, expiresAt := range map[string]string{
		"expired":           "2026-11-16T11:00:00Z",
		"within skew":       "2026-11-16T12:00:20Z",
		"exactly skew edge": "2026-11-16T12:00:30Z",
	} {
		t.Run(name, func(t *testing.T) {
			chain := testChain("", "cached-token", expiresAt)
			_, err := chain.Resolve(context.Background())
			require.Error(t, err)
			assert.Contains(t, err.Error(), `no credentials found for profile "test"`)
			assert.Contains(t, err.Error(), "cached access token in credentials-file /tmp/credentials expired at "+expiresAt)
		})
	}
}

func TestChain_ReportsInvalidExpiry(t *testing.T) {
	chain := testChain("", "cached-token", "tomorrow")

	_, err := chain.Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), `invalid access_token_expires_at "tomorrow"`)
}

func TestChain_IncludesGitHubActionsHint(t *testing.T) {
	chain := testChain("", "", "")
	chain.githubActionsHint = "running in GitHub Actions without an OIDC token request environment"

	err := chain.Check()
	require.Error(t, err)
	assert.Contains(t, err.Error(), chain.githubActionsHint)
}

func TestNewChain_PicksUpResolvedSettings(t *testing.T) {
	resolved := []config.Resolved{
		{Setting: config.Setting{Name: "api_key"}, Value: "k", Source: config.SourceCommandLine, Location: "--api-key"},
	}
	chain := NewChain(ChainOptions{Profile: "p", Settings: resolved})
	assert.Equal(t, "p", chain.profile)
	assert.Nil(t, chain.githubActions, "not running in GitHub Actions")
	assert.Empty(t, chain.githubActionsHint)

	credentials, err := chain.Resolve(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "k", credentials.Token)
	assert.Equal(t, "option --api-key", credentials.Source)
}

func TestStoreAccessToken(t *testing.T) {
	_, credentialsPath := testutil.WriteConfigFiles(t, "", "")
	cfg, err := config.Load("ci")
	require.NoError(t, err)

	expiresAt := time.Date(2026, 11, 16, 12, 10, 0, 0, time.FixedZone("CET", 3600))
	require.NoError(t, StoreAccessToken(cfg, Credentials{Token: "token", ExpiresAt: expiresAt}))
	assert.Equal(t, "[ci]\naccess_token = token\naccess_token_expires_at = 2026-11-16T11:10:00Z\n", testutil.ReadFile(t, credentialsPath))

	require.NoError(t, StoreAccessToken(cfg, Credentials{Token: "forever"}))
	assert.Equal(t, "[ci]\naccess_token = forever\n", testutil.ReadFile(t, credentialsPath), "a token without expiry drops the stale expiry")
}
