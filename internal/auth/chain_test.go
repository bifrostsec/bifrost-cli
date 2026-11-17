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

func fromCredentialsFile(name, value string) config.Resolved {
	r := config.Resolved{Setting: config.Setting{Name: name}, Source: config.SourceNotSet}
	if value != "" {
		r.Value, r.Source, r.Location = value, config.SourceCredentialsFile, "/tmp/credentials"
	}
	return r
}

func testChain(apiKey, accessToken, expiresAt string) *Chain {
	chain := &Chain{
		profile:              "test",
		serverURL:            "https://portal.example.com",
		apiKey:               config.Resolved{Setting: config.Setting{Name: "api_key"}, Source: config.SourceNotSet},
		accessToken:          fromCredentialsFile(config.AccessTokenSetting, accessToken),
		accessTokenExpiresAt: fromCredentialsFile(config.AccessTokenExpiresAtSetting, expiresAt),
		accessTokenServerURL: fromCredentialsFile(config.AccessTokenServerURLSetting, ""),
		accessTokenOrgID:     fromCredentialsFile(config.AccessTokenOrgIDSetting, ""),
		now:                  func() time.Time { return time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC) },
		output:               &bytes.Buffer{},
	}
	if apiKey != "" {
		chain.apiKey.Value, chain.apiKey.Source, chain.apiKey.Location = apiKey, config.SourceEnvironment, "BIFROST_API_KEY"
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

func TestChain_ReusesCachedAccessTokenOnlyForItsServerAndOrganization(t *testing.T) {
	scoped := func(serverURL, orgID string) *Chain {
		chain := testChain("", "cached-token", "2026-11-16T13:00:00Z")
		chain.accessTokenServerURL = fromCredentialsFile(config.AccessTokenServerURLSetting, "https://portal.example.com/")
		chain.accessTokenOrgID = fromCredentialsFile(config.AccessTokenOrgIDSetting, "org_a")
		chain.serverURL, chain.orgID = serverURL, orgID
		return chain
	}

	credentials, err := scoped("https://PORTAL.example.com", "").Resolve(context.Background())
	require.NoError(t, err, "same server up to case and trailing slash, organization not given")
	assert.Equal(t, "cached-token", credentials.Token)
	assert.Equal(t, "https://portal.example.com/", credentials.ServerURL)
	assert.Equal(t, "org_a", credentials.OrgID)

	credentials, err = scoped("https://portal.example.com", "org_a").Resolve(context.Background())
	require.NoError(t, err, "same organization")
	assert.Equal(t, "cached-token", credentials.Token)

	_, err = scoped("https://other.example.com", "").Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cached access token in credentials-file /tmp/credentials was issued by https://portal.example.com/, not https://other.example.com")

	_, err = scoped("https://portal.example.com", "org_b").Resolve(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cached access token in credentials-file /tmp/credentials is for organization org_a, not org_b")

	unscoped := testChain("", "cached-token", "")
	unscoped.serverURL, unscoped.orgID = "https://anywhere.example.com", "org_z"
	credentials, err = unscoped.Resolve(context.Background())
	require.NoError(t, err, "a token stored without scope, e.g. by hand, is usable anywhere")
	assert.Equal(t, "cached-token", credentials.Token)
}

func TestSameServerURL(t *testing.T) {
	assert.True(t, sameServerURL("https://Portal.Example.com/", "HTTPS://portal.example.com"), "scheme and host are case-insensitive, trailing slash ignored")
	assert.True(t, sameServerURL("https://portal.example.com/PortalA/", "https://portal.example.com/PortalA"))
	assert.True(t, sameServerURL(" https://portal.example.com:8443 ", "https://portal.example.com:8443/"))
	assert.False(t, sameServerURL("https://portal.example.com/PortalA", "https://portal.example.com/portala"), "paths are case-sensitive")
	assert.False(t, sameServerURL("https://portal.example.com", "http://portal.example.com"), "no scheme downgrade")
	assert.False(t, sameServerURL("https://portal.example.com", "https://portal.example.com:8443"))
	assert.False(t, sameServerURL("https://portal.example.com", "https://portal.example.org"))
	assert.True(t, sameServerURL("not a url/", "not a url"), "unparsable values fall back to a plain comparison")
}

func TestCredentials_Valid(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	assert.False(t, Credentials{}.Valid(now), "no token")
	assert.True(t, Credentials{Token: "t"}.Valid(now), "no expiry")
	assert.True(t, Credentials{Token: "t", ExpiresAt: now.Add(31 * time.Second)}.Valid(now))
	assert.False(t, Credentials{Token: "t", ExpiresAt: now.Add(30 * time.Second)}.Valid(now), "within skew")
	assert.False(t, Credentials{Token: "t", ExpiresAt: now.Add(-time.Minute)}.Valid(now))
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
	require.NoError(t, StoreAccessToken(cfg, Credentials{Token: "token", ExpiresAt: expiresAt, ServerURL: "https://portal.example.com", OrgID: "org_1"}))
	stored := testutil.ReadFile(t, credentialsPath)
	assert.Contains(t, stored, "[ci]\naccess_token = token\n")
	assert.Contains(t, stored, "access_token_expires_at = 2026-11-16T11:10:00Z\n")
	assert.Contains(t, stored, "access_token_server_url = https://portal.example.com\n")
	assert.Contains(t, stored, "access_token_org_id = org_1\n")

	require.NoError(t, StoreAccessToken(cfg, Credentials{Token: "forever"}))
	assert.Equal(t, "[ci]\naccess_token = forever\n", testutil.ReadFile(t, credentialsPath), "a token without expiry or scope drops the stale metadata")
}
