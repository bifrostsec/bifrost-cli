// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectGitHubActions(t *testing.T) {
	env, hint := DetectGitHubActions()
	assert.False(t, env.Available())
	assert.Empty(t, hint, "outside GitHub Actions there is nothing to hint about")

	t.Setenv(GitHubActionsEnvironmentVariable, "true")
	env, hint = DetectGitHubActions()
	assert.False(t, env.Available())
	assert.Contains(t, hint, GitHubActionsIDTokenPermissionHint)

	t.Setenv(GitHubActionsIDTokenRequestURLVariable, "https://example.com/token")
	t.Setenv(GitHubActionsIDTokenRequestTokenVariable, "request-token")
	env, hint = DetectGitHubActions()
	assert.True(t, env.Available())
	assert.Empty(t, hint)

	exchange, hint := NewGitHubActionsExchange(GitHubActionsOptions{})
	assert.Nil(t, exchange)
	assert.Contains(t, hint, "no organization id is configured")

	exchange, hint = NewGitHubActionsExchange(GitHubActionsOptions{OrgID: "org_1", ServerURL: "https://portal.example.com"})
	require.NotNil(t, exchange)
	assert.Empty(t, hint)
	assert.Equal(t, "org_1", exchange.OrgID())
}

func TestGitHubActionsExchange_Exchange(t *testing.T) {
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "2.0", r.URL.Query().Get("api-version"), "existing query parameters are preserved")
		assert.Equal(t, "org_1", r.URL.Query().Get("audience"))
		assert.Equal(t, "bearer request-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json; api-version=2.0", r.Header.Get("Accept"))
		_ = json.NewEncoder(w).Encode(map[string]any{"count": 1, "value": "id-token"})
	}))
	defer github.Close()
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "id-token", r.PostForm.Get("subject_token"))
		assert.Equal(t, "bifrost-cli/1.0", r.Header.Get("User-Agent"))
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 600})
	}))
	defer portal.Close()
	t.Setenv(GitHubActionsIDTokenRequestURLVariable, github.URL+"/token?api-version=2.0")
	t.Setenv(GitHubActionsIDTokenRequestTokenVariable, "request-token")

	exchange, hint := NewGitHubActionsExchange(GitHubActionsOptions{ServerURL: portal.URL, OrgID: "org_1", UserAgent: "bifrost-cli/1.0", HTTPTimeout: time.Second})
	require.NotNil(t, exchange, hint)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	exchange.now = func() time.Time { return now }

	credentials, err := exchange.Exchange(context.Background())
	require.NoError(t, err)
	assert.Equal(t, Credentials{
		Token:     "access",
		Source:    GitHubActionsCredentialSource,
		ExpiresAt: now.Add(10 * time.Minute),
		ServerURL: portal.URL,
		OrgID:     "org_1",
	}, credentials)
}

func TestGitHubActionsExchange_RetriesTransientFailuresOfBothRequests(t *testing.T) {
	var githubRequests, portalRequests atomic.Int32
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if githubRequests.Add(1) <= 2 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": "id-token"})
	}))
	defer github.Close()
	portal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if portalRequests.Add(1) == 1 {
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 600})
	}))
	defer portal.Close()
	t.Setenv(GitHubActionsIDTokenRequestURLVariable, github.URL)
	t.Setenv(GitHubActionsIDTokenRequestTokenVariable, "request-token")
	var output bytes.Buffer

	exchange, hint := NewGitHubActionsExchange(GitHubActionsOptions{
		ServerURL: portal.URL, OrgID: "org_1", RetryAttempts: 3, RetryDelay: time.Second, Output: &output,
	})
	require.NotNil(t, exchange, hint)
	var waits []time.Duration
	sleep := func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil }
	exchange.retry.Sleep = sleep
	exchange.oauth2.Retry.Sleep = sleep

	credentials, err := exchange.Exchange(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "access", credentials.Token)
	assert.Equal(t, int32(3), githubRequests.Load())
	assert.Equal(t, int32(2), portalRequests.Load())
	assert.Equal(t, []time.Duration{time.Second, 2 * time.Second, 3 * time.Second}, waits, "backoff for GitHub, then the portal's Retry-After")
	assert.Equal(t, "GitHub OIDC token request failed: GitHub OIDC token request failed: 502 Bad Gateway: . Retrying in 1s (1/3)\n"+
		"GitHub OIDC token request failed: GitHub OIDC token request failed: 502 Bad Gateway: . Retrying in 2s (2/3)\n"+
		"Token exchange failed: token endpoint returned 429: (rate limited). Retrying in 3s (1/3)\n", output.String())
}

func TestGitHubActionsExchange_DoesNotRetryRejectedTokens(t *testing.T) {
	var githubRequests atomic.Int32
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		githubRequests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer github.Close()
	t.Setenv(GitHubActionsIDTokenRequestURLVariable, github.URL)
	t.Setenv(GitHubActionsIDTokenRequestTokenVariable, "request-token")

	exchange, _ := NewGitHubActionsExchange(GitHubActionsOptions{ServerURL: "http://127.0.0.1:9", OrgID: "org_1", RetryAttempts: 3})
	_, err := exchange.Exchange(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401 Unauthorized")
	assert.Equal(t, int32(1), githubRequests.Load())
}

func TestGitHubActionsEnvironment_FetchIDTokenDoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		leaked.Store(true)
		_, _ = w.Write([]byte(`{"value":"stolen"}`))
	}))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	env := GitHubActionsEnvironment{RequestURL: server.URL, RequestToken: "t"}

	_, err := env.FetchIDToken(context.Background(), server.Client(), "org_1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GitHub OIDC token request failed: 307 Temporary Redirect")
	assert.False(t, leaked.Load(), "the request token must not be sent to the redirect target")
}

func TestGitHubActionsEnvironment_FetchIDTokenErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("audience") {
		case "forbidden":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("missing id-token permission"))
		case "empty":
			_, _ = w.Write([]byte(`{"count":0,"value":""}`))
		default:
			_, _ = w.Write([]byte(`not json`))
		}
	}))
	defer server.Close()
	env := GitHubActionsEnvironment{RequestURL: server.URL, RequestToken: "t"}

	_, err := env.FetchIDToken(context.Background(), server.Client(), "forbidden")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "GitHub OIDC token request failed: 403 Forbidden: missing id-token permission")

	_, err = env.FetchIDToken(context.Background(), nil, "empty")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "did not include a token")

	_, err = env.FetchIDToken(context.Background(), server.Client(), "garbage")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse GitHub OIDC token response")

	_, err = GitHubActionsEnvironment{RequestURL: "://bad", RequestToken: "t"}.FetchIDToken(context.Background(), nil, "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ACTIONS_ID_TOKEN_REQUEST_URL")
}
