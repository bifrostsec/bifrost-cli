// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package auth

import (
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
