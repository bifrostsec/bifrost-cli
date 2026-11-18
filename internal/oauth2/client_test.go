// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bifrostsec/bifrost-cli/internal/retry"
)

func TestClient_ExchangeToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, TokenEndpointPath, r.URL.Path)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "bifrost-cli/1.0", r.Header.Get("User-Agent"))
		require.NoError(t, r.ParseForm())
		assert.Equal(t, GrantTypeTokenExchange, r.PostForm.Get("grant_type"))
		assert.Equal(t, TokenTypeJWT, r.PostForm.Get("subject_token_type"))
		assert.Equal(t, "subject", r.PostForm.Get("subject_token"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged",
			"token_type":        "Bearer",
			"expires_in":        600,
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
	}))
	defer server.Close()
	client := &Client{HTTPClient: server.Client(), ServerURL: server.URL + "/", UserAgent: "bifrost-cli/1.0"}

	token, err := client.ExchangeToken(context.Background(), "subject")
	require.NoError(t, err)
	assert.Equal(t, "exchanged", token.AccessToken)
	assert.Equal(t, 600, token.ExpiresIn)
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	assert.Equal(t, now.Add(10*time.Minute), token.ExpiresAt(now))
	assert.True(t, TokenResponse{}.ExpiresAt(now).IsZero())
}

func TestClient_RetriesTransientFailures(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch requests.Add(1) {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable)
		case 2:
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":"rate_limited"}`))
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "exchanged", "token_type": "Bearer", "expires_in": 600})
		}
	}))
	defer server.Close()
	var waits []time.Duration
	var notices []string
	client := &Client{
		HTTPClient: server.Client(), ServerURL: server.URL, UserAgent: "bifrost-cli/1.0",
		Retry: retry.Policy{
			Attempts: 3,
			Delay:    time.Second,
			Notify: func(err error, attempt, attempts int, wait time.Duration) {
				notices = append(notices, fmt.Sprintf("%d/%d %s: %v", attempt, attempts, wait, err))
			},
			Sleep: func(_ context.Context, d time.Duration) error { waits = append(waits, d); return nil },
		},
	}

	token, err := client.ExchangeToken(context.Background(), "subject")
	require.NoError(t, err)
	assert.Equal(t, "exchanged", token.AccessToken)
	assert.Equal(t, int32(3), requests.Load())
	assert.Equal(t, []time.Duration{time.Second, 7 * time.Second}, waits, "backoff, then the server's Retry-After")
	require.Len(t, notices, 2)
	assert.Equal(t, "1/3 1s: token endpoint returned 503", notices[0])
	assert.Equal(t, "2/3 7s: token endpoint returned 429: rate_limited: (rate limited)", notices[1])
}

func TestClient_DoesNotRetryClientErrors(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer server.Close()
	client := &Client{HTTPClient: server.Client(), ServerURL: server.URL, Retry: retry.Policy{Attempts: 3}}

	_, err := client.ExchangeToken(context.Background(), "subject")
	require.Error(t, err)
	assert.Equal(t, int32(1), requests.Load())
	var transient *retry.TransientError
	assert.False(t, errors.As(err, &transient))
	var oauthErr *Error
	require.ErrorAs(t, err, &oauthErr)
	assert.Equal(t, "invalid_grant", oauthErr.Code)
}

func TestClient_RetriesNetworkErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	url := server.URL
	server.Close()
	calls := 0
	client := &Client{ServerURL: url, Retry: retry.Policy{Attempts: 2, Sleep: func(context.Context, time.Duration) error { calls++; return nil }}}

	_, err := client.ExchangeToken(context.Background(), "subject")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to send token request")
	assert.Equal(t, 2, calls, "network errors are retried")
}

func TestClient_DoesNotFollowRedirects(t *testing.T) {
	var leaked atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		leaked.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()
	for _, status := range []int{http.StatusMovedPermanently, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, other.URL+TokenEndpointPath, status)
			}))
			defer server.Close()
			client := &Client{HTTPClient: server.Client(), ServerURL: server.URL, UserAgent: "bifrost-cli/1.0"}

			_, err := client.ExchangeToken(context.Background(), "subject")
			require.Error(t, err)
			assert.Contains(t, err.Error(), fmt.Sprintf("token endpoint returned %d: redirect to %q is not followed", status, other.URL+TokenEndpointPath))
			assert.False(t, leaked.Load(), "the subject token must not be replayed to the redirect target")
			assert.Nil(t, client.HTTPClient.CheckRedirect, "the caller's client is left untouched")
		})
	}
}

func TestClient_ErrorResponses(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		expected string
	}{
		{"oauth error", http.StatusBadRequest, `{"error":"invalid_request","error_description":"Missing required parameter: subject_token"}`, "token endpoint returned 400: invalid_request: Missing required parameter: subject_token"},
		{"rate limited", http.StatusTooManyRequests, `too many requests`, "token endpoint returned 429: too many requests (rate limited)"},
		{"html error page", http.StatusBadGateway, `<html>bad gateway</html>`, "token endpoint returned 502: <html>bad gateway</html>"},
		{"missing access token", http.StatusOK, `{"token_type":"Bearer"}`, "token response did not include an access token"},
		{"unsupported token type", http.StatusOK, `{"access_token":"x","token_type":"MAC"}`, `unsupported token type "MAC"`},
		{"invalid json", http.StatusOK, `{`, "failed to parse token response"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer server.Close()
			client := &Client{HTTPClient: server.Client(), ServerURL: server.URL, UserAgent: "bifrost-cli/1.0"}

			_, err := client.ExchangeToken(context.Background(), "subject")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.expected)

			var oauthErr *Error
			if tt.status != http.StatusOK {
				require.ErrorAs(t, err, &oauthErr)
				assert.Equal(t, tt.status, oauthErr.StatusCode)
			}
		})
	}
}
