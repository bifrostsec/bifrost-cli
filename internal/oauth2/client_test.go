// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package oauth2

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestClient_ErrorResponses(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		expected string
	}{
		{"oauth error", http.StatusBadRequest, `{"error":"invalid_request","error_description":"Missing required parameter: subject_token"}`, "token endpoint returned 400: invalid_request: Missing required parameter: subject_token"},
		{"rate limited", http.StatusTooManyRequests, `too many requests`, "token endpoint returned 429: too many requests (rate limited, retry later)"},
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
