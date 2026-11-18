// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

// Package oauth2 is a minimal client for the portal's OAuth 2.0 token endpoint.
// It currently implements Token Exchange (RFC 8693); other grants, such as the
// ones an interactive login needs, add methods that build on Client.Token.
package oauth2

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bifrostsec/bifrost-cli/internal/retry"
)

const (
	// TokenEndpointPath is the token endpoint relative to the portal URL.
	TokenEndpointPath = "/oauth2/token"

	// GrantTypeTokenExchange is the Token Exchange grant, RFC 8693 section 2.1.
	GrantTypeTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange"
	// TokenTypeJWT identifies a JWT subject token, RFC 8693 section 3.
	TokenTypeJWT = "urn:ietf:params:oauth:token-type:jwt"
)

// TokenResponse is the successful token endpoint response, RFC 6749 section 5.1.
type TokenResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	RefreshToken    string `json:"refresh_token"`
	IssuedTokenType string `json:"issued_token_type"`
}

// ExpiresAt converts the relative lifetime into an absolute time, zero when the server did not say.
func (r TokenResponse) ExpiresAt(now time.Time) time.Time {
	if r.ExpiresIn <= 0 {
		return time.Time{}
	}
	return now.Add(time.Duration(r.ExpiresIn) * time.Second).UTC().Truncate(time.Second)
}

// Error is an error response from the token endpoint, RFC 6749 section 5.2.
type Error struct {
	StatusCode  int
	Code        string `json:"error"`
	Description string `json:"error_description"`
}

func (e *Error) Error() string {
	message := fmt.Sprintf("token endpoint returned %d", e.StatusCode)
	if e.Code != "" {
		message += ": " + e.Code
	}
	if e.Description != "" {
		message += ": " + e.Description
	}
	return message
}

// Client talks to the token endpoint of the portal at ServerURL.
type Client struct {
	HTTPClient *http.Client
	ServerURL  string
	UserAgent  string
	// Retry governs how network errors, 408, 429 and 5xx responses are
	// retried; the zero value gives up after the first failure.
	Retry retry.Policy
}

// TokenEndpoint is the absolute token endpoint URL.
func (c *Client) TokenEndpoint() string {
	return strings.TrimRight(c.ServerURL, "/") + TokenEndpointPath
}

// ExchangeToken performs a Token Exchange (RFC 8693), trading a subject token
// (for example a GitHub Actions OIDC token) for a portal access token.
func (c *Client) ExchangeToken(ctx context.Context, subjectToken string) (TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", GrantTypeTokenExchange)
	form.Set("subject_token_type", TokenTypeJWT)
	form.Set("subject_token", subjectToken)
	return c.Token(ctx, form)
}

// httpClient returns a copy of the configured client that does not follow
// redirects. A token request carries the subject token in its body, which a
// 307 or 308 redirect would replay to whatever host the response names.
func (c *Client) httpClient() *http.Client {
	base := c.HTTPClient
	if base == nil {
		base = http.DefaultClient
	}
	client := *base
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &client
}

// Token posts an access token request with the given form parameters,
// retrying transient failures according to Retry.
func (c *Client) Token(ctx context.Context, form url.Values) (TokenResponse, error) {
	var token TokenResponse
	err := c.Retry.Do(ctx, func(ctx context.Context) error {
		var err error
		token, err = c.token(ctx, form)
		return err
	})
	return token, err
}

func (c *Client) token(ctx context.Context, form url.Values) (TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.TokenEndpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.UserAgent)

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return TokenResponse{}, retry.Transient(fmt.Errorf("failed to send token request: %w", err), 0)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		oauthErr := &Error{StatusCode: resp.StatusCode}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			oauthErr.Description = fmt.Sprintf("redirect to %q is not followed for token requests", resp.Header.Get("Location"))
		} else if err := json.Unmarshal(body, oauthErr); err != nil || oauthErr.Code == "" {
			oauthErr.Description = strings.TrimSpace(string(body))
		}
		if resp.StatusCode == http.StatusTooManyRequests {
			oauthErr.Description = strings.TrimSpace(oauthErr.Description + " (rate limited)")
		}
		if retry.IsTransientStatus(resp.StatusCode) {
			return TokenResponse{}, retry.Transient(oauthErr, retry.RetryAfter(resp, time.Now()))
		}
		return TokenResponse{}, oauthErr
	}

	var token TokenResponse
	if err := json.Unmarshal(body, &token); err != nil {
		return TokenResponse{}, fmt.Errorf("failed to parse token response: %w", err)
	}
	if token.AccessToken == "" {
		return TokenResponse{}, fmt.Errorf("token response did not include an access token")
	}
	if token.TokenType != "" && !strings.EqualFold(token.TokenType, "Bearer") {
		return TokenResponse{}, fmt.Errorf("unsupported token type %q, expected Bearer", token.TokenType)
	}
	return token, nil
}
