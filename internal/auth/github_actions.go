// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/bifrostsec/bifrost-cli/internal/oauth2"
)

// Environment provided to GitHub Actions jobs that have `permissions: id-token: write`,
// see https://docs.github.com/en/actions/concepts/security/openid-connect
const (
	GitHubActionsEnvironmentVariable         = "GITHUB_ACTIONS"
	GitHubActionsIDTokenRequestURLVariable   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	GitHubActionsIDTokenRequestTokenVariable = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
	GitHubActionsIDTokenPermissionHint       = "grant the job `permissions: id-token: write`"

	// GitHubActionsCredentialSource labels credentials obtained through the exchange.
	GitHubActionsCredentialSource = "GitHub Actions OIDC token exchange"
)

// GitHubActionsEnvironment is the OIDC token request endpoint GitHub exposes to a job.
type GitHubActionsEnvironment struct {
	RequestURL   string
	RequestToken string
}

// DetectGitHubActions reads the OIDC token request environment. The returned
// hint explains why no token can be requested and is empty when it can, or
// when the CLI is not running in GitHub Actions at all.
func DetectGitHubActions() (env GitHubActionsEnvironment, hint string) {
	env = GitHubActionsEnvironment{
		RequestURL:   os.Getenv(GitHubActionsIDTokenRequestURLVariable),
		RequestToken: os.Getenv(GitHubActionsIDTokenRequestTokenVariable),
	}
	if env.Available() {
		return env, ""
	}
	if os.Getenv(GitHubActionsEnvironmentVariable) == "true" {
		return env, "running in GitHub Actions without an OIDC token request environment: " + GitHubActionsIDTokenPermissionHint
	}
	return env, ""
}

// Available reports whether an OIDC token can be requested.
func (e GitHubActionsEnvironment) Available() bool {
	return e.RequestURL != "" && e.RequestToken != ""
}

// FetchIDToken requests an OIDC token for the given audience from GitHub Actions.
func (e GitHubActionsEnvironment) FetchIDToken(ctx context.Context, client *http.Client, audience string) (string, error) {
	requestURL, err := url.Parse(e.RequestURL)
	if err != nil {
		return "", fmt.Errorf("invalid %s: %w", GitHubActionsIDTokenRequestURLVariable, err)
	}
	query := requestURL.Query()
	query.Set("audience", audience)
	requestURL.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return "", fmt.Errorf("failed to create GitHub OIDC token request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+e.RequestToken)
	req.Header.Set("Accept", "application/json; api-version=2.0")

	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to request GitHub OIDC token: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub OIDC token request failed: %s: %s", resp.Status, string(body))
	}

	var payload struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("failed to parse GitHub OIDC token response: %w", err)
	}
	if payload.Value == "" {
		return "", fmt.Errorf("GitHub OIDC token response did not include a token")
	}
	return payload.Value, nil
}

// GitHubActionsOptions configures the OIDC token exchange.
type GitHubActionsOptions struct {
	// ServerURL is the portal that issues the access token.
	ServerURL string
	// OrgID is the bifrost organization id, used as audience of the OIDC token.
	OrgID       string
	HTTPTimeout time.Duration
	UserAgent   string
}

// GitHubActionsExchange obtains a portal access token for a GitHub Actions
// job: it fetches an OIDC token with the bifrost organization id as audience
// and exchanges it at the portal token endpoint (RFC 8693).
type GitHubActionsExchange struct {
	env    GitHubActionsEnvironment
	oauth2 *oauth2.Client
	orgID  string
	now    func() time.Time
}

// NewGitHubActionsExchange returns the exchange when it can be performed in
// the current environment, otherwise nil and a hint explaining what is missing.
// Both are nil and empty when the CLI is not running in GitHub Actions.
func NewGitHubActionsExchange(opts GitHubActionsOptions) (exchange *GitHubActionsExchange, hint string) {
	env, hint := DetectGitHubActions()
	if hint != "" {
		return nil, hint
	}
	if !env.Available() {
		return nil, ""
	}
	if opts.OrgID == "" {
		return nil, "a GitHub Actions OIDC token is available but no organization id is configured: pass --org-id, set BIFROST_ORG_ID, or run `bifrost config set org_id <id>`"
	}
	return &GitHubActionsExchange{
		env: env,
		oauth2: &oauth2.Client{
			HTTPClient: &http.Client{Timeout: opts.HTTPTimeout},
			ServerURL:  opts.ServerURL,
			UserAgent:  opts.UserAgent,
		},
		orgID: opts.OrgID,
		now:   time.Now,
	}, ""
}

// OrgID is the organization the exchange issues tokens for.
func (g *GitHubActionsExchange) OrgID() string {
	return g.orgID
}

// Exchange fetches the OIDC token and exchanges it for a portal access token.
func (g *GitHubActionsExchange) Exchange(ctx context.Context) (Credentials, error) {
	idToken, err := g.env.FetchIDToken(ctx, g.oauth2.HTTPClient, g.orgID)
	if err != nil {
		return Credentials{}, err
	}
	token, err := g.oauth2.ExchangeToken(ctx, idToken)
	if err != nil {
		return Credentials{}, fmt.Errorf("failed to exchange GitHub Actions OIDC token for organization %s: %w", g.orgID, err)
	}
	return Credentials{
		Token:     token.AccessToken,
		Source:    GitHubActionsCredentialSource,
		ExpiresAt: token.ExpiresAt(g.now()),
		ServerURL: g.oauth2.ServerURL,
		OrgID:     g.orgID,
	}, nil
}
