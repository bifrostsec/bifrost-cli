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
	"github.com/bifrostsec/bifrost-cli/internal/retry"
)

// Environment provided to GitHub Actions jobs that have `permissions: id-token: write`,
// see https://docs.github.com/en/actions/concepts/security/openid-connect
const (
	GitHubActionsEnvironmentVariable         = "GITHUB_ACTIONS"
	GitHubActionsIDTokenRequestURLVariable   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	GitHubActionsIDTokenRequestTokenVariable = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
	GitHubActionsIDTokenPermissionHint       = "grant the job `permissions: id-token: write`"
	// GitHubEnvFileVariable names the file a step appends `NAME=value` lines to
	// in order to export environment variables to the later steps of its job.
	GitHubEnvFileVariable = "GITHUB_ENV"

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
	// The request carries the job's bearer token; never follow a redirect with it.
	noRedirect := *client
	noRedirect.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	resp, err := noRedirect.Do(req)
	if err != nil {
		return "", retry.Transient(fmt.Errorf("failed to request GitHub OIDC token: %w", err), 0)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("GitHub OIDC token request failed: %s: %s", resp.Status, string(body))
		if retry.IsTransientStatus(resp.StatusCode) {
			// GitHub's own toolkit retries this request on 5xx as well.
			return "", retry.Transient(err, retry.RetryAfter(resp, time.Now()))
		}
		return "", err
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
	// RetryAttempts and RetryDelay govern retries of transient failures when
	// fetching the OIDC token and when exchanging it; GitHub and the portal
	// both answer with 429 or 5xx under load.
	RetryAttempts int
	RetryDelay    time.Duration
	// Output receives retry notices; nil disables them.
	Output io.Writer
}

// GitHubActionsExchange obtains a portal access token for a GitHub Actions
// job: it fetches an OIDC token with the bifrost organization id as audience
// and exchanges it at the portal token endpoint (RFC 8693).
type GitHubActionsExchange struct {
	env    GitHubActionsEnvironment
	oauth2 *oauth2.Client
	orgID  string
	retry  retry.Policy
	now    func() time.Time
}

// retryNotifier reports a retry to output in the same shape as the upload client.
func retryNotifier(output io.Writer, operation string) func(err error, attempt, attempts int, wait time.Duration) {
	if output == nil {
		return nil
	}
	return func(err error, attempt, attempts int, wait time.Duration) {
		_, _ = fmt.Fprintf(output, "%s failed: %v. Retrying in %s (%d/%d)\n", operation, err, wait, attempt, attempts)
	}
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
	policy := retry.Policy{Attempts: max(opts.RetryAttempts, 0), Delay: max(opts.RetryDelay, 0)}
	exchangePolicy := policy
	exchangePolicy.Notify = retryNotifier(opts.Output, "Token exchange")
	policy.Notify = retryNotifier(opts.Output, "GitHub OIDC token request")
	return &GitHubActionsExchange{
		env: env,
		oauth2: &oauth2.Client{
			HTTPClient: &http.Client{Timeout: opts.HTTPTimeout},
			ServerURL:  opts.ServerURL,
			UserAgent:  opts.UserAgent,
			Retry:      exchangePolicy,
		},
		orgID: opts.OrgID,
		retry: policy,
		now:   time.Now,
	}, ""
}

// OrgID is the organization the exchange issues tokens for.
func (g *GitHubActionsExchange) OrgID() string {
	return g.orgID
}

// Exchange fetches the OIDC token and exchanges it for a portal access token,
// retrying transient failures of either request.
func (g *GitHubActionsExchange) Exchange(ctx context.Context) (Credentials, error) {
	var idToken string
	err := g.retry.Do(ctx, func(ctx context.Context) error {
		var err error
		idToken, err = g.env.FetchIDToken(ctx, g.oauth2.HTTPClient, g.orgID)
		return err
	})
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
