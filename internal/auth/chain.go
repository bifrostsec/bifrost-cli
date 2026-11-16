// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bifrostsec/bifrost-cli/internal/config"
)

// ChainOptions configures a Chain.
type ChainOptions struct {
	Profile string
	// Settings are the resolved configuration settings; the chain reads the
	// api_key and the cached access_token settings from them.
	Settings []config.Resolved
	// ServerURL and OrgID are the portal and organization of this invocation.
	// A cached access token is only reused when it was issued for them, and
	// the GitHub Actions OIDC token exchange issues tokens for them.
	ServerURL string
	OrgID     string
	// HTTPTimeout and UserAgent apply to the OIDC token exchange.
	HTTPTimeout time.Duration
	UserAgent   string
	// Output receives informational messages, nil disables them.
	Output io.Writer
}

// Chain resolves credentials from the first available source, in order:
//
//  1. an API key from the command line, environment or the profile
//  2. an unexpired access token cached in the profile by a `bifrost auth` command
//  3. a GitHub Actions OIDC token exchanged for an access token, when running
//     in GitHub Actions with an organization id configured
//
// A future interactive login flow adds another cached token source with
// refresh support without changing the commands that consume credentials.
type Chain struct {
	profile              string
	serverURL            string
	orgID                string
	apiKey               config.Resolved
	accessToken          config.Resolved
	accessTokenExpiresAt config.Resolved
	accessTokenServerURL config.Resolved
	accessTokenOrgID     config.Resolved
	githubActions        *GitHubActionsExchange
	githubActionsHint    string
	now                  func() time.Time
	output               io.Writer
}

// NewChain builds the chain from resolved settings and the current environment.
func NewChain(opts ChainOptions) *Chain {
	githubActions, hint := NewGitHubActionsExchange(GitHubActionsOptions{
		ServerURL:   opts.ServerURL,
		OrgID:       opts.OrgID,
		HTTPTimeout: opts.HTTPTimeout,
		UserAgent:   opts.UserAgent,
	})
	return &Chain{
		profile:              opts.Profile,
		serverURL:            opts.ServerURL,
		orgID:                opts.OrgID,
		apiKey:               config.Find(opts.Settings, "api_key"),
		accessToken:          config.Find(opts.Settings, config.AccessTokenSetting),
		accessTokenExpiresAt: config.Find(opts.Settings, config.AccessTokenExpiresAtSetting),
		accessTokenServerURL: config.Find(opts.Settings, config.AccessTokenServerURLSetting),
		accessTokenOrgID:     config.Find(opts.Settings, config.AccessTokenOrgIDSetting),
		githubActions:        githubActions,
		githubActionsHint:    hint,
		now:                  time.Now,
		output:               opts.Output,
	}
}

// Check reports, without any network access, whether some credential source is available.
func (c *Chain) Check() error {
	_, err := c.resolve(context.Background(), false)
	return err
}

// Resolve returns credentials from the first source that provides them.
func (c *Chain) Resolve(ctx context.Context) (Credentials, error) {
	return c.resolve(ctx, true)
}

func (c *Chain) resolve(ctx context.Context, exchange bool) (Credentials, error) {
	if c.apiKey.IsSet() && c.apiKey.Value != "" {
		return Credentials{Token: c.apiKey.Value, Source: c.apiKey.DescribeSource()}, nil
	}

	var problems []string
	if c.accessToken.IsSet() && c.accessToken.Value != "" {
		cached, err := c.cachedAccessToken()
		location := c.accessToken.DescribeSource()
		switch {
		case err != nil:
			problems = append(problems, err.Error())
		case !cached.Valid(c.now()):
			problems = append(problems, fmt.Sprintf("cached access token in %s expired at %s", location, cached.ExpiresAt.Format(time.RFC3339)))
		case cached.ServerURL != "" && !sameServerURL(cached.ServerURL, c.serverURL):
			// Never present a token to a server other than the one that issued it.
			problems = append(problems, fmt.Sprintf("cached access token in %s was issued by %s, not %s", location, cached.ServerURL, c.serverURL))
		case c.orgID != "" && cached.OrgID != "" && cached.OrgID != c.orgID:
			problems = append(problems, fmt.Sprintf("cached access token in %s is for organization %s, not %s", location, cached.OrgID, c.orgID))
		default:
			return cached, nil
		}
	}

	if c.githubActions != nil {
		if !exchange {
			return Credentials{Source: GitHubActionsCredentialSource}, nil
		}
		credentials, err := c.githubActions.Exchange(ctx)
		if err != nil {
			return Credentials{}, err
		}
		c.printExchangeMessage(credentials)
		return credentials, nil
	}
	if c.githubActionsHint != "" {
		problems = append(problems, c.githubActionsHint)
	}

	message := fmt.Sprintf(
		"no credentials found for profile %q: pass --api-key, set BIFROST_API_KEY, run `bifrost config`, or run `bifrost auth github-actions` in a GitHub Actions job",
		c.profile,
	)
	if len(problems) > 0 {
		message += "\n  " + strings.Join(problems, "\n  ")
	}
	return Credentials{}, errors.New(message)
}

// cachedAccessToken assembles the access token stored in the profile. Scope
// settings that were never recorded, for example for a token written by hand
// with `config set`, leave the token usable anywhere.
func (c *Chain) cachedAccessToken() (Credentials, error) {
	cached := Credentials{
		Token:     c.accessToken.Value,
		Source:    c.accessToken.DescribeSource(),
		ServerURL: c.accessTokenServerURL.Value,
		OrgID:     c.accessTokenOrgID.Value,
	}
	if c.accessTokenExpiresAt.Value == "" {
		return cached, nil
	}
	expiresAt, err := time.Parse(time.RFC3339, c.accessTokenExpiresAt.Value)
	if err != nil {
		return Credentials{}, fmt.Errorf("invalid %s %q in %s: expected RFC 3339 timestamp", config.AccessTokenExpiresAtSetting, c.accessTokenExpiresAt.Value, c.accessTokenExpiresAt.DescribeSource())
	}
	cached.ExpiresAt = expiresAt
	return cached, nil
}

// sameServerURL compares portal URLs ignoring case and trailing slashes.
func sameServerURL(a, b string) bool {
	normalize := func(u string) string {
		return strings.TrimRight(strings.ToLower(strings.TrimSpace(u)), "/")
	}
	return normalize(a) == normalize(b)
}

func (c *Chain) printExchangeMessage(credentials Credentials) {
	if c.output == nil {
		return
	}
	message := fmt.Sprintf("Exchanged GitHub Actions OIDC token for a bifrost access token (organization %s", c.githubActions.OrgID())
	if !credentials.ExpiresAt.IsZero() {
		message += fmt.Sprintf(", expires at %s", credentials.ExpiresAt.Format(time.RFC3339))
	}
	_, _ = fmt.Fprintln(c.output, message+")")
}
