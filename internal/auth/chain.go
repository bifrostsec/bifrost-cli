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

// accessTokenExpirySkew treats cached tokens as expired slightly before their
// real expiry so a request does not start with a token about to lapse.
const accessTokenExpirySkew = 30 * time.Second

// ChainOptions configures a Chain.
type ChainOptions struct {
	Profile string
	// Settings are the resolved configuration settings; the chain reads
	// api_key, access_token and access_token_expires_at from them.
	Settings []config.Resolved
	// GitHubActions configures the OIDC token exchange used as the last resort.
	GitHubActions GitHubActionsOptions
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
	apiKey               config.Resolved
	accessToken          config.Resolved
	accessTokenExpiresAt config.Resolved
	githubActions        *GitHubActionsExchange
	githubActionsHint    string
	now                  func() time.Time
	output               io.Writer
}

// NewChain builds the chain from resolved settings and the current environment.
func NewChain(opts ChainOptions) *Chain {
	githubActions, hint := NewGitHubActionsExchange(opts.GitHubActions)
	return &Chain{
		profile:              opts.Profile,
		apiKey:               config.Find(opts.Settings, "api_key"),
		accessToken:          config.Find(opts.Settings, config.AccessTokenSetting),
		accessTokenExpiresAt: config.Find(opts.Settings, config.AccessTokenExpiresAtSetting),
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
		expiresAt, err := c.cachedAccessTokenExpiry()
		switch {
		case err != nil:
			problems = append(problems, err.Error())
		case !expiresAt.IsZero() && !c.now().Add(accessTokenExpirySkew).Before(expiresAt):
			problems = append(problems, fmt.Sprintf("cached access token in %s expired at %s", c.accessToken.DescribeSource(), expiresAt.Format(time.RFC3339)))
		default:
			return Credentials{Token: c.accessToken.Value, Source: c.accessToken.DescribeSource(), ExpiresAt: expiresAt}, nil
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

func (c *Chain) cachedAccessTokenExpiry() (time.Time, error) {
	if !c.accessTokenExpiresAt.IsSet() || c.accessTokenExpiresAt.Value == "" {
		return time.Time{}, nil
	}
	expiresAt, err := time.Parse(time.RFC3339, c.accessTokenExpiresAt.Value)
	if err != nil {
		return time.Time{}, fmt.Errorf("invalid %s %q in %s: expected RFC 3339 timestamp", config.AccessTokenExpiresAtSetting, c.accessTokenExpiresAt.Value, c.accessTokenExpiresAt.DescribeSource())
	}
	return expiresAt, nil
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
