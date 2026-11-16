// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package command

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/bifrostsec/bifrost-cli/internal/auth"
	"github.com/bifrostsec/bifrost-cli/internal/config"
)

// authGitHubActions implements `bifrost auth github-actions`: it exchanges
// the job's GitHub OIDC token for a portal access token and caches it in the
// profile, so following steps in the job authenticate without any secrets.
type authGitHubActions struct {
	cfg      *config.Config
	exchange *auth.GitHubActionsExchange
	output   io.Writer
}

// NewAuthGitHubActions fails when the exchange cannot be performed in the
// current environment, with an error that explains what is missing.
func NewAuthGitHubActions(cfg *config.Config, opts auth.GitHubActionsOptions) (Task, error) {
	exchange, hint := auth.NewGitHubActionsExchange(opts)
	if exchange == nil {
		if hint == "" {
			hint = fmt.Sprintf(
				"%s and %s are not set; this command must run in a GitHub Actions job, %s",
				auth.GitHubActionsIDTokenRequestURLVariable,
				auth.GitHubActionsIDTokenRequestTokenVariable,
				auth.GitHubActionsIDTokenPermissionHint,
			)
		}
		return nil, fmt.Errorf("cannot exchange GitHub Actions OIDC token: %s", hint)
	}
	return &authGitHubActions{cfg: cfg, exchange: exchange, output: os.Stderr}, nil
}

func (t *authGitHubActions) Run(ctx context.Context) error {
	credentials, err := t.exchange.Exchange(ctx)
	if err != nil {
		return err
	}
	if err := auth.StoreAccessToken(t.cfg, credentials); err != nil {
		return err
	}
	message := fmt.Sprintf(
		"Stored access token for organization %s in profile %q (%s)",
		t.exchange.OrgID(),
		t.cfg.Profile,
		config.DisplayPath(t.cfg.CredentialsPath),
	)
	if !credentials.ExpiresAt.IsZero() {
		message += fmt.Sprintf(", expires at %s", credentials.ExpiresAt.Format(time.RFC3339))
	}
	_, _ = fmt.Fprintln(t.output, message)
	return nil
}

// authToken implements `bifrost auth token`: it prints the token the CLI
// would authenticate with, resolved through the credential chain.
type authToken struct {
	credentials auth.Resolver
	output      io.Writer
}

func NewAuthToken(credentials auth.Resolver) Task {
	return &authToken{credentials: credentials, output: os.Stdout}
}

func (t *authToken) Run(ctx context.Context) error {
	credentials, err := t.credentials.Resolve(ctx)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(t.output, credentials.Token)
	return nil
}
