// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package command

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/bifrostsec/bifrost-cli/internal/auth"
	"github.com/bifrostsec/bifrost-cli/internal/config"
)

// TokenStore says where `bifrost auth github-actions` puts the access token.
type TokenStore string

const (
	// StoreGitHubEnv exports the token as BIFROST_API_KEY to the later steps
	// of the current job through the file named by GITHUB_ENV. Nothing is
	// written to disk that could outlive the job on a shared runner.
	StoreGitHubEnv TokenStore = "github-env"
	// StoreProfile caches the token in the profile's credentials file.
	StoreProfile TokenStore = "profile"

	// exportedTokenVariable is the variable later steps read the token from;
	// it is the first source of the credential chain.
	exportedTokenVariable = "BIFROST_API_KEY"
)

// AuthGitHubActionsOptions are the resolved inputs of `bifrost auth github-actions`.
type AuthGitHubActionsOptions struct {
	Exchange auth.GitHubActionsOptions
	Store    TokenStore
	// GitHubEnvPath is the file named by GITHUB_ENV, required for StoreGitHubEnv.
	GitHubEnvPath string
}

// authGitHubActions implements `bifrost auth github-actions`: it exchanges
// the job's GitHub OIDC token for a portal access token and hands it to the
// following steps, so they authenticate without any long-lived secret.
type authGitHubActions struct {
	cfg      *config.Config
	opts     AuthGitHubActionsOptions
	exchange *auth.GitHubActionsExchange
	stdout   io.Writer
	stderr   io.Writer
}

// NewAuthGitHubActions fails when the exchange cannot be performed in the
// current environment, with an error that explains what is missing.
func NewAuthGitHubActions(cfg *config.Config, opts AuthGitHubActionsOptions) (Task, error) {
	switch opts.Store {
	case StoreGitHubEnv:
		if opts.GitHubEnvPath == "" {
			return nil, fmt.Errorf("cannot export the access token to later steps: %s is not set; use --store %s to cache it in the profile instead", auth.GitHubEnvFileVariable, StoreProfile)
		}
	case StoreProfile:
	default:
		return nil, fmt.Errorf("unknown token store %q (expected %s or %s)", opts.Store, StoreGitHubEnv, StoreProfile)
	}
	exchange, hint := auth.NewGitHubActionsExchange(opts.Exchange)
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
	return &authGitHubActions{cfg: cfg, opts: opts, exchange: exchange, stdout: os.Stdout, stderr: os.Stderr}, nil
}

func (t *authGitHubActions) Run(ctx context.Context) error {
	credentials, err := t.exchange.Exchange(ctx)
	if err != nil {
		return err
	}
	var message string
	switch t.opts.Store {
	case StoreGitHubEnv:
		if err := t.exportToGitHubEnv(credentials.Token); err != nil {
			return err
		}
		message = fmt.Sprintf(
			"Exported access token for organization %s to the later steps of this job as %s",
			t.exchange.OrgID(),
			exportedTokenVariable,
		)
	case StoreProfile:
		if err := auth.StoreAccessToken(t.cfg, credentials); err != nil {
			return err
		}
		message = fmt.Sprintf(
			"Stored access token for organization %s in profile %q (%s)",
			t.exchange.OrgID(),
			t.cfg.Profile,
			config.DisplayPath(t.cfg.CredentialsPath),
		)
	}
	if !credentials.ExpiresAt.IsZero() {
		message += fmt.Sprintf(", expires at %s", credentials.ExpiresAt.Format(time.RFC3339))
	}
	_, _ = fmt.Fprintln(t.stderr, message)
	return nil
}

// exportToGitHubEnv makes the token available to later steps and asks the
// runner to redact it from logs, the way the aws-actions credentials action does.
func (t *authGitHubActions) exportToGitHubEnv(token string) error {
	if strings.ContainsAny(token, "\r\n") {
		return fmt.Errorf("refusing to export an access token that contains line breaks")
	}
	// The mask must be in place before anything could echo the value.
	if _, err := fmt.Fprintf(t.stdout, "::add-mask::%s\n", token); err != nil {
		return fmt.Errorf("failed to mask the access token: %w", err)
	}
	file, err := os.OpenFile(t.opts.GitHubEnvPath, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("failed to open %s file: %w", auth.GitHubEnvFileVariable, err)
	}
	if _, err := fmt.Fprintf(file, "%s=%s\n", exportedTokenVariable, token); err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to write %s file: %w", auth.GitHubEnvFileVariable, err)
	}
	return file.Close()
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
