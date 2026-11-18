// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bifrostsec/bifrost-cli/internal/auth"
	"github.com/bifrostsec/bifrost-cli/internal/command"
)

const storeFlag = "store"

// parseAuthGitHubActionsArgs reads the flags that follow `auth github-actions`.
// The token goes to the later steps of the job when GitHub provides a
// GITHUB_ENV file, and into the profile otherwise.
func parseAuthGitHubActionsArgs(opts Options, cliVersion string, args []string) (command.AuthGitHubActionsOptions, error) {
	githubEnvPath := os.Getenv(auth.GitHubEnvFileVariable)
	defaultStore := command.StoreProfile
	if githubEnvPath != "" {
		defaultStore = command.StoreGitHubEnv
	}

	fl := flag.NewFlagSet("auth github-actions", flag.ContinueOnError)
	fl.SetOutput(io.Discard)
	store := fl.String(storeFlag, string(defaultStore), "")
	if err := fl.Parse(args); err != nil {
		return command.AuthGitHubActionsOptions{}, fmt.Errorf("auth github-actions: %w", err)
	}
	if fl.NArg() != 0 {
		return command.AuthGitHubActionsOptions{}, fmt.Errorf("auth github-actions takes no arguments")
	}
	return command.AuthGitHubActionsOptions{
		Exchange:      opts.githubActionsOptions(cliVersion),
		Store:         command.TokenStore(*store),
		GitHubEnvPath: githubEnvPath,
	}, nil
}
