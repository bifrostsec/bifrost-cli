// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	gitRepoPathFlag                  = "git-repo-path"
	gitRepoPathEnvironmentVariable   = "BIFROST_GIT_REPO_PATH"
	gitAutoDetectFlag                = "git-auto-detect"
	gitAutoDetectEnvironmentVariable = "BIFROST_GIT_AUTO_DETECT"
	gitAutoDetectDeprecationWarning  = "Warning: legacy Git auto-detection configuration is deprecated; use --git-repo-path=. or BIFROST_GIT_REPO_PATH=. instead.\n"
)

type Options struct {
	ServerURL      string
	apiKey         string
	service        string
	serviceVersion string
	image          string
	retryAttempts  int
	retryDelay     time.Duration
	gitBranch      string
	gitCommitSHA   string
	gitOrigin      string
	gitRepoPath    string
	gitAutoDetect  bool
}

func RegisterOptions(fl *flag.FlagSet, opts *Options) {
	fl.StringVar(&opts.ServerURL, "server-url", DefaultServerURL, "URL to bifrost server")
	fl.StringVar(&opts.apiKey, "api-key", "", "Bifrost API key (or BIFROST_API_KEY environment variable)")
	fl.StringVar(&opts.service, "service", "", "Name of the service")
	fl.StringVar(&opts.serviceVersion, "service-version", "", "Service version for the uploaded SBOM (or SERVICE_VERSION environment variable); required unless an image is provided")
	fl.StringVar(&opts.image, "image", "", "Container image reference for the uploaded SBOM (or IMAGE environment variable); required unless a service version is provided")
	fl.IntVar(&opts.retryAttempts, "retry-attempts", DefaultRetryAttempts, "Number of retry attempts for transient upload failures")
	fl.DurationVar(&opts.retryDelay, "retry-delay", DefaultRetryDelay, "Delay between upload retry attempts")
	fl.StringVar(&opts.gitBranch, "git-branch", "", "Optional Git branch name for the uploaded SBOM")
	fl.StringVar(&opts.gitCommitSHA, "git-commit-sha", "", "Optional Git commit SHA for the uploaded SBOM")
	fl.StringVar(&opts.gitOrigin, "git-origin", "", "Optional Git origin URL for the uploaded SBOM")
	fl.StringVar(&opts.gitRepoPath, gitRepoPathFlag, "", "Git repository path used for automatic Git metadata detection (or BIFROST_GIT_REPO_PATH environment variable)")
	fl.BoolVar(&opts.gitAutoDetect, gitAutoDetectFlag, false, "Deprecated: use --git-repo-path=.")
}

func ValidateBaseOptions(fl *flag.FlagSet, opts *Options) error {
	if u := os.Getenv("SERVER_URL"); u != "" {
		opts.ServerURL = u
	}
	if u := os.Getenv("BIFROST_SERVER_URL"); u != "" {
		opts.ServerURL = u
	}
	_, err := url.Parse(opts.ServerURL)
	if err != nil {
		return err
	}

	if opts.apiKey == "" {
		opts.apiKey = os.Getenv("BIFROST_API_KEY")
		if opts.apiKey == "" {
			return fmt.Errorf("API key is required")
		}
	}
	if opts.retryAttempts < 0 {
		return fmt.Errorf("retry attempts must be zero or greater")
	}
	if opts.retryDelay < 0 {
		return fmt.Errorf("retry delay must be zero or greater")
	}
	if opts.gitRepoPath == "" {
		opts.gitRepoPath = os.Getenv(gitRepoPathEnvironmentVariable)
	}

	err = handleDeprecatedGitAutoDetect(fl, opts)
	if err != nil {
		return err
	}

	return nil
}

func handleDeprecatedGitAutoDetect(fl *flag.FlagSet, opts *Options) error {
	if opts.gitRepoPath != "" {
		// Git repository path is explicitly set, no need to handle deprecated auto-detect
		return nil
	}

	// Check if Deprecated `git-auto-detect` flag is set or if its corresponding environment variable is set
	if !isFlagSet(fl, gitAutoDetectFlag) {
		if value := os.Getenv(gitAutoDetectEnvironmentVariable); value != "" {
			gitAutoDetect, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("BIFROST_GIT_AUTO_DETECT must be a boolean")
			}
			opts.gitAutoDetect = gitAutoDetect
		}
	}

	if opts.gitAutoDetect {
		// Deprecated `git-auto-detect` is set, configure path to current directory
		opts.gitRepoPath = "."
	}

	return nil
}

func isDeprecatedGitAutoDetectEnvironmentSet(fl *flag.FlagSet, opts *Options) bool {
	return opts.gitRepoPath == "" &&
		os.Getenv(gitRepoPathEnvironmentVariable) == "" &&
		!isFlagSet(fl, gitAutoDetectFlag) &&
		os.Getenv(gitAutoDetectEnvironmentVariable) != ""
}

func isFlagSet(fl *flag.FlagSet, name string) bool {
	isSet := false
	fl.Visit(func(f *flag.Flag) {
		if f.Name == name {
			isSet = true
		}
	})
	return isSet
}
