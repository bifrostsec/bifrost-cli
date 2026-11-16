// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/bifrostsec/bifrost-cli/internal/auth"
	"github.com/bifrostsec/bifrost-cli/internal/command"
	"github.com/bifrostsec/bifrost-cli/internal/config"
	"github.com/bifrostsec/bifrost-cli/internal/flagutil"
	"github.com/bifrostsec/bifrost-cli/internal/portal"
)

const (
	profileFlag     = "profile"
	gitRepoPathFlag = "git-repo-path"

	// Deprecated: use --git-repo-path instead.
	gitAutoDetectFlag = "git-auto-detect"
	// Deprecated: use BIFROST_GIT_REPO_PATH instead.
	gitAutoDetectEnvironmentVariable = "BIFROST_GIT_AUTO_DETECT"
	gitAutoDetectDeprecationWarning  = "Warning: legacy Git auto-detection configuration is deprecated; use --git-repo-path=. or BIFROST_GIT_REPO_PATH=. instead.\n"
)

// Options is the normalized state of one invocation after every configuration
// source has been applied.
type Options struct {
	ServerURL      string
	profile        string
	apiKey         string
	orgID          string
	service        string
	serviceVersion string
	image          string
	retryAttempts  int
	retryDelay     time.Duration
	httpTimeout    time.Duration
	gitBranch      string
	gitCommitSHA   string
	gitOrigin      string
	gitRepoPath    string
	gitAutoDetect  bool // Deprecated: retained for the legacy flag and environment variable.
}

// RegisterOptions binds the command-line flags to opts. Every setting in
// config.Settings that has a flag must be registered here.
func RegisterOptions(fl *flag.FlagSet, opts *Options) {
	fl.StringVar(&opts.profile, profileFlag, "", "Profile to read from the config and credentials files (or BIFROST_PROFILE environment variable)")
	fl.StringVar(&opts.ServerURL, "server-url", portal.DefaultServerURL, "URL to bifrost server (or BIFROST_SERVER_URL or SERVER_URL environment variable, or server_url setting)")
	fl.StringVar(&opts.apiKey, "api-key", "", "Bifrost API key (or BIFROST_API_KEY environment variable, or api_key setting)")
	fl.StringVar(&opts.orgID, "org-id", "", "Bifrost organization id used to exchange a GitHub Actions OIDC token for an access token (or BIFROST_ORG_ID environment variable, or org_id setting)")
	fl.StringVar(&opts.service, "service", "", "Name of the service (or SERVICE environment variable)")
	fl.StringVar(&opts.serviceVersion, "service-version", "", "Service version for the uploaded SBOM (or SERVICE_VERSION environment variable); required unless an image is provided")
	fl.StringVar(&opts.image, "image", "", "Container image reference for the uploaded SBOM (or IMAGE environment variable); required unless a service version is provided")
	fl.IntVar(&opts.retryAttempts, "retry-attempts", portal.DefaultRetryAttempts, "Number of retry attempts for transient upload failures (or BIFROST_RETRY_ATTEMPTS environment variable, or retry_attempts setting)")
	fl.DurationVar(&opts.retryDelay, "retry-delay", portal.DefaultRetryDelay, "Delay between upload retry attempts (or BIFROST_RETRY_DELAY environment variable, or retry_delay setting)")
	fl.DurationVar(&opts.httpTimeout, "http-timeout", portal.DefaultHTTPTimeout, "Maximum duration to wait for an HTTP request (or BIFROST_HTTP_TIMEOUT environment variable, or http_timeout setting)")
	fl.StringVar(&opts.gitBranch, "git-branch", "", "Optional Git branch name for the uploaded SBOM")
	fl.StringVar(&opts.gitCommitSHA, "git-commit-sha", "", "Optional Git commit SHA for the uploaded SBOM")
	fl.StringVar(&opts.gitOrigin, "git-origin", "", "Optional Git origin URL for the uploaded SBOM")
	fl.StringVar(&opts.gitRepoPath, gitRepoPathFlag, "", "Git repository path used for automatic Git metadata detection (or BIFROST_GIT_REPO_PATH environment variable, or git_repo_path setting)")
	fl.BoolVar(&opts.gitAutoDetect, gitAutoDetectFlag, false, "DEPRECATED: use --git-repo-path=.")
}

// ResolvedOptions is the outcome of layering command-line flags, environment
// variables and the configuration files on top of the built-in defaults.
type ResolvedOptions struct {
	Config *config.Config
	// Settings holds the effective value and origin of every setting.
	Settings []config.Resolved
	// Profile records how the profile was selected.
	Profile config.Resolved
	// DeprecatedGitAutoDetect is true when the legacy auto-detection flag or
	// environment variable was used instead of a repository path.
	DeprecatedGitAutoDetect bool
}

// ResolveOptions fills opts from every configuration source in order of
// precedence (flags, environment, profile, defaults) and validates the result.
func ResolveOptions(fl *flag.FlagSet, opts *Options) (*ResolvedOptions, error) {
	profile := resolveProfile(fl, opts)
	opts.profile = profile.Value

	cfg, err := config.Load(opts.profile)
	if err != nil {
		return nil, err
	}
	resolved, err := config.Resolve(fl, cfg)
	if err != nil {
		return nil, err
	}
	// Per-upload values have environment variables but no configuration file setting.
	applyEnvironmentFallback(&opts.service, "SERVICE")
	applyEnvironmentFallback(&opts.serviceVersion, "SERVICE_VERSION")
	applyEnvironmentFallback(&opts.image, "IMAGE")

	if _, err := url.Parse(opts.ServerURL); err != nil {
		return nil, err
	}
	if opts.retryAttempts < 0 {
		return nil, fmt.Errorf("retry attempts must be zero or greater")
	}
	if opts.retryDelay < 0 {
		return nil, fmt.Errorf("retry delay must be zero or greater")
	}
	if opts.httpTimeout <= 0 {
		return nil, fmt.Errorf("HTTP timeout must be greater than zero")
	}

	deprecatedGitAutoDetect := isDeprecatedGitAutoDetectSet(fl, opts)
	if err := handleDeprecatedGitAutoDetect(fl, opts); err != nil {
		return nil, err
	}

	return &ResolvedOptions{
		Config:                  cfg,
		Settings:                resolved,
		Profile:                 profile,
		DeprecatedGitAutoDetect: deprecatedGitAutoDetect,
	}, nil
}

func applyEnvironmentFallback(value *string, name string) {
	if *value == "" {
		*value = os.Getenv(name)
	}
}

// resolveProfile picks the profile from the flag, then the environment, then the default.
func resolveProfile(fl *flag.FlagSet, opts *Options) config.Resolved {
	r := config.Resolved{Setting: config.Setting{Name: profileFlag}}
	switch {
	case flagutil.IsSet(fl, profileFlag) && opts.profile != "":
		r.Value, r.Source, r.Location = opts.profile, config.SourceCommandLine, "--"+profileFlag
	case os.Getenv(config.ProfileEnvironmentVariable) != "":
		r.Value, r.Source, r.Location = os.Getenv(config.ProfileEnvironmentVariable), config.SourceEnvironment, config.ProfileEnvironmentVariable
	default:
		r.Value, r.Source = config.DefaultProfile, config.SourceDefault
	}
	return r
}

// handleDeprecatedGitAutoDetect translates legacy auto-detection configuration
// into the Git repository path.
//
// Deprecated: use gitRepoPath instead.
func handleDeprecatedGitAutoDetect(fl *flag.FlagSet, opts *Options) error {
	if opts.gitRepoPath != "" {
		// A repository path is already configured, so legacy auto-detection is ignored.
		return nil
	}

	// The legacy flag takes precedence over its corresponding environment variable.
	if !flagutil.IsSet(fl, gitAutoDetectFlag) {
		if value := os.Getenv(gitAutoDetectEnvironmentVariable); value != "" {
			gitAutoDetect, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("BIFROST_GIT_AUTO_DETECT must be a boolean")
			}
			opts.gitAutoDetect = gitAutoDetect
		}
	}

	if opts.gitAutoDetect {
		// Legacy auto-detection uses the current directory as the repository path.
		opts.gitRepoPath = "."
	}

	return nil
}

// isDeprecatedGitAutoDetectSet reports whether legacy automatic Git metadata
// detection is configured through its flag or environment variable while no
// repository path is configured. It must run after the settings are resolved.
//
// Deprecated: use gitRepoPath instead.
func isDeprecatedGitAutoDetectSet(fl *flag.FlagSet, opts *Options) bool {
	return opts.gitRepoPath == "" &&
		(flagutil.IsSet(fl, gitAutoDetectFlag) || os.Getenv(gitAutoDetectEnvironmentVariable) != "")
}

// sbomUploadOptions maps the resolved options onto the upload command's inputs.
func (o Options) sbomUploadOptions(cliVersion string) command.SBOMUploadOptions {
	return command.SBOMUploadOptions{
		ServerURL:      o.ServerURL,
		Service:        o.service,
		ServiceVersion: o.serviceVersion,
		Image:          o.image,
		RetryAttempts:  o.retryAttempts,
		RetryDelay:     o.retryDelay,
		HTTPTimeout:    o.httpTimeout,
		GitBranch:      o.gitBranch,
		GitCommitSHA:   o.gitCommitSHA,
		GitOrigin:      o.gitOrigin,
		GitRepoPath:    o.gitRepoPath,
		CLIVersion:     cliVersion,
	}
}

// githubActionsOptions maps the resolved options onto the OIDC token exchange inputs.
func (o Options) githubActionsOptions(cliVersion string) auth.GitHubActionsOptions {
	return auth.GitHubActionsOptions{
		ServerURL:   o.ServerURL,
		OrgID:       o.orgID,
		HTTPTimeout: o.httpTimeout,
		UserAgent:   portal.UserAgent(cliVersion),
	}
}

// credentialChain builds the credential provider chain for this invocation.
func (o Options) credentialChain(resolved *ResolvedOptions, cliVersion string) *auth.Chain {
	return auth.NewChain(auth.ChainOptions{
		Profile:       o.profile,
		Settings:      resolved.Settings,
		GitHubActions: o.githubActionsOptions(cliVersion),
		Output:        os.Stderr,
	})
}
