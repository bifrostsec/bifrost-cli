// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

// Package cli is the command-line front end: it parses flags, resolves the
// configuration, dispatches to a command task and formats the outcome.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/bifrostsec/bifrost-cli/internal/command"
	"github.com/bifrostsec/bifrost-cli/internal/config"
	"github.com/bifrostsec/bifrost-cli/internal/flagutil"
)

// CLI runs the command line given by args and returns the process exit code.
func CLI(version, gitCommit string, args []string) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runCLI(ctx, version, gitCommit, args)
}

func runCLI(ctx context.Context, version, gitCommit string, args []string) int {
	fl := flagutil.NewAliasedFlagSet("", flag.ContinueOnError)

	var showHelp bool
	fl.BoolVar(&showHelp, "help", false, "show this help and exit", "h")

	var showVersion bool
	fl.BoolVar(&showVersion, "version", false, "print the CLI version and build commit, then exit", "V")

	fl.Usage = func() {
		printUsage(os.Stderr, fl)
	}
	options := Options{}
	RegisterOptions(fl.FlagSet, &options)
	err := fl.Parse(args)
	if err != nil {
		return 2
	}
	remaining := fl.Args()
	if showHelp {
		printHelp(os.Stdout, fl, version, gitCommit)
		return 0
	}
	if showVersion {
		printVersion(os.Stdout, version, gitCommit)
		return 0
	}
	if len(remaining) == 0 {
		printHeader(os.Stderr, version, gitCommit)
		printUsage(os.Stderr, fl)
		return 2
	}

	resolved, err := ResolveOptions(fl.FlagSet, &options)
	if err != nil {
		return printUsageError(err, fl)
	}
	if resolved.DeprecatedGitAutoDetect {
		_, _ = fmt.Fprint(os.Stderr, gitAutoDetectDeprecationWarning)
	}

	name := remaining[0]
	if name == "config" {
		// Configuration commands must keep working with a bad stored value so it can be repaired.
		printWarnings(resolved.Invalid)
	} else if err := ValidateOptions(&options, resolved); err != nil {
		return printUsageError(err, fl)
	}
	// Commands that write credentials or settings may create a new profile;
	// every other command needs an existing one, which catches a mistyped name.
	createsProfile := name == "config" || (len(remaining) >= 2 && name == "auth" && remaining[1] == "github-actions")
	if !createsProfile && options.profile != config.DefaultProfile && !resolved.Config.ProfileExists() {
		return printError(fmt.Errorf("profile %q was not found %s", options.profile, describeConfigLocations(resolved.Config)))
	}

	var task command.Task
	switch {
	case len(remaining) >= 2 && name == "sbom" && remaining[1] == "upload":
		credentials := options.credentialChain(resolved, version)
		// Fail before touching the SBOM files when no credential source is available.
		if err := credentials.Check(); err != nil {
			return printError(err)
		}
		task, err = command.NewSBOMUpload(options.sbomUploadOptions(version), credentials, remaining[2:])
		if err != nil {
			return printUsageError(err, fl)
		}
	case name == "config":
		task = command.NewConfig(resolved.Config, resolved.Settings, resolved.Profile, remaining[1:])
	case len(remaining) >= 2 && name == "auth" && remaining[1] == "github-actions":
		authOptions, err := parseAuthGitHubActionsArgs(options, version, remaining[2:])
		if err != nil {
			return printUsageError(err, fl)
		}
		task, err = command.NewAuthGitHubActions(resolved.Config, authOptions)
		if err != nil {
			// Not a usage mistake: the environment lacks what the exchange needs.
			return printError(err)
		}
	case len(remaining) == 2 && name == "auth" && remaining[1] == "token":
		task = command.NewAuthToken(options.credentialChain(resolved, version))
	default:
		_, _ = fmt.Fprintf(os.Stderr, "Error: Unrecognized command\n\n")
		printUsage(os.Stderr, fl)
		return 2
	}

	err = task.Run(ctx)
	if errors.Is(err, command.ErrConfigValueNotSet) {
		return 1
	}
	if err != nil {
		return printError(err)
	}
	return 0
}

// describeConfigLocations names the files a profile would be read from.
func describeConfigLocations(cfg *config.Config) string {
	var locations []string
	for _, path := range []string{cfg.ConfigPath, cfg.CredentialsPath} {
		if path != "" {
			locations = append(locations, config.DisplayPath(path))
		}
	}
	if len(locations) == 0 {
		return fmt.Sprintf("because no configuration files are available (set %s or %s)", config.ConfigFileEnvironmentVariable, config.CredentialsFileEnvironmentVariable)
	}
	return "in " + strings.Join(locations, " or ")
}

// printWarnings prints one line per problem; err may be nil or a joined error.
func printWarnings(err error) {
	if err == nil {
		return
	}
	problems := []error{err}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		problems = joined.Unwrap()
	}
	for _, problem := range problems {
		_, _ = fmt.Fprintf(os.Stderr, "Warning: %v\n", problem)
	}
}

// printUsageError reports a mistake in the invocation and shows how to use the CLI.
func printUsageError(err error, fl *flagutil.AliasedFlagSet) int {
	_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
	printUsage(os.Stderr, fl)
	return 2
}

// printError reports a failure that is not a usage mistake, so no usage text follows it.
func printError(err error) int {
	_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)
	return 2
}

func printHelp(output io.Writer, fl *flagutil.AliasedFlagSet, version, gitCommit string) {
	printHeader(output, version, gitCommit)
	printUsage(output, fl)
}

func printHeader(output io.Writer, version, gitCommit string) {
	_, _ = fmt.Fprintf(output, "bifrost CLI (ver: %s, commit: %s, %s)\n\n", version, gitCommit, runtime.Version())
}

func printVersion(output io.Writer, version, gitCommit string) {
	_, _ = fmt.Fprintf(output, "bifrost version %s (commit %s)\n", version, gitCommit)
}

func printUsage(output io.Writer, fl *flagutil.AliasedFlagSet) {
	_, _ = fmt.Fprintf(output, "Usage:\n")
	_, _ = fmt.Fprintf(output, "  bifrost [options] sbom upload <sbom_path|->\n")
	_, _ = fmt.Fprintf(output, "  bifrost [options] config [list | list-profiles | get <name> | set <name> <value> | unset <name>]\n")
	_, _ = fmt.Fprintf(output, "  bifrost [options] auth github-actions [--store github-env|profile]\n")
	_, _ = fmt.Fprintf(output, "  bifrost [options] auth token\n\n")
	_, _ = fmt.Fprintf(output, "Commands:\n")
	_, _ = fmt.Fprintf(output, "  sbom upload           Upload one or more SBOM files for a service version\n")
	_, _ = fmt.Fprintf(output, "  config                Prompt for the API key and server URL and store them in the profile\n")
	_, _ = fmt.Fprintf(output, "  config list           Show every setting with its effective value and where it comes from\n")
	_, _ = fmt.Fprintf(output, "  config get|set|unset  Read or change a setting stored in the profile\n")
	_, _ = fmt.Fprintf(output, "  auth github-actions   Exchange the GitHub Actions OIDC token for an access token and export it to the\n")
	_, _ = fmt.Fprintf(output, "                        later steps of the job as BIFROST_API_KEY (--store github-env, the default when\n")
	_, _ = fmt.Fprintf(output, "                        GITHUB_ENV is set) or cache it in the profile (--store profile)\n")
	_, _ = fmt.Fprintf(output, "  auth token            Print the access token the CLI authenticates with\n\n")
	_, _ = fmt.Fprintf(output, "Options:\n")
	fl.PrintDefaults(output)
	_, _ = fmt.Fprintf(output, "\nConfiguration:\n")
	_, _ = fmt.Fprintf(output, "  Settings are resolved in order of precedence: command-line options, environment variables,\n")
	_, _ = fmt.Fprintf(output, "  the selected profile in ~/%s/%s and ~/%s/%s, then built-in defaults.\n", config.DirName, config.CredentialsFileName, config.DirName, config.ConfigFileName)
	_, _ = fmt.Fprintf(output, "  Set %s or %s to use other file locations.\n", config.ConfigFileEnvironmentVariable, config.CredentialsFileEnvironmentVariable)
	_, _ = fmt.Fprintf(output, "  Credentials are taken from --api-key, BIFROST_API_KEY or the api_key setting, then from an access\n")
	_, _ = fmt.Fprintf(output, "  token stored by `bifrost auth`, and finally by exchanging the GitHub Actions OIDC token when the\n")
	_, _ = fmt.Fprintf(output, "  CLI runs in a GitHub Actions job with an organization id configured.\n")
}
