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
	// `config` may create a new profile, every other command needs an existing one.
	if name != "config" && options.profile != config.DefaultProfile && !resolved.Config.ProfileExists() {
		return printError(fmt.Errorf(
			"profile %q was not found in %s or %s",
			options.profile,
			config.DisplayPath(resolved.Config.ConfigPath),
			config.DisplayPath(resolved.Config.CredentialsPath),
		))
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
	case len(remaining) == 2 && name == "auth" && remaining[1] == "github-actions":
		task, err = command.NewAuthGitHubActions(resolved.Config, options.githubActionsOptions(version))
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
	_, _ = fmt.Fprintf(output, "  bifrost [options] auth github-actions\n")
	_, _ = fmt.Fprintf(output, "  bifrost [options] auth token\n\n")
	_, _ = fmt.Fprintf(output, "Commands:\n")
	_, _ = fmt.Fprintf(output, "  sbom upload           Upload one or more SBOM files for a service version\n")
	_, _ = fmt.Fprintf(output, "  config                Prompt for the API key and server URL and store them in the profile\n")
	_, _ = fmt.Fprintf(output, "  config list           Show every setting with its effective value and where it comes from\n")
	_, _ = fmt.Fprintf(output, "  config get|set|unset  Read or change a setting stored in the profile\n")
	_, _ = fmt.Fprintf(output, "  auth github-actions   Exchange the GitHub Actions OIDC token for an access token and store it in the profile\n")
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
