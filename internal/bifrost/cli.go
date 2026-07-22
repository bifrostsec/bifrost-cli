// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
)

type Task interface {
	Run(ctx context.Context) error
}

func CLI(version, gitCommit string, args []string) int {
	fl := NewAliasedFlagSet("", flag.ContinueOnError)
	showHelp := false
	fl.BoolVar(&showHelp, "help", false, "show this help and exit", "h")
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
	if showHelp || hasHelpFlag(remaining) {
		printHelp(os.Stdout, fl, version, gitCommit)
		return 0
	}
	if len(remaining) == 0 {
		printHeader(os.Stderr, version, gitCommit)
		printUsage(os.Stderr, fl)
		return 2
	}
	err = ValidateBaseOptions(fl.FlagSet, &options)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		printUsage(os.Stderr, fl)
		return 2
	}

	var task Task
	switch {
	case len(remaining) >= 2 && remaining[0] == "sbom" && remaining[1] == "upload":
		task, err = NewSBOMUploadTask(options, remaining[2:], version)
	default:
		_, _ = fmt.Fprintf(os.Stderr, "Error: Unrecognized command\n\n")
		printUsage(os.Stderr, fl)
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		printUsage(os.Stderr, fl)
		return 2
	}

	err = task.Run(context.Background())
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 2
	}
	return 0
}

func hasHelpFlag(args []string) bool {
	for _, arg := range args {
		if arg == "--help" || arg == "-h" {
			return true
		}
	}
	return false
}

func printHelp(output io.Writer, fl *AliasedFlagSet, version, gitCommit string) {
	printHeader(output, version, gitCommit)
	printUsage(output, fl)
}

func printHeader(output io.Writer, version, gitCommit string) {
	_, _ = fmt.Fprintf(output, "bifrost CLI (ver: %s, commit: %s, %s)\n\n", version, gitCommit, runtime.Version())
}

func printUsage(output io.Writer, fl *AliasedFlagSet) {
	_, _ = fmt.Fprintf(output, "Usage:\n")
	_, _ = fmt.Fprintf(output, "  bifrost (options) sbom upload <sbom_path|->\n\n")
	_, _ = fmt.Fprintf(output, "Options:\n")
	fl.PrintDefaults(output)
}
