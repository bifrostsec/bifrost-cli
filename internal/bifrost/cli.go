// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
)

type Task interface {
	Run(ctx context.Context) error
}

func CLI(version, gitCommit string, args []string) int {
	fl := flag.NewFlagSet("", flag.ContinueOnError)
	showHelp := fl.Bool("help", false, "show this help and exit")
	fl.Usage = func() {
		printUsage(fl)
	}
	options := Options{}
	RegisterOptions(fl, &options)
	err := fl.Parse(args)
	if err != nil {
		return 2
	}
	if isFlagSet(fl, gitAutoDetectFlag) || isDeprecatedGitAutoDetectEnvironmentSet(fl, &options) {
		_, _ = fmt.Fprint(os.Stderr, gitAutoDetectDeprecationWarning)
	}
	if *showHelp || len(fl.Args()) == 0 {
		printHeader(version, gitCommit)
		printUsage(fl)
		return 2
	}
	err = ValidateBaseOptions(fl, &options)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		printUsage(fl)
		return 2
	}

	remaining := fl.Args()
	var task Task
	switch {
	case len(remaining) >= 2 && remaining[0] == "sbom" && remaining[1] == "upload":
		task, err = NewSBOMUploadTask(options, remaining[2:], version)
	default:
		_, _ = fmt.Fprintf(os.Stderr, "Error: Unrecognized command\n\n")
		printUsage(fl)
		return 2
	}
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n\n", err)
		printUsage(fl)
		return 2
	}

	err = task.Run(context.Background())
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %s\n", err)
		return 2
	}
	return 0
}

func printHeader(version, gitCommit string) {
	_, _ = fmt.Fprintf(os.Stderr, "bifrost CLI (ver: %s, commit: %s, %s)\n\n", version, gitCommit, runtime.Version())
}

func printUsage(fl *flag.FlagSet) {
	_, _ = fmt.Fprintf(os.Stderr, "Usage:\n")
	_, _ = fmt.Fprintf(os.Stderr, "  bifrost (options) sbom upload <sbom_path|->\n\n")
	_, _ = fmt.Fprintf(os.Stderr, "Options:\n")
	printVisibleDefaults(fl)
}

func printVisibleDefaults(fl *flag.FlagSet) {
	output := fl.Output()
	var defaults bytes.Buffer
	fl.SetOutput(&defaults)
	fl.PrintDefaults()
	fl.SetOutput(output)

	skipDeprecatedFlagDescription := false
	for _, line := range strings.SplitAfter(defaults.String(), "\n") {
		if strings.HasPrefix(line, "  -"+gitAutoDetectFlag) {
			skipDeprecatedFlagDescription = true
			continue
		}
		if skipDeprecatedFlagDescription && strings.HasPrefix(line, "    \t") {
			continue
		}
		skipDeprecatedFlagDescription = false
		_, _ = fmt.Fprint(output, line)
	}
}
