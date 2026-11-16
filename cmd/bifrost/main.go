// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/bifrostsec/bifrost-cli/internal/cli"
)

var (
	Version   string
	GitCommit string
)

func main() {
	os.Exit(cli.CLI(Version, GitCommit, os.Args[1:]))
}
