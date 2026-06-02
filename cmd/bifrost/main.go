// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"github.com/bifrostsec/bifrost-cli/internal/bifrost"
)

var (
	Version   string
	GitCommit string
)

func main() {
	os.Exit(bifrost.CLI(Version, GitCommit, os.Args[1:]))
}
