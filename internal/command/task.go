// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

// Package command implements the tasks behind each CLI command. Tasks receive
// fully resolved options and report outcomes through their return value, so
// the cli package stays responsible for parsing input and formatting output.
package command

import "context"

// Task is a command ready to run.
type Task interface {
	Run(ctx context.Context) error
}
