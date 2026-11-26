// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

// Package git discovers metadata about a local Git repository.
package git

import (
	"fmt"
	"os/exec"
	"strings"
)

// Metadata describes the checked out state of a repository.
type Metadata struct {
	Branch          string
	CommitSHA       string
	CommitTimestamp string
	Origin          string
}

// Discovery is the outcome of reading a repository; Errors lists what could not be read.
type Discovery struct {
	Metadata Metadata
	Errors   []error
}

// Discover reads branch, commit SHA, commit timestamp and origin from the repository at dir.
func Discover(dir string) Discovery {
	// Verify that we are inside a Git repository.
	insideWorkingTree, err := run(dir, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		return Discovery{
			Errors: []error{fmt.Errorf("check git work tree: %w", err)},
		}
	}
	if insideWorkingTree != "true" {
		return Discovery{
			Errors: []error{fmt.Errorf("check git work tree: not inside a Git work tree")},
		}
	}

	var errors []error
	read := func(label string, args ...string) string {
		value, err := run(dir, args...)
		if err != nil {
			errors = append(errors, fmt.Errorf("%s: %w", label, err))
		}
		return value
	}

	// Read branch and commit metadata.
	branch := read("read git branch", "rev-parse", "--abbrev-ref", "HEAD")
	if branch == "HEAD" {
		branch = ""
	}
	commitSHA := read("read git commit SHA", "rev-parse", "HEAD")
	// Committer date in strict ISO 8601. Signature output is disabled since it would be mixed into the value.
	commitTimestamp := read("read git commit timestamp", "show", "-s", "--no-show-signature", "--format=%cI", "HEAD")

	// Get remote origin
	origin, _ := run(dir, "config", "--get", "remote.origin.url")

	return Discovery{
		Metadata: Metadata{
			Branch:          branch,
			CommitSHA:       commitSHA,
			CommitTimestamp: commitTimestamp,
			Origin:          origin,
		},
		Errors: errors,
	}
}

func run(dir string, args ...string) (string, error) {
	gitArgs := append([]string{"-C", dir}, args...)
	output, err := exec.Command("git", gitArgs...).CombinedOutput()
	message := strings.TrimSpace(string(output))
	if err != nil {
		command := fmt.Sprintf("git -C %q %s", dir, strings.Join(args, " "))
		if message == "" {
			return "", fmt.Errorf("%s: %w", command, err)
		}
		return "", fmt.Errorf("%s: %w: %s", command, err, message)
	}
	return message, nil
}
