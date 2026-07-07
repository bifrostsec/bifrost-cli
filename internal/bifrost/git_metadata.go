// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"fmt"
	"os/exec"
	"strings"
)

type gitMetadata struct {
	branch    string
	commitSHA string
	origin    string
}

type gitMetadataDiscovery struct {
	metadata gitMetadata
	errors   []error
}

func discoverGitMetadata(dir string) gitMetadataDiscovery {
	// Verify that we are inside a Git repository.
	insideWorkingTree, err := runGitCommand(dir, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		return gitMetadataDiscovery{
			errors: []error{fmt.Errorf("check git work tree: %w", err)},
		}
	}
	if insideWorkingTree != "true" {
		return gitMetadataDiscovery{
			errors: []error{fmt.Errorf("check git work tree: not inside a Git work tree")},
		}
	}

	var errors []error
	read := func(label string, args ...string) string {
		value, err := runGitCommand(dir, args...)
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

	// Get remote origin
	origin, _ := runGitCommand(dir, "config", "--get", "remote.origin.url")

	return gitMetadataDiscovery{
		metadata: gitMetadata{
			branch:    branch,
			commitSHA: commitSHA,
			origin:    origin,
		},
		errors: errors,
	}
}

func runGitCommand(dir string, args ...string) (string, error) {
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
