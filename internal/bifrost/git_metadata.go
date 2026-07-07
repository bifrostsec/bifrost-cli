// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"os/exec"
	"strings"
)

type gitMetadata struct {
	branch    string
	commitSHA string
	origin    string
}

func discoverGitMetadata(dir string) gitMetadata {
	insideWorkTree, ok := runGit(dir, "rev-parse", "--is-inside-work-tree")
	if !ok || insideWorkTree != "true" {
		return gitMetadata{}
	}

	branch, _ := runGit(dir, "rev-parse", "--abbrev-ref", "HEAD")
	if branch == "HEAD" {
		branch = ""
	}
	commitSHA, _ := runGit(dir, "rev-parse", "HEAD")
	origin, _ := runGit(dir, "config", "--get", "remote.origin.url")

	metadata := gitMetadata{
		branch:    branch,
		commitSHA: commitSHA,
		origin:    origin,
	}
	return metadata
}

func runGit(dir string, args ...string) (string, bool) {
	gitArgs := append([]string{"-C", dir}, args...)
	output, err := exec.Command("git", gitArgs...).Output()
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(output)), true
}

func gitMetadataRepoPath(path string) string {
	if path == "" {
		return "."
	}
	return path
}
