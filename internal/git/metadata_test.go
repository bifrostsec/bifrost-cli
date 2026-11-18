// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	output, err := exec.Command("git", append([]string{"-C", dir}, args...)...).CombinedOutput()
	if err != nil {
		var execErr *exec.Error
		if errors.As(err, &execErr) {
			t.Skip("git is not available")
		}
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func TestDiscover_ReadsBranchCommitAndOrigin(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "init")
	runGit(t, dir, "config", "user.email", "test@example.com")
	runGit(t, dir, "config", "user.name", "Test User")
	runGit(t, dir, "config", "commit.gpgsign", "false")
	runGit(t, dir, "checkout", "-b", "feature/discover")
	runGit(t, dir, "remote", "add", "origin", "https://github.com/example/project.git")
	require.NoError(t, os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x\n"), 0o644))
	runGit(t, dir, "add", "file.txt")
	runGit(t, dir, "commit", "-m", "initial")
	commit := runGit(t, dir, "rev-parse", "HEAD")

	discovery := Discover(dir)
	assert.Empty(t, discovery.Errors)
	assert.Equal(t, Metadata{Branch: "feature/discover", CommitSHA: commit, Origin: "https://github.com/example/project.git"}, discovery.Metadata)

	// A detached HEAD has no branch name.
	runGit(t, dir, "checkout", "--detach")
	discovery = Discover(dir)
	assert.Empty(t, discovery.Errors)
	assert.Empty(t, discovery.Metadata.Branch)
	assert.Equal(t, commit, discovery.Metadata.CommitSHA)
}

func TestDiscover_OutsideRepositoryReportsError(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "--version") // skip when git is unavailable

	discovery := Discover(dir)
	assert.Equal(t, Metadata{}, discovery.Metadata)
	require.Len(t, discovery.Errors, 1)
	assert.Contains(t, discovery.Errors[0].Error(), "check git work tree:")
	assert.Contains(t, discovery.Errors[0].Error(), "rev-parse --is-inside-work-tree")
}
