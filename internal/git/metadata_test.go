// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"errors"
	"fmt"
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
	commitTimestamp := runGit(t, dir, "show", "-s", "--format=%cI", "HEAD")

	discovery := Discover(dir)
	assert.Empty(t, discovery.Errors)
	assert.Equal(t, Metadata{Branch: "feature/discover", CommitSHA: commit, CommitTimestamp: commitTimestamp, Origin: "https://github.com/example/project.git"}, discovery.Metadata)

	// A detached HEAD has no branch name.
	runGit(t, dir, "checkout", "--detach")
	discovery = Discover(dir)
	assert.Empty(t, discovery.Errors)
	assert.Empty(t, discovery.Metadata.Branch)
	assert.Equal(t, commit, discovery.Metadata.CommitSHA)
}

func TestDiscover_ReadsCommitterTimestampWithoutSignatureOutput(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "init")

	// A commit with a signature that cannot be verified makes git print verification
	// errors when log.showSignature is enabled.
	tree := runGit(t, dir, "write-tree")
	commitObject := fmt.Sprintf(
		"tree %s\n"+
			"author Test User <test@example.com> 1769855400 +0100\n"+
			"committer Test User <test@example.com> 1769859000 +0100\n"+
			"gpgsig -----BEGIN PGP SIGNATURE-----\n"+
			" \n"+
			" invalid\n"+
			" -----END PGP SIGNATURE-----\n"+
			"\n"+
			"signed commit\n",
		tree,
	)
	commitObjectPath := filepath.Join(t.TempDir(), "commit")
	require.NoError(t, os.WriteFile(commitObjectPath, []byte(commitObject), 0o644))
	commit := runGit(t, dir, "hash-object", "-t", "commit", "-w", commitObjectPath)
	runGit(t, dir, "update-ref", "HEAD", commit)
	runGit(t, dir, "config", "log.showSignature", "true")

	discovery := Discover(dir)
	assert.Empty(t, discovery.Errors)
	assert.Equal(t, commit, discovery.Metadata.CommitSHA)
	assert.Equal(t, "2026-01-31T12:30:00+01:00", discovery.Metadata.CommitTimestamp)
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
