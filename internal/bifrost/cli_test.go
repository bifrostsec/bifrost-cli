// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCLI_ValidCommand(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "bifrost-cli/1.0", r.Header.Get("User-Agent"))
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	// Create a temporary file to simulate a valid SBOM
	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(path)
	}()

	// Command line arguments
	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		"sbom", "upload", path,
	}

	// Run the CLI with the parsed arguments
	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", args)
	})
	assert.Equal(t, 0, exitCode)
	assert.Empty(t, stderr)
}

func TestCLI_HelpOmitsDeprecatedGitAutoDetectFlag(t *testing.T) {
	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{"--help"})
	})

	assert.Equal(t, 2, exitCode)
	assert.NotContains(t, stderr, gitAutoDetectFlag)
}

func TestCLI_ValidCommandWithGitMetadata(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "1.0", r.URL.Query().Get("version"))
		assert.Equal(t, "main", r.URL.Query().Get("git_branch"))
		assert.Equal(t, "abc123", r.URL.Query().Get("git_commit_sha"))
		assert.Equal(t, "https://github.com/example/project.git", r.URL.Query().Get("git_origin"))
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(path)
	}()

	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		"--git-branch=main",
		"--git-commit-sha=abc123",
		"--git-origin=https://github.com/example/project.git",
		"sbom", "upload", path,
	}

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", args)
	})
	assert.Equal(t, 0, exitCode)
	assert.Empty(t, stderr)
}

func TestCLI_ValidCommandWithGitRepoPathCurrentDirectory(t *testing.T) {
	branch := "feature/auto-git-metadata"
	origin := "https://github.com/example/auto-project.git"
	repoDir, commitSHA := createTestGitRepo(t, branch, origin)
	chdir(t, repoDir)

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, branch, r.URL.Query().Get("git_branch"))
		assert.Equal(t, commitSHA, r.URL.Query().Get("git_commit_sha"))
		assert.Equal(t, origin, r.URL.Query().Get("git_origin"))
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)

	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		"--git-repo-path=.",
		"sbom", "upload", path,
	}

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", args)
	})
	assert.Equal(t, 0, exitCode)
	assertGitMetadataDetection(t, stderr, ".", branch, commitSHA, origin)
}

func TestCLI_DeprecatedGitAutoDetectUsesCurrentDirectory(t *testing.T) {
	branch := "feature/deprecated-auto-git-metadata"
	origin := "https://github.com/example/deprecated-auto-project.git"
	repoDir, commitSHA := createTestGitRepo(t, branch, origin)
	chdir(t, repoDir)

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, branch, r.URL.Query().Get("git_branch"))
		assert.Equal(t, commitSHA, r.URL.Query().Get("git_commit_sha"))
		assert.Equal(t, origin, r.URL.Query().Get("git_origin"))
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)

	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		"--git-auto-detect",
		"sbom", "upload", path,
	}

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", args)
	})
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stderr, gitAutoDetectDeprecationWarning)
	assertGitMetadataDetection(t, stderr, ".", branch, commitSHA, origin)
}

func TestCLI_DeprecatedGitAutoDetectEnvironmentUsesCurrentDirectory(t *testing.T) {
	branch := "feature/deprecated-auto-git-metadata-environment"
	origin := "https://github.com/example/deprecated-auto-environment-project.git"
	repoDir, commitSHA := createTestGitRepo(t, branch, origin)
	chdir(t, repoDir)
	t.Setenv(gitAutoDetectEnvironmentVariable, "true")

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, branch, r.URL.Query().Get("git_branch"))
		assert.Equal(t, commitSHA, r.URL.Query().Get("git_commit_sha"))
		assert.Equal(t, origin, r.URL.Query().Get("git_origin"))
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)

	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		"sbom", "upload", path,
	}

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", args)
	})
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stderr, gitAutoDetectDeprecationWarning)
	assertGitMetadataDetection(t, stderr, ".", branch, commitSHA, origin)
}

func TestCLI_InvalidDeprecatedGitAutoDetectEnvironmentValue(t *testing.T) {
	t.Setenv(gitAutoDetectEnvironmentVariable, "not-a-boolean")

	args := []string{
		"--server-url=https://portal.bifrostsec.com",
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		"sbom", "upload", "test-sbom.json",
	}

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", args)
	})
	assert.Equal(t, 2, exitCode)
	assert.Contains(t, stderr, "BIFROST_GIT_AUTO_DETECT must be a boolean")
}

func TestCLI_ValidCommandWithAbsoluteGitRepoPath(t *testing.T) {
	branch := "feature/auto-git-metadata-path"
	origin := "https://github.com/example/auto-project-path.git"
	repoDir, commitSHA := createTestGitRepo(t, branch, origin)
	chdir(t, t.TempDir())

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, branch, r.URL.Query().Get("git_branch"))
		assert.Equal(t, commitSHA, r.URL.Query().Get("git_commit_sha"))
		assert.Equal(t, origin, r.URL.Query().Get("git_origin"))
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)

	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		fmt.Sprintf("--git-repo-path=%s", repoDir),
		"sbom", "upload", path,
	}

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", args)
	})
	assert.Equal(t, 0, exitCode)
	assertGitMetadataDetection(t, stderr, repoDir, branch, commitSHA, origin)
}

func TestCLI_ValidCommandInGitRepoWithoutGitRepoPathOmitsGitMetadata(t *testing.T) {
	branch := "feature/default-no-auto-git-metadata"
	origin := "https://github.com/example/default-no-auto-project.git"
	repoDir, _ := createTestGitRepo(t, branch, origin)
	chdir(t, repoDir)

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertNoGitMetadataQuery(t, r)
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)

	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		"sbom", "upload", path,
	}

	exitCode := CLI("1.0", "commit", args)
	assert.Equal(t, 0, exitCode)
}

func TestCLI_ExplicitGitRepoPathOverridesEnvironment(t *testing.T) {
	envRepoDir, _ := createTestGitRepo(t, "env-branch", "https://github.com/example/env-project.git")
	branch := "flag-branch"
	origin := "https://github.com/example/flag-project.git"
	flagRepoDir, commitSHA := createTestGitRepo(t, branch, origin)
	t.Setenv("BIFROST_GIT_REPO_PATH", envRepoDir)
	t.Setenv(gitAutoDetectEnvironmentVariable, "not-a-boolean")

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, branch, r.URL.Query().Get("git_branch"))
		assert.Equal(t, commitSHA, r.URL.Query().Get("git_commit_sha"))
		assert.Equal(t, origin, r.URL.Query().Get("git_origin"))
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)

	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		fmt.Sprintf("--git-repo-path=%s", flagRepoDir),
		"sbom", "upload", path,
	}

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", args)
	})
	assert.Equal(t, 0, exitCode)
	assertGitMetadataDetection(t, stderr, flagRepoDir, branch, commitSHA, origin)
}

func TestCLI_ValidCommandWithGitRepoPathFromEnvironment(t *testing.T) {
	branch := "feature/env-enabled-auto-git-metadata"
	origin := "https://github.com/example/env-enabled-project.git"
	repoDir, commitSHA := createTestGitRepo(t, branch, origin)
	t.Setenv("BIFROST_GIT_REPO_PATH", repoDir)

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, branch, r.URL.Query().Get("git_branch"))
		assert.Equal(t, commitSHA, r.URL.Query().Get("git_commit_sha"))
		assert.Equal(t, origin, r.URL.Query().Get("git_origin"))
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)

	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		"sbom", "upload", path,
	}

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", args)
	})
	assert.Equal(t, 0, exitCode)
	assertGitMetadataDetection(t, stderr, repoDir, branch, commitSHA, origin)
}

func TestCLI_ValidCommandWithRelativeGitRepoPath(t *testing.T) {
	branch := "feature/relative-git-metadata"
	origin := "https://github.com/example/relative-project.git"
	repoDir, commitSHA := createTestGitRepo(t, branch, origin)
	parentDir := filepath.Dir(repoDir)
	relativeRepoPath := filepath.Base(repoDir)
	chdir(t, parentDir)

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, branch, r.URL.Query().Get("git_branch"))
		assert.Equal(t, commitSHA, r.URL.Query().Get("git_commit_sha"))
		assert.Equal(t, origin, r.URL.Query().Get("git_origin"))
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := filepath.Join(t.TempDir(), "test-sbom.json")
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)

	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		fmt.Sprintf("--git-repo-path=%s", relativeRepoPath),
		"sbom", "upload", path,
	}

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", args)
	})
	assert.Equal(t, 0, exitCode)
	assertGitMetadataDetection(t, stderr, relativeRepoPath, branch, commitSHA, origin)
}

func TestCLI_ValidCommandWithGitRepoPathOutsideGitRepoPrintsError(t *testing.T) {
	tempDir := t.TempDir()
	chdir(t, tempDir)

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertNoGitMetadataQuery(t, r)
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)

	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		"--git-repo-path=.",
		"sbom", "upload", path,
	}

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", args)
	})
	assert.Equal(t, 0, exitCode)
	assertGitMetadataDetection(t, stderr, ".", "", "", "")
	assert.Contains(t, stderr, "  error=\"check git work tree:")
	assert.Contains(t, stderr, "git -C \\\".\\\" rev-parse --is-inside-work-tree")
}

func TestCLI_ValidCommandWithImage(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.URL.Query().Get("version"))
		assert.Equal(t, "registry.example.com/team/app:1.0", r.URL.Query().Get("image"))
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(path)
	}()

	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--image=registry.example.com/team/app:1.0",
		"--api-key=test-token",
		"sbom", "upload", path,
	}

	exitCode := CLI("1.0", "commit", args)
	assert.Equal(t, 0, exitCode)
}

func TestCLI_ValidCommandWithServiceVersionFromEnvironment(t *testing.T) {
	t.Setenv("SERVICE_VERSION", "1.0-env")

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "1.0-env", r.URL.Query().Get("version"))
		assert.Empty(t, r.URL.Query().Get("image"))
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(path)
	}()

	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--api-key=test-token",
		"sbom", "upload", path,
	}

	exitCode := CLI("1.0", "commit", args)
	assert.Equal(t, 0, exitCode)
}

func TestCLI_ValidCommandWithImageFromEnvironment(t *testing.T) {
	t.Setenv("IMAGE", "registry.example.com/team/app:env")

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Empty(t, r.URL.Query().Get("version"))
		assert.Equal(t, "registry.example.com/team/app:env", r.URL.Query().Get("image"))
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(path)
	}()

	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--api-key=test-token",
		"sbom", "upload", path,
	}

	exitCode := CLI("1.0", "commit", args)
	assert.Equal(t, 0, exitCode)
}

func TestCLI_MissingServiceVersionAndImage(t *testing.T) {
	args := []string{
		"--server-url=https://portal.bifrostsec.com",
		"--service=test-service",
		"--api-key=test-token",
		"sbom", "upload", "test-sbom.json",
	}

	exitCode := CLI("1.0", "commit", args)
	assert.Equal(t, 2, exitCode)
}

func TestCLI_ValidCommandFromStdin(t *testing.T) {
	var body string
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestBody, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		body = string(requestBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	stdinFile, err := os.CreateTemp("", "stdin-sbom-*.json")
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(stdinFile.Name())
	}()

	_, err = stdinFile.WriteString(`{"name":"stdin","version":"1.0"}`)
	assert.NoError(t, err)
	_, err = stdinFile.Seek(0, 0)
	assert.NoError(t, err)
	defer func() {
		_ = stdinFile.Close()
	}()

	originalStdin := os.Stdin
	os.Stdin = stdinFile
	defer func() {
		os.Stdin = originalStdin
	}()

	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		"sbom", "upload", "-",
	}

	exitCode := CLI("1.0", "commit", args)
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, `{"name":"stdin","version":"1.0"}`, body)
}

func TestCLI_StdinPathRequiresPipedInput(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	tty, err := os.Open("/dev/tty")
	if err != nil {
		t.Skipf("tty not available: %v", err)
	}
	defer func() {
		_ = tty.Close()
	}()

	originalStdin := os.Stdin
	os.Stdin = tty
	defer func() {
		os.Stdin = originalStdin
	}()

	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		"sbom", "upload", "-",
	}

	exitCode := CLI("1.0", "commit", args)
	assert.Equal(t, 2, exitCode)
}

func createTestGitRepo(t *testing.T, branch string, origin string) (string, string) {
	t.Helper()

	repoDir := t.TempDir()
	runTestGit(t, repoDir, "init")
	runTestGit(t, repoDir, "config", "user.email", "test@example.com")
	runTestGit(t, repoDir, "config", "user.name", "Test User")
	runTestGit(t, repoDir, "config", "commit.gpgsign", "false")
	runTestGit(t, repoDir, "checkout", "-b", branch)
	runTestGit(t, repoDir, "remote", "add", "origin", origin)

	err := os.WriteFile(filepath.Join(repoDir, "tracked.txt"), []byte("tracked\n"), 0644)
	assert.NoError(t, err)
	runTestGit(t, repoDir, "add", "tracked.txt")
	runTestGit(t, repoDir, "commit", "-m", "initial commit")

	commitSHA := runTestGit(t, repoDir, "rev-parse", "HEAD")
	return repoDir, commitSHA
}

func runTestGit(t *testing.T, dir string, args ...string) string {
	t.Helper()

	gitArgs := append([]string{"-C", dir}, args...)
	cmd := exec.Command("git", gitArgs...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		var execErr *exec.Error
		if errors.As(err, &execErr) {
			t.Skip("git is not available")
		}
		t.Fatalf("git %s failed: %v\n%s", strings.Join(args, " "), err, string(output))
	}
	return strings.TrimSpace(string(output))
}

func chdir(t *testing.T, dir string) {
	t.Helper()

	previousDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to read current directory: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("failed to change directory to %s: %v", dir, err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previousDir); err != nil {
			t.Fatalf("failed to restore directory to %s: %v", previousDir, err)
		}
	})
}

func assertNoGitMetadataQuery(t *testing.T, r *http.Request) {
	t.Helper()

	query := r.URL.Query()
	_, hasGitBranch := query["git_branch"]
	_, hasGitCommitSHA := query["git_commit_sha"]
	_, hasGitOrigin := query["git_origin"]
	assert.False(t, hasGitBranch)
	assert.False(t, hasGitCommitSHA)
	assert.False(t, hasGitOrigin)
}

func assertGitMetadataDetection(t *testing.T, stderr string, repoPath string, branch string, commitSHA string, origin string) {
	t.Helper()

	assert.Contains(t, stderr, fmt.Sprintf("Git metadata detection from %s:\n", repoPath))
	assert.Contains(t, stderr, fmt.Sprintf("  git_branch=%q\n", branch))
	assert.Contains(t, stderr, fmt.Sprintf("  git_commit_sha=%q\n", commitSHA))
	assert.Contains(t, stderr, fmt.Sprintf("  git_origin=%q\n", origin))
}

func captureStderr(t *testing.T, run func() int) (int, string) {
	t.Helper()

	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stderr pipe: %v", err)
	}
	defer func() {
		_ = readPipe.Close()
	}()

	originalStderr := os.Stderr
	os.Stderr = writePipe
	writePipeClosed := false
	defer func() {
		os.Stderr = originalStderr
		if !writePipeClosed {
			_ = writePipe.Close()
		}
	}()

	exitCode := run()
	os.Stderr = originalStderr

	err = writePipe.Close()
	writePipeClosed = true
	if err != nil {
		t.Fatalf("failed to close stderr pipe: %v", err)
	}

	output, err := io.ReadAll(readPipe)
	if err != nil {
		t.Fatalf("failed to read stderr pipe: %v", err)
	}
	return exitCode, string(output)
}

func TestCaptureStderrRestoresStderrAfterPanic(t *testing.T) {
	originalStderr := os.Stderr
	defer func() {
		os.Stderr = originalStderr
	}()

	panicked := false
	func() {
		defer func() {
			panicked = recover() != nil
		}()

		_, _ = captureStderr(t, func() int {
			panic("test panic")
		})
	}()

	assert.True(t, panicked)
	assert.Same(t, originalStderr, os.Stderr)
}

func TestCLI_InvalidCommand(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	// Create a temporary file to simulate a valid SBOM
	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(path)
	}()

	// Command line arguments
	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		"invalid", "command", path,
	}

	// Run the CLI with the parsed arguments
	exitCode := CLI("1.0", "commit", args)
	assert.Equal(t, 2, exitCode)
}

func TestCLI_InvalidSBOMPath(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	// Command line arguments
	args := []string{
		fmt.Sprintf("--server-url=%s", httpServer.URL),
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		"sbom", "upload", "nonexistent-file.json",
	}

	// Run the CLI with the parsed arguments
	exitCode := CLI("1.0", "commit", args)
	assert.Equal(t, 2, exitCode)
}

func TestCLI_InvalidRetryAttempts(t *testing.T) {
	args := []string{
		"--server-url=https://portal.bifrostsec.com",
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		"--retry-attempts=-1",
		"sbom", "upload", "test-sbom.json",
	}

	exitCode := CLI("1.0", "commit", args)
	assert.Equal(t, 2, exitCode)
}

func TestCLI_InvalidRetryDelay(t *testing.T) {
	args := []string{
		"--server-url=https://portal.bifrostsec.com",
		"--service=test-service",
		"--service-version=1.0",
		"--api-key=test-token",
		fmt.Sprintf("--retry-delay=%s", -1*time.Second),
		"sbom", "upload", "test-sbom.json",
	}

	exitCode := CLI("1.0", "commit", args)
	assert.Equal(t, 2, exitCode)
}
