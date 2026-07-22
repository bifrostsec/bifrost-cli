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
	assert.Contains(t, stderr, missingGitMetadataHint)
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
	assert.NotContains(t, stderr, missingGitMetadataHint)
}

func TestCLI_ValidCommandWithGitAutoDetectEnabledByFlag(t *testing.T) {
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
		"--git-auto-detect",
		"sbom", "upload", path,
	}

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", args)
	})
	assert.Equal(t, 0, exitCode)
	assertGitMetadataDetection(t, stderr, ".", branch, commitSHA, origin)
	assert.NotContains(t, stderr, missingGitMetadataHint)
}

func TestCLI_ValidCommandWithGitAutoDetectFromGitRepoPath(t *testing.T) {
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
		"--git-auto-detect",
		fmt.Sprintf("--git-repo-path=%s", repoDir),
		"sbom", "upload", path,
	}

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", args)
	})
	assert.Equal(t, 0, exitCode)
	assertGitMetadataDetection(t, stderr, repoDir, branch, commitSHA, origin)
	assert.NotContains(t, stderr, missingGitMetadataHint)
}

func TestCLI_ValidCommandInGitRepoWithoutGitAutoDetectOmitsGitMetadata(t *testing.T) {
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

func TestCLI_ExplicitGitAutoDetectFlagOverridesEnvironment(t *testing.T) {
	t.Setenv("BIFROST_GIT_AUTO_DETECT", "true")
	branch := "feature/flag-overrides-env"
	origin := "https://github.com/example/flag-overrides-env-project.git"
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
		"--git-auto-detect=false",
		"sbom", "upload", path,
	}

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", args)
	})
	assert.Equal(t, 0, exitCode)
	assert.Contains(t, stderr, missingGitMetadataHint)
}

func TestCLI_InvalidGitAutoDetectEnvironmentValue(t *testing.T) {
	t.Setenv("BIFROST_GIT_AUTO_DETECT", "notabool")

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

func TestCLI_ValidCommandWithGitAutoDetectEnabledByEnvironment(t *testing.T) {
	t.Setenv("BIFROST_GIT_AUTO_DETECT", "true")
	branch := "feature/env-enabled-auto-git-metadata"
	origin := "https://github.com/example/env-enabled-project.git"
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
		"sbom", "upload", path,
	}

	exitCode := CLI("1.0", "commit", args)
	assert.Equal(t, 0, exitCode)
}

func TestCLI_ValidCommandWithGitAutoDetectOutsideGitRepoPrintsError(t *testing.T) {
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
		"--git-auto-detect",
		"sbom", "upload", path,
	}

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", args)
	})
	assert.Equal(t, 0, exitCode)
	assertGitMetadataDetection(t, stderr, ".", "", "", "")
	assert.Contains(t, stderr, "  error=\"check git work tree:")
	assert.Contains(t, stderr, "git -C \\\".\\\" rev-parse --is-inside-work-tree")
	assert.Contains(t, stderr, missingGitMetadataHint)
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

func captureOutput(t *testing.T, run func() int) (int, string, string) {
	t.Helper()

	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stdout pipe: %v", err)
	}
	defer func() {
		_ = stdoutReader.Close()
	}()

	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create stderr pipe: %v", err)
	}
	defer func() {
		_ = stderrReader.Close()
	}()

	originalStdout, originalStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	defer func() {
		os.Stdout, os.Stderr = originalStdout, originalStderr
		_ = stdoutWriter.Close()
		_ = stderrWriter.Close()
	}()

	exitCode := run()
	os.Stdout, os.Stderr = originalStdout, originalStderr
	if err := stdoutWriter.Close(); err != nil {
		t.Fatalf("failed to close stdout pipe: %v", err)
	}
	if err := stderrWriter.Close(); err != nil {
		t.Fatalf("failed to close stderr pipe: %v", err)
	}

	stdout, err := io.ReadAll(stdoutReader)
	if err != nil {
		t.Fatalf("failed to read stdout pipe: %v", err)
	}
	stderr, err := io.ReadAll(stderrReader)
	if err != nil {
		t.Fatalf("failed to read stderr pipe: %v", err)
	}
	return exitCode, string(stdout), string(stderr)
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

func TestCLI_HelpWritesToStdoutAndExitsSuccessfully(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "long flag", args: []string{"--help"}},
		{name: "long flag equals true", args: []string{"--help=true"}},
		{name: "short flag", args: []string{"-h"}},
		{name: "after command", args: []string{"sbom", "upload", "--help"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCode, stdout, stderr := captureOutput(t, func() int {
				return CLI("1.0", "commit", tt.args)
			})

			assert.Equal(t, 0, exitCode)
			assert.Contains(t, stdout, "bifrost CLI (ver: 1.0, commit: commit")
			assert.Contains(t, stdout, "Usage:")
			assert.Contains(t, stdout, "-h")
			assert.Contains(t, stdout, "--help")
			assert.Empty(t, stderr)
		})
	}
}

func TestCLI_NoArgumentsRemainUsageError(t *testing.T) {
	exitCode, stdout, stderr := captureOutput(t, func() int {
		return CLI("1.0", "commit", nil)
	})

	assert.Equal(t, 2, exitCode)
	assert.Empty(t, stdout)
	assert.Contains(t, stderr, "Usage:")
}

func TestCLI_HelpDoesNotBypassGlobalFlagValidation(t *testing.T) {
	exitCode, stdout, stderr := captureOutput(t, func() int {
		return CLI("1.0", "commit", []string{"--badflag", "--help"})
	})

	assert.Equal(t, 2, exitCode)
	assert.Empty(t, stdout)
	assert.Contains(t, stderr, "flag provided but not defined: -badflag")
}

func TestCLI_HelpLikeStringFlagValueIsNotTreatedAsHelp(t *testing.T) {
	exitCode, stdout, stderr := captureOutput(t, func() int {
		return CLI("1.0", "commit", []string{
			"--service", "-h",
			"--service-version", "1.0",
			"--api-key", "test-token",
			"invalid",
		})
	})

	assert.Equal(t, 2, exitCode)
	assert.Empty(t, stdout)
	assert.Contains(t, stderr, "Error: Unrecognized command")
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
