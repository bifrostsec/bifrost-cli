// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCLI_ValidCommand(t *testing.T) {
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
		"sbom", "upload", path,
	}

	// Run the CLI with the parsed arguments
	exitCode := CLI("1.0", "commit", args)
	assert.Equal(t, 0, exitCode)
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

	exitCode := CLI("1.0", "commit", args)
	assert.Equal(t, 0, exitCode)
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
