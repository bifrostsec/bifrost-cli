// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

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
