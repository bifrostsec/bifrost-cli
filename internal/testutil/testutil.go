// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

// Package testutil holds helpers shared by the test suites of several packages.
package testutil

import (
	"os"
	"path/filepath"
	"testing"
)

// environmentVariables lists every variable the CLI reads. They are spelled
// out here rather than imported so that any package's tests can use this
// helper without creating import cycles.
var environmentVariables = []string{
	"BIFROST_PROFILE", "BIFROST_CONFIG_FILE", "BIFROST_SHARED_CREDENTIALS_FILE",
	"BIFROST_API_KEY", "BIFROST_SERVER_URL", "SERVER_URL", "BIFROST_ORG_ID",
	"BIFROST_RETRY_ATTEMPTS", "BIFROST_RETRY_DELAY", "BIFROST_HTTP_TIMEOUT",
	"BIFROST_GIT_REPO_PATH", "BIFROST_GIT_AUTO_DETECT",
	"SERVICE", "SERVICE_VERSION", "IMAGE",
	"GITHUB_ACTIONS", "GITHUB_ENV", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
}

// IsolateEnvironment points the home directory at an empty temporary directory
// and clears every environment variable the CLI reads, so tests never see the
// developer's own configuration. Call it from TestMain and invoke the returned
// cleanup before exiting.
func IsolateEnvironment() (cleanup func()) {
	home, err := os.MkdirTemp("", "bifrost-cli-test-home-*")
	if err != nil {
		panic(err)
	}
	for _, name := range []string{"HOME", "USERPROFILE"} {
		_ = os.Setenv(name, home)
	}
	for _, name := range environmentVariables {
		_ = os.Unsetenv(name)
	}
	return func() {
		_ = os.RemoveAll(home)
	}
}

// WriteConfigFiles points the CLI at config and credentials files in a
// temporary directory. Empty contents leave the corresponding file absent.
func WriteConfigFiles(t *testing.T, config, credentials string) (configPath, credentialsPath string) {
	t.Helper()
	dir := t.TempDir()
	configPath = filepath.Join(dir, "config")
	credentialsPath = filepath.Join(dir, "credentials")
	t.Setenv("BIFROST_CONFIG_FILE", configPath)
	t.Setenv("BIFROST_SHARED_CREDENTIALS_FILE", credentialsPath)
	if config != "" {
		if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if credentials != "" {
		if err := os.WriteFile(credentialsPath, []byte(credentials), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return configPath, credentialsPath
}

// WriteSBOM creates a small SBOM file in a temporary directory and returns its path.
func WriteSBOM(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test-sbom.json")
	if err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// ReadFile returns the contents of path, failing the test on error.
func ReadFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
