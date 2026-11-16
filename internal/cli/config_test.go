// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bifrostsec/bifrost-cli/internal/testutil"
)

func TestCLI_ConfigSetWritesSettingsToTheRightFile(t *testing.T) {
	configPath, credentialsPath := testutil.WriteConfigFiles(t, "", "")

	assert.Equal(t, 0, CLI("1.0", "commit", []string{"config", "set", "api_key", "secret-1234"}))
	assert.Equal(t, 0, CLI("1.0", "commit", []string{"config", "set", "server-url", "https://example.com"}))
	assert.Equal(t, 0, CLI("1.0", "commit", []string{"--profile=staging", "config", "set", "org_id", "org_staging"}))
	assert.Equal(t, 0, CLI("1.0", "commit", []string{"--profile=staging", "config", "set", "api_key", "staging-secret"}))

	assert.Equal(t, "[default]\nserver_url = https://example.com\n\n[profile staging]\norg_id = org_staging\n", testutil.ReadFile(t, configPath))
	assert.Equal(t, "[default]\napi_key = secret-1234\n\n[staging]\napi_key = staging-secret\n", testutil.ReadFile(t, credentialsPath))

	for _, path := range []string{configPath, credentialsPath} {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), path)
	}
}

func TestCLI_ConfigGetReadsOnlyStoredValues(t *testing.T) {
	testutil.WriteConfigFiles(t, "[default]\nserver_url = https://file.example.com\n", "[default]\napi_key = file-key\n")
	t.Setenv("BIFROST_SERVER_URL", "https://env.example.com")

	exitCode, stdout, stderr := captureOutput(t, func() int {
		return CLI("1.0", "commit", []string{"config", "get", "server_url"})
	})
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, "https://file.example.com\n", stdout)
	assert.Empty(t, stderr)

	exitCode, stdout, _ = captureOutput(t, func() int {
		return CLI("1.0", "commit", []string{"config", "get", "api_key"})
	})
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, "file-key\n", stdout)

	exitCode, stdout, stderr = captureOutput(t, func() int {
		return CLI("1.0", "commit", []string{"config", "get", "org_id"})
	})
	assert.Equal(t, 1, exitCode, "an unset value exits with status 1 and no output")
	assert.Empty(t, stdout)
	assert.Empty(t, stderr)
}

func TestCLI_ConfigUnsetRemovesValue(t *testing.T) {
	_, credentialsPath := testutil.WriteConfigFiles(t, "", "[default]\napi_key = file-key\naccess_token = cached\n")

	assert.Equal(t, 0, CLI("1.0", "commit", []string{"config", "unset", "access_token"}))
	assert.Equal(t, "[default]\napi_key = file-key\n", testutil.ReadFile(t, credentialsPath))

	assert.Equal(t, 0, CLI("1.0", "commit", []string{"config", "unset", "access_token"}), "unsetting an absent value succeeds")
}

func TestCLI_ConfigRejectsUnknownNames(t *testing.T) {
	testutil.WriteConfigFiles(t, "", "")

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{"config", "set", "service", "x"})
	})
	assert.Equal(t, 2, exitCode)
	assert.Contains(t, stderr, `unknown configuration name "service"`)
	assert.Contains(t, stderr, "server_url")

	exitCode, stderr = captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{"config", "frobnicate"})
	})
	assert.Equal(t, 2, exitCode)
	assert.Contains(t, stderr, `unknown config subcommand "frobnicate"`)
}

func TestCLI_ConfigListShowsValuesAndSources(t *testing.T) {
	configPath, credentialsPath := testutil.WriteConfigFiles(t, "[default]\nserver_url = https://file.example.com\n", "[default]\napi_key = secret-token-wxyz\n")
	t.Setenv("BIFROST_RETRY_DELAY", "4s")

	exitCode, stdout, stderr := captureOutput(t, func() int {
		return CLI("1.0", "commit", []string{"--http-timeout=5s", "config", "list"})
	})
	assert.Equal(t, 0, exitCode)
	assert.Empty(t, stderr)

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	require.GreaterOrEqual(t, len(lines), 3)
	assert.Equal(t, []string{"Name", "Value", "Type", "Location"}, strings.Fields(lines[0]))
	rows := map[string][]string{}
	for _, line := range lines[2:] {
		fields := strings.Fields(line)
		rows[fields[0]] = fields[1:]
	}
	assert.Equal(t, []string{"default", "default"}, rows["profile"])
	assert.Equal(t, []string{"https://file.example.com", "config-file", configPath}, rows["server_url"])
	assert.Equal(t, []string{"****************wxyz", "credentials-file", credentialsPath}, rows["api_key"])
	assert.Equal(t, []string{"4s", "env", "BIFROST_RETRY_DELAY"}, rows["retry_delay"])
	assert.Equal(t, []string{"5s", "command-line", "--http-timeout"}, rows["http_timeout"])
	assert.Equal(t, []string{"3", "default"}, rows["retry_attempts"])
	assert.Equal(t, []string{"<not", "set>", "not", "set"}, rows["org_id"])
	assert.NotContains(t, stdout, "secret-token-wxyz", "secrets are masked")
}

func TestCLI_ConfigListProfiles(t *testing.T) {
	testutil.WriteConfigFiles(t, "[default]\n\n[profile staging]\n", "[default]\n\n[ci]\n")

	exitCode, stdout, _ := captureOutput(t, func() int {
		return CLI("1.0", "commit", []string{"config", "list-profiles"})
	})
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, "default\nstaging\nci\n", stdout)
}

func TestCLI_ConfigInteractivePromptsAndStores(t *testing.T) {
	configPath, credentialsPath := testutil.WriteConfigFiles(t, "", "[default]\napi_key = existing-key-abcd\n")

	stdin, err := os.CreateTemp(t.TempDir(), "stdin")
	require.NoError(t, err)
	// Enter keeps the existing API key, the server URL is set.
	_, err = stdin.WriteString("\nhttps://staging.example.com\n")
	require.NoError(t, err)
	_, err = stdin.Seek(0, 0)
	require.NoError(t, err)
	originalStdin := os.Stdin
	os.Stdin = stdin
	defer func() {
		os.Stdin = originalStdin
		_ = stdin.Close()
	}()

	exitCode, stdout, stderr := captureOutput(t, func() int {
		return CLI("1.0", "commit", []string{"config"})
	})
	assert.Equal(t, 0, exitCode)
	assert.Empty(t, stderr)
	assert.Equal(t, "Bifrost API key [****************abcd]: Server URL [None]: ", stdout)
	assert.Equal(t, "[default]\napi_key = existing-key-abcd\n", testutil.ReadFile(t, credentialsPath))
	assert.Equal(t, "[default]\nserver_url = https://staging.example.com\n", testutil.ReadFile(t, configPath))
}
