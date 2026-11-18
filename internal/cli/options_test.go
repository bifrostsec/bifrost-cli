// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bifrostsec/bifrost-cli/internal/config"
	"github.com/bifrostsec/bifrost-cli/internal/testutil"
)

// resolveTestOptions resolves and validates like every command except `config` does.
func resolveTestOptions(t *testing.T, args ...string) (Options, *ResolvedOptions, error) {
	t.Helper()
	fl := flag.NewFlagSet("", flag.ContinueOnError)
	options := Options{}
	RegisterOptions(fl, &options)
	require.NoError(t, fl.Parse(args))
	resolved, err := ResolveOptions(fl, &options)
	if err != nil {
		return options, nil, err
	}
	return options, resolved, ValidateOptions(&options, resolved)
}

func TestRegisterOptions_RegistersAFlagForEverySetting(t *testing.T) {
	fl := flag.NewFlagSet("", flag.ContinueOnError)
	RegisterOptions(fl, &Options{})
	for _, s := range config.Settings {
		if s.Flag == "" {
			continue
		}
		assert.NotNil(t, fl.Lookup(s.Flag), "setting %s refers to flag --%s", s.Name, s.Flag)
	}
}

func TestResolveOptions_FlagsOverrideEnvironmentOverridesFilesOverridesDefaults(t *testing.T) {
	configPath, credentialsPath := testutil.WriteConfigFiles(t, `[default]
server_url = https://file.example.com
retry_attempts = 7
retry_delay = 9s
http_timeout = 11s
git_repo_path = /from/file
org_id = org_file
api_key = key-from-config
`, `[default]
api_key = key-from-credentials
`)
	t.Setenv("BIFROST_SERVER_URL", "https://env.example.com")
	t.Setenv("BIFROST_RETRY_DELAY", "4s")

	options, resolved, err := resolveTestOptions(t, "--retry-attempts=2")
	require.NoError(t, err)

	assert.Equal(t, 2, options.retryAttempts, "flag wins")
	assert.Equal(t, 4*time.Second, options.retryDelay, "environment wins over file")
	assert.Equal(t, "https://env.example.com", options.ServerURL)
	assert.Equal(t, 11*time.Second, options.httpTimeout, "file wins over default")
	assert.Equal(t, "/from/file", options.gitRepoPath)
	assert.Equal(t, "org_file", options.orgID)
	assert.Equal(t, "key-from-credentials", options.apiKey, "credentials file wins over config file")
	assert.Equal(t, config.DefaultProfile, options.profile)

	expected := map[string]config.Resolved{
		"retry_attempts": {Value: "2", Source: config.SourceCommandLine, Location: "--retry-attempts"},
		"retry_delay":    {Value: "4s", Source: config.SourceEnvironment, Location: "BIFROST_RETRY_DELAY"},
		"server_url":     {Value: "https://env.example.com", Source: config.SourceEnvironment, Location: "BIFROST_SERVER_URL"},
		"http_timeout":   {Value: "11s", Source: config.SourceConfigFile, Location: configPath},
		"api_key":        {Value: "key-from-credentials", Source: config.SourceCredentialsFile, Location: credentialsPath},
		"access_token":   {Source: config.SourceNotSet},
	}
	for name, want := range expected {
		got := config.Find(resolved.Settings, name)
		assert.Equal(t, want.Value, got.Value, name)
		assert.Equal(t, want.Source, got.Source, name)
		assert.Equal(t, want.Location, got.Location, name)
	}
	assert.Equal(t, config.SourceDefault, resolved.Profile.Source)
}

func TestResolveOptions_DefaultsApplyWithoutFiles(t *testing.T) {
	testutil.WriteConfigFiles(t, "", "")

	options, resolved, err := resolveTestOptions(t)
	require.NoError(t, err)
	assert.Equal(t, "https://portal.bifrostsec.com", options.ServerURL)
	assert.Equal(t, 3, options.retryAttempts)
	assert.Equal(t, 30*time.Second, options.httpTimeout)
	assert.Empty(t, options.apiKey)

	serverURL := config.Find(resolved.Settings, "server_url")
	assert.Equal(t, config.SourceDefault, serverURL.Source)
	assert.Equal(t, "https://portal.bifrostsec.com", serverURL.Value)
	assert.Equal(t, config.SourceNotSet, config.Find(resolved.Settings, "api_key").Source)
}

func TestResolveOptions_PerUploadValuesFallBackToEnvironment(t *testing.T) {
	testutil.WriteConfigFiles(t, "", "")
	t.Setenv("SERVICE", "env-service")
	t.Setenv("SERVICE_VERSION", "env-version")
	t.Setenv("IMAGE", "env-image")

	options, _, err := resolveTestOptions(t, "--service=flag-service")
	require.NoError(t, err)
	assert.Equal(t, "flag-service", options.service)
	assert.Equal(t, "env-version", options.serviceVersion)
	assert.Equal(t, "env-image", options.image)
}

func TestResolveOptions_LegacyServerURLEnvironmentVariableIsFallback(t *testing.T) {
	testutil.WriteConfigFiles(t, "[default]\nserver_url = https://file.example.com\n", "")
	t.Setenv("SERVER_URL", "https://legacy.example.com")

	options, _, err := resolveTestOptions(t)
	require.NoError(t, err)
	assert.Equal(t, "https://legacy.example.com", options.ServerURL)

	t.Setenv("BIFROST_SERVER_URL", "https://preferred.example.com")
	options, _, err = resolveTestOptions(t)
	require.NoError(t, err)
	assert.Equal(t, "https://preferred.example.com", options.ServerURL)
}

func TestResolveOptions_ProfileSelection(t *testing.T) {
	testutil.WriteConfigFiles(t, `[default]
server_url = https://default.example.com

[profile staging]
server_url = https://staging.example.com
`, `[default]
api_key = default-key

[staging]
api_key = staging-key
`)

	t.Run("flag", func(t *testing.T) {
		options, resolved, err := resolveTestOptions(t, "--profile=staging")
		require.NoError(t, err)
		assert.Equal(t, "staging", options.profile)
		assert.Equal(t, "https://staging.example.com", options.ServerURL)
		assert.Equal(t, "staging-key", options.apiKey)
		assert.Equal(t, config.SourceCommandLine, resolved.Profile.Source)
		assert.Equal(t, "--profile", resolved.Profile.Location)
	})

	t.Run("environment", func(t *testing.T) {
		t.Setenv(config.ProfileEnvironmentVariable, "staging")
		options, resolved, err := resolveTestOptions(t)
		require.NoError(t, err)
		assert.Equal(t, "staging-key", options.apiKey)
		assert.Equal(t, config.SourceEnvironment, resolved.Profile.Source)
		assert.Equal(t, config.ProfileEnvironmentVariable, resolved.Profile.Location)
	})

	t.Run("flag overrides environment", func(t *testing.T) {
		t.Setenv(config.ProfileEnvironmentVariable, "staging")
		options, _, err := resolveTestOptions(t, "--profile=default")
		require.NoError(t, err)
		assert.Equal(t, "default-key", options.apiKey)
	})

	t.Run("unknown profile has no values", func(t *testing.T) {
		options, resolved, err := resolveTestOptions(t, "--profile=missing")
		require.NoError(t, err)
		assert.False(t, resolved.Config.ProfileExists())
		assert.Empty(t, options.apiKey)
	})
}

func TestResolveOptions_InvalidValuesReportTheirSource(t *testing.T) {
	configPath, _ := testutil.WriteConfigFiles(t, "[default]\nhttp_timeout = soon\n", "")

	options, resolved, err := resolveTestOptions(t)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `invalid value "soon" for http_timeout`)
	assert.Contains(t, err.Error(), configPath)
	require.NotNil(t, resolved, "resolution itself succeeds so the configuration can be repaired")
	assert.Equal(t, err, resolved.Invalid)
	assert.Equal(t, 30*time.Second, options.httpTimeout, "the invalid value is not applied")
	assert.Equal(t, "soon", config.Find(resolved.Settings, "http_timeout").Value)
}

func TestResolveOptions_MalformedConfigFile(t *testing.T) {
	configPath, _ := testutil.WriteConfigFiles(t, "server_url = https://example.com\n", "")

	_, _, err := resolveTestOptions(t)
	require.Error(t, err)
	assert.Contains(t, err.Error(), configPath)
}

func TestResolveOptions_GitRepoPathFromConfigFileDisablesDeprecatedAutoDetect(t *testing.T) {
	testutil.WriteConfigFiles(t, "[default]\ngit_repo_path = /repo\n", "")
	t.Setenv(gitAutoDetectEnvironmentVariable, "true")

	options, resolved, err := resolveTestOptions(t)
	require.NoError(t, err)
	assert.Equal(t, "/repo", options.gitRepoPath)
	assert.False(t, resolved.DeprecatedGitAutoDetect)
}

func TestResolveOptions_DefaultFileLocationsUnderHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	require.NoError(t, os.MkdirAll(filepath.Join(home, config.DirName), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(home, config.DirName, config.ConfigFileName), []byte("[default]\nserver_url = https://home.example.com\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(home, config.DirName, config.CredentialsFileName), []byte("[default]\napi_key = home-key\n"), 0o600))

	options, _, err := resolveTestOptions(t)
	require.NoError(t, err)
	assert.Equal(t, "https://home.example.com", options.ServerURL)
	assert.Equal(t, "home-key", options.apiKey)
}

func TestCLI_RunsWithoutHomeDirectory(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	var authorization string
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()
	path := testutil.WriteSBOM(t)

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{"--server-url=" + httpServer.URL, "--api-key=flag-key", "--service=test-service", "--service-version=1.0", "sbom", "upload", path})
	})
	assert.Equal(t, 0, exitCode, "everything comes from flags, no home directory is needed: %s", stderr)
	assert.Empty(t, stderr)
	assert.Equal(t, "Bearer flag-key", authorization)

	exitCode, stdout, stderr := captureOutput(t, func() int {
		return CLI("1.0", "commit", []string{"config", "list"})
	})
	assert.Equal(t, 0, exitCode)
	assert.Empty(t, stderr)
	assert.Contains(t, stdout, "api_key")

	exitCode, stderr = captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{"config", "set", "api_key", "k"})
	})
	assert.Equal(t, 2, exitCode, "writing needs a location")
	assert.Contains(t, stderr, "cannot write credentials file: no home directory")
	assert.Contains(t, stderr, "set BIFROST_SHARED_CREDENTIALS_FILE to choose a location")

	exitCode, stderr = captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{"--profile=ci", "--api-key=k", "--service=s", "--service-version=1", "sbom", "upload", path})
	})
	assert.Equal(t, 2, exitCode)
	assert.Contains(t, stderr, `profile "ci" was not found because no configuration files are available (set BIFROST_CONFIG_FILE or BIFROST_SHARED_CREDENTIALS_FILE)`)
}

func TestCLI_UploadUsesAPIKeyFromCredentialsFile(t *testing.T) {
	var authorization string
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()
	testutil.WriteConfigFiles(t, fmt.Sprintf("[default]\nserver_url = %s\n", httpServer.URL), "[default]\napi_key = file-key\n")
	path := testutil.WriteSBOM(t)

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{"--service=test-service", "--service-version=1.0", "sbom", "upload", path})
	})
	assert.Equal(t, 0, exitCode)
	assert.Empty(t, stderr)
	assert.Equal(t, "Bearer file-key", authorization)

	t.Setenv("BIFROST_API_KEY", "env-key")
	exitCode = CLI("1.0", "commit", []string{"--service=test-service", "--service-version=1.0", "sbom", "upload", path})
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, "Bearer env-key", authorization, "environment overrides the credentials file")

	exitCode = CLI("1.0", "commit", []string{"--api-key=flag-key", "--service=test-service", "--service-version=1.0", "sbom", "upload", path})
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, "Bearer flag-key", authorization, "flag overrides the environment")
}

func TestCLI_UploadWithoutCredentialsFails(t *testing.T) {
	testutil.WriteConfigFiles(t, "", "")
	path := testutil.WriteSBOM(t)

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{"--service=test-service", "--service-version=1.0", "sbom", "upload", path})
	})
	assert.Equal(t, 2, exitCode)
	assert.Contains(t, stderr, `no credentials found for profile "default"`)
	assert.Contains(t, stderr, "bifrost config")
	assert.NotContains(t, stderr, "Usage:", "a missing credential is not a usage mistake")
}

func TestCLI_UnknownProfileFails(t *testing.T) {
	configPath, _ := testutil.WriteConfigFiles(t, "[default]\n", "")

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{"--profile=missing", "--service=s", "--service-version=1", "--api-key=k", "sbom", "upload", "x.json"})
	})
	assert.Equal(t, 2, exitCode)
	assert.Contains(t, stderr, `profile "missing" was not found`)
	assert.Contains(t, stderr, configPath)
}
