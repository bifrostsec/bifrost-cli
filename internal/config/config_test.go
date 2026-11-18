// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bifrostsec/bifrost-cli/internal/testutil"
)

func TestMain(m *testing.M) {
	cleanup := testutil.IsolateEnvironment()
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// newFlagSet registers a flag for every setting, as the cli package does.
func newFlagSet() (*flag.FlagSet, map[string]any) {
	fl := flag.NewFlagSet("", flag.ContinueOnError)
	values := map[string]any{}
	values["server_url"] = fl.String("server-url", "https://default.example.com", "")
	values["api_key"] = fl.String("api-key", "", "")
	values["org_id"] = fl.String("org-id", "", "")
	values["retry_attempts"] = fl.Int("retry-attempts", 3, "")
	values["retry_delay"] = fl.Duration("retry-delay", 2*time.Second, "")
	values["http_timeout"] = fl.Duration("http-timeout", 30*time.Second, "")
	values["git_repo_path"] = fl.String("git-repo-path", "", "")
	return fl, values
}

func TestResolve_Precedence(t *testing.T) {
	configPath, credentialsPath := testutil.WriteConfigFiles(t, `[default]
server_url = https://file.example.com
retry_attempts = 7
http_timeout = 11s
api_key = key-from-config
`, `[default]
api_key = key-from-credentials
`)
	t.Setenv("BIFROST_SERVER_URL", "https://env.example.com")
	fl, values := newFlagSet()
	require.NoError(t, fl.Parse([]string{"--retry-attempts=2"}))
	cfg, err := Load(DefaultProfile)
	require.NoError(t, err)

	resolved, err := Resolve(fl, cfg)
	require.NoError(t, err)

	assert.Equal(t, 2, *values["retry_attempts"].(*int), "flag wins")
	assert.Equal(t, "https://env.example.com", *values["server_url"].(*string), "environment wins over file")
	assert.Equal(t, 11*time.Second, *values["http_timeout"].(*time.Duration), "file wins over default")
	assert.Equal(t, "key-from-credentials", *values["api_key"].(*string), "credentials file wins over config file")
	assert.Equal(t, 2*time.Second, *values["retry_delay"].(*time.Duration), "default remains")

	expected := map[string]Resolved{
		"retry_attempts": {Value: "2", Source: SourceCommandLine, Location: "--retry-attempts"},
		"server_url":     {Value: "https://env.example.com", Source: SourceEnvironment, Location: "BIFROST_SERVER_URL"},
		"http_timeout":   {Value: "11s", Source: SourceConfigFile, Location: configPath},
		"api_key":        {Value: "key-from-credentials", Source: SourceCredentialsFile, Location: credentialsPath},
		"retry_delay":    {Value: "2s", Source: SourceDefault},
		"org_id":         {Source: SourceNotSet},
		"access_token":   {Source: SourceNotSet},
	}
	for name, want := range expected {
		got := Find(resolved, name)
		assert.Equal(t, want.Value, got.Value, name)
		assert.Equal(t, want.Source, got.Source, name)
		assert.Equal(t, want.Location, got.Location, name)
		assert.Equal(t, want.Source != SourceNotSet, got.IsSet(), name)
	}
	assert.Equal(t, SourceNotSet, Find(resolved, "unknown").Source)
}

func TestResolve_InvalidValuesAreReportedButDoNotStopResolution(t *testing.T) {
	configPath, _ := testutil.WriteConfigFiles(t, "[default]\nhttp_timeout = soon\nserver_url = https://file.example.com\n", "")
	fl, values := newFlagSet()
	cfg, err := Load(DefaultProfile)
	require.NoError(t, err)

	resolved, err := Resolve(fl, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), `invalid value "soon" for http_timeout from config-file `+configPath)
	assert.Equal(t, "https://file.example.com", *values["server_url"].(*string), "valid values are still applied")
	assert.Equal(t, 30*time.Second, *values["http_timeout"].(*time.Duration), "the invalid value leaves the default in place")
	invalid := Find(resolved, "http_timeout")
	assert.Equal(t, "soon", invalid.Value, "the stored value is still reported so it can be inspected and repaired")
	assert.Equal(t, SourceConfigFile, invalid.Source)

	t.Setenv("BIFROST_RETRY_ATTEMPTS", "many")
	_, err = Resolve(fl, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "environment variable BIFROST_RETRY_ATTEMPTS")
	assert.Contains(t, err.Error(), "http_timeout", "every invalid value is reported")
}

func TestLoad_CredentialsFileMayHoldAnySetting(t *testing.T) {
	_, credentialsPath := testutil.WriteConfigFiles(t, "[default]\nserver_url = https://config.example.com\n", "[default]\napi_key = key\nserver_url = https://credentials.example.com\n")
	fl, values := newFlagSet()
	cfg, err := Load(DefaultProfile)
	require.NoError(t, err)

	resolved, err := Resolve(fl, cfg)
	require.NoError(t, err)
	assert.Equal(t, "https://credentials.example.com", *values["server_url"].(*string), "the credentials file wins for every setting")
	serverURL := Find(resolved, "server_url")
	assert.Equal(t, SourceCredentialsFile, serverURL.Source)
	assert.Equal(t, credentialsPath, serverURL.Location)
}

func TestLoad_ProfilesAndSections(t *testing.T) {
	testutil.WriteConfigFiles(t, `[default]
server_url = https://default.example.com

[profile staging]
server_url = https://staging.example.com

[bare]
server_url = https://bare.example.com
`, `[default]
api_key = default-key

[staging]
api_key = staging-key
`)
	serverURL := MustSetting("server_url")
	apiKey := MustSetting("api_key")

	cfg, err := Load("staging")
	require.NoError(t, err)
	assert.True(t, cfg.ProfileExists())
	value, _ := cfg.Get(serverURL)
	assert.Equal(t, "https://staging.example.com", value)
	value, _ = cfg.Get(apiKey)
	assert.Equal(t, "staging-key", value)
	assert.Equal(t, []string{"default", "staging", "bare"}, cfg.Profiles())

	cfg, err = Load("bare")
	require.NoError(t, err)
	assert.True(t, cfg.ProfileExists(), "a bare section name is accepted in the config file")
	value, _ = cfg.Get(serverURL)
	assert.Equal(t, "https://bare.example.com", value)
	_, ok := cfg.Get(apiKey)
	assert.False(t, ok)

	cfg, err = Load("missing")
	require.NoError(t, err)
	assert.False(t, cfg.ProfileExists())

	cfg, err = Load("")
	require.NoError(t, err)
	assert.Equal(t, DefaultProfile, cfg.Profile)
}

func TestConfig_SetUnsetSave(t *testing.T) {
	configPath, credentialsPath := testutil.WriteConfigFiles(t, "", "")

	cfg, err := Load("staging")
	require.NoError(t, err)
	cfg.Set(MustSetting("api_key"), "secret")
	cfg.Set(MustSetting("server-url"), "https://staging.example.com")
	require.NoError(t, cfg.Save())

	assert.Equal(t, "[profile staging]\nserver_url = https://staging.example.com\n", testutil.ReadFile(t, configPath))
	assert.Equal(t, "[staging]\napi_key = secret\n", testutil.ReadFile(t, credentialsPath))
	for _, path := range []string{configPath, credentialsPath} {
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), path)
	}

	cfg, err = Load("staging")
	require.NoError(t, err)
	assert.True(t, cfg.Unset(MustSetting("api_key")))
	assert.False(t, cfg.Unset(MustSetting("api_key")))
	require.NoError(t, cfg.Save())
	assert.Equal(t, "[staging]\n", testutil.ReadFile(t, credentialsPath))
}

func TestLoad_MalformedFile(t *testing.T) {
	configPath, _ := testutil.WriteConfigFiles(t, "server_url = https://example.com\n", "")

	_, err := Load(DefaultProfile)
	require.Error(t, err)
	assert.Contains(t, err.Error(), configPath)
	assert.Contains(t, err.Error(), "before any [section] header")
}

func TestLoad_DefaultLocationsUnderHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	cfg, err := Load(DefaultProfile)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, DirName, ConfigFileName), cfg.ConfigPath)
	assert.Equal(t, filepath.Join(home, DirName, CredentialsFileName), cfg.CredentialsPath)
	assert.Equal(t, filepath.Join("~", DirName, ConfigFileName), DisplayPath(cfg.ConfigPath))
	assert.Equal(t, "/elsewhere/config", DisplayPath("/elsewhere/config"))
}

func TestLoad_WithoutHomeDirectoryReadsNothingAndCannotWrite(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")

	cfg, err := Load(DefaultProfile)
	require.NoError(t, err, "a missing home directory must not stop commands that get everything from flags")
	assert.Empty(t, cfg.ConfigPath)
	assert.Empty(t, cfg.CredentialsPath)
	assert.False(t, cfg.ProfileExists())
	assert.Empty(t, cfg.Profiles())
	_, ok := cfg.Get(MustSetting("api_key"))
	assert.False(t, ok)

	fl, values := newFlagSet()
	resolved, err := Resolve(fl, cfg)
	require.NoError(t, err)
	assert.Equal(t, "https://default.example.com", *values["server_url"].(*string))
	assert.Equal(t, SourceDefault, Find(resolved, "server_url").Source)

	cfg.Set(MustSetting("api_key"), "k")
	err = cfg.Save()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot write credentials file: no home directory for the default credentials file location")
	assert.Contains(t, err.Error(), "set BIFROST_SHARED_CREDENTIALS_FILE to choose a location")

	cfg.Set(MustSetting("server_url"), "https://x.example.com")
	err = cfg.Save()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set BIFROST_CONFIG_FILE to choose a location")

	// An explicit location works without a home directory.
	_, credentialsPath := testutil.WriteConfigFiles(t, "", "[default]\napi_key = from-file\n")
	cfg, err = Load(DefaultProfile)
	require.NoError(t, err)
	assert.Equal(t, credentialsPath, cfg.CredentialsPath)
	value, _ := cfg.Get(MustSetting("api_key"))
	assert.Equal(t, "from-file", value)
	cfg.Set(MustSetting("api_key"), "k")
	require.NoError(t, cfg.Save())
}

func TestMaskSecret(t *testing.T) {
	assert.Equal(t, "****", MaskSecret(""))
	assert.Equal(t, "****", MaskSecret("abcd"))
	assert.Equal(t, "****************wxyz", MaskSecret("secret-token-wxyz"))
}

func TestLookupSetting_AcceptsFlagSpelling(t *testing.T) {
	for _, name := range []string{"server_url", "server-url", "--server-url", "SERVER_URL"} {
		s, ok := LookupSetting(name)
		assert.True(t, ok, name)
		assert.Equal(t, "server_url", s.Name)
	}
	_, ok := LookupSetting("service")
	assert.False(t, ok, "per-upload options are not stored in configuration files")
	assert.Panics(t, func() { MustSetting("service") })
	assert.Equal(t, []string{"server_url", "api_key", "org_id", "retry_attempts", "retry_delay", "http_timeout", "git_repo_path", "access_token", "access_token_expires_at", "access_token_server_url", "access_token_org_id"}, Names())
}

func TestResolved_DescribeSource(t *testing.T) {
	assert.Equal(t, "option --api-key", Resolved{Source: SourceCommandLine, Location: "--api-key"}.DescribeSource())
	assert.Equal(t, "environment variable BIFROST_API_KEY", Resolved{Source: SourceEnvironment, Location: "BIFROST_API_KEY"}.DescribeSource())
	assert.Equal(t, "credentials-file /tmp/credentials", Resolved{Source: SourceCredentialsFile, Location: "/tmp/credentials"}.DescribeSource())
	assert.Equal(t, "default", Resolved{Source: SourceDefault}.DescribeSource())
}
