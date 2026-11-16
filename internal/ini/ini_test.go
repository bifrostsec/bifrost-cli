// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package ini

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sample = `# shared settings
[default]
server_url = https://portal.example.com
retry_attempts=5

[profile staging]
; staging portal
server_url = https://staging.example.com
org_id = org_123
`

func TestParse_ReadsSectionsAndKeys(t *testing.T) {
	file, err := Parse(strings.NewReader(sample))
	require.NoError(t, err)

	assert.Equal(t, []string{"default", "profile staging"}, file.Sections())

	value, ok := file.Get("default", "server_url")
	assert.True(t, ok)
	assert.Equal(t, "https://portal.example.com", value)

	value, ok = file.Get("default", "RETRY_ATTEMPTS")
	assert.True(t, ok, "keys are matched case-insensitively")
	assert.Equal(t, "5", value)

	value, ok = file.Get("profile staging", "org_id")
	assert.True(t, ok)
	assert.Equal(t, "org_123", value)

	_, ok = file.Get("default", "org_id")
	assert.False(t, ok)
	_, ok = file.Get("missing", "server_url")
	assert.False(t, ok)
}

func TestParse_RejectsMalformedInput(t *testing.T) {
	tests := map[string]string{
		"key before section":   "server_url = x\n",
		"missing equals sign":  "[default]\nserver_url\n",
		"empty key":            "[default]\n= value\n",
		"empty section header": "[]\n",
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(strings.NewReader(input))
			assert.Error(t, err)
		})
	}
}

func TestParse_ValueMayContainEquals(t *testing.T) {
	file, err := Parse(strings.NewReader("[default]\napi_key = abc==def=\n"))
	require.NoError(t, err)
	value, _ := file.Get("default", "api_key")
	assert.Equal(t, "abc==def=", value)
}

func TestSet_PreservesCommentsAndOrder(t *testing.T) {
	file, err := Parse(strings.NewReader(sample))
	require.NoError(t, err)

	file.Set("default", "server_url", "https://other.example.com")
	file.Set("default", "http_timeout", "45s")
	file.Set("profile prod", "org_id", "org_999")

	var out strings.Builder
	_, err = file.WriteTo(&out)
	require.NoError(t, err)
	assert.Equal(t, `# shared settings
[default]
server_url = https://other.example.com
retry_attempts=5
http_timeout = 45s

[profile staging]
; staging portal
server_url = https://staging.example.com
org_id = org_123

[profile prod]
org_id = org_999
`, out.String())
}

func TestDelete_RemovesKey(t *testing.T) {
	file, err := Parse(strings.NewReader(sample))
	require.NoError(t, err)

	assert.True(t, file.Delete("profile staging", "org_id"))
	assert.False(t, file.Delete("profile staging", "org_id"))
	assert.False(t, file.Delete("missing", "org_id"))
	_, ok := file.Get("profile staging", "org_id")
	assert.False(t, ok)
}

func TestLoadAndSave_RoundTripsWithOwnerOnlyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "credentials")

	file, err := Load(path)
	require.NoError(t, err, "a missing file is not an error")
	assert.Empty(t, file.Sections())

	file.Set("default", "api_key", "secret")
	require.NoError(t, file.Save(path))

	info, err := os.Stat(path)
	require.NoError(t, err)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("expected permissions 0600, got %o", info.Mode().Perm())
	}

	reloaded, err := Load(path)
	require.NoError(t, err)
	value, ok := reloaded.Get("default", "api_key")
	assert.True(t, ok)
	assert.Equal(t, "secret", value)
}

func TestLoad_ReportsParseErrorsWithPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config")
	require.NoError(t, os.WriteFile(path, []byte("broken\n"), 0o600))

	_, err := Load(path)
	require.Error(t, err)
	assert.Contains(t, err.Error(), path)
}
