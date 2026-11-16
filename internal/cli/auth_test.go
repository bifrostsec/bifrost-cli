// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bifrostsec/bifrost-cli/internal/auth"
	"github.com/bifrostsec/bifrost-cli/internal/oauth2"
	"github.com/bifrostsec/bifrost-cli/internal/testutil"
)

const (
	testOrgID          = "org_01m2fwhfjmfdcv7cm1b23xg7qa"
	testIDToken        = "header.github-oidc-payload.signature"
	testExchangedToken = "header.portal-access-token.signature"
	testRequestToken   = "actions-request-token"
)

// fakeGitHubActions serves the OIDC token request endpoint a GitHub Actions
// job sees and exports the environment variables that point the CLI at it.
func fakeGitHubActions(t *testing.T, idToken string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/token", r.URL.Path)
		assert.Equal(t, "2.0", r.URL.Query().Get("api-version"), "existing query parameters are preserved")
		assert.Equal(t, testOrgID, r.URL.Query().Get("audience"))
		assert.Equal(t, "bearer "+testRequestToken, r.Header.Get("Authorization"))
		assert.Equal(t, "application/json; api-version=2.0", r.Header.Get("Accept"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"count": 1, "value": idToken})
	}))
	t.Cleanup(server.Close)
	t.Setenv(auth.GitHubActionsEnvironmentVariable, "true")
	t.Setenv(auth.GitHubActionsIDTokenRequestURLVariable, server.URL+"/token?api-version=2.0")
	t.Setenv(auth.GitHubActionsIDTokenRequestTokenVariable, testRequestToken)
	return server
}

// fakePortal serves the token endpoint and the SBOM upload endpoint.
type fakePortal struct {
	*httptest.Server
	exchanges     atomic.Int32
	uploadBearer  atomic.Pointer[string]
	tokenResponse func(w http.ResponseWriter, form map[string]string)
}

func newFakePortal(t *testing.T) *fakePortal {
	t.Helper()
	portal := &fakePortal{}
	portal.tokenResponse = func(w http.ResponseWriter, _ map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      testExchangedToken,
			"token_type":        "Bearer",
			"expires_in":        600,
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		})
	}
	portal.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == oauth2.TokenEndpointPath:
			portal.exchanges.Add(1)
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
			assert.Equal(t, "bifrost-cli/1.0", r.Header.Get("User-Agent"))
			require.NoError(t, r.ParseForm())
			assert.Equal(t, oauth2.GrantTypeTokenExchange, r.PostForm.Get("grant_type"))
			assert.Equal(t, oauth2.TokenTypeJWT, r.PostForm.Get("subject_token_type"))
			assert.Equal(t, testIDToken, r.PostForm.Get("subject_token"))
			assert.Empty(t, r.PostForm.Get("scope"))
			form := map[string]string{}
			for key := range r.PostForm {
				form[key] = r.PostForm.Get(key)
			}
			portal.tokenResponse(w, form)
		case strings.HasPrefix(r.URL.Path, "/api/v2/service/"):
			bearer := r.Header.Get("Authorization")
			portal.uploadBearer.Store(&bearer)
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected request to %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(portal.Close)
	return portal
}

func (p *fakePortal) uploadAuthorization() string {
	if bearer := p.uploadBearer.Load(); bearer != nil {
		return *bearer
	}
	return ""
}

func TestCLI_UploadExchangesGitHubActionsOIDCTokenAutomatically(t *testing.T) {
	testutil.WriteConfigFiles(t, "", "")
	fakeGitHubActions(t, testIDToken)
	portal := newFakePortal(t)
	path := testutil.WriteSBOM(t)

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{
			"--server-url=" + portal.URL, "--org-id=" + testOrgID,
			"--service=test-service", "--service-version=1.0", "sbom", "upload", path,
		})
	})
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, int32(1), portal.exchanges.Load())
	assert.Equal(t, "Bearer "+testExchangedToken, portal.uploadAuthorization())
	assert.Contains(t, stderr, "Exchanged GitHub Actions OIDC token for a bifrost access token (organization "+testOrgID+", expires at ")
}

func TestCLI_UploadPrefersConfiguredAPIKeyOverGitHubActionsExchange(t *testing.T) {
	testutil.WriteConfigFiles(t, fmt.Sprintf("[default]\norg_id = %s\n", testOrgID), "[default]\napi_key = file-key\n")
	fakeGitHubActions(t, testIDToken)
	portal := newFakePortal(t)
	path := testutil.WriteSBOM(t)

	exitCode := CLI("1.0", "commit", []string{"--server-url=" + portal.URL, "--service=test-service", "--service-version=1.0", "sbom", "upload", path})
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, int32(0), portal.exchanges.Load())
	assert.Equal(t, "Bearer file-key", portal.uploadAuthorization())
}

func TestCLI_UploadInGitHubActionsWithoutOrgIDExplainsWhatIsMissing(t *testing.T) {
	testutil.WriteConfigFiles(t, "", "")
	fakeGitHubActions(t, testIDToken)
	path := testutil.WriteSBOM(t)

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{"--service=test-service", "--service-version=1.0", "sbom", "upload", path})
	})
	assert.Equal(t, 2, exitCode)
	assert.Contains(t, stderr, "no credentials found")
	assert.Contains(t, stderr, "no organization id is configured: pass --org-id, set BIFROST_ORG_ID")
}

func TestCLI_UploadInGitHubActionsWithoutIDTokenPermissionExplainsWhatIsMissing(t *testing.T) {
	testutil.WriteConfigFiles(t, "", "")
	t.Setenv(auth.GitHubActionsEnvironmentVariable, "true")
	path := testutil.WriteSBOM(t)

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{"--org-id=" + testOrgID, "--service=test-service", "--service-version=1.0", "sbom", "upload", path})
	})
	assert.Equal(t, 2, exitCode)
	assert.Contains(t, stderr, "running in GitHub Actions without an OIDC token request environment: grant the job `permissions: id-token: write`")
}

func TestCLI_UploadReportsTokenExchangeErrors(t *testing.T) {
	testutil.WriteConfigFiles(t, "", "")
	fakeGitHubActions(t, testIDToken)
	portal := newFakePortal(t)
	portal.tokenResponse = func(w http.ResponseWriter, _ map[string]string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "GitHub organization 'acme' is not linked to organization 'Acme Inc'",
		})
	}
	path := testutil.WriteSBOM(t)

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{
			"--server-url=" + portal.URL, "--org-id=" + testOrgID,
			"--service=test-service", "--service-version=1.0", "sbom", "upload", path,
		})
	})
	assert.Equal(t, 2, exitCode)
	assert.Contains(t, stderr, "failed to exchange GitHub Actions OIDC token for organization "+testOrgID)
	assert.Contains(t, stderr, "invalid_grant: GitHub organization 'acme' is not linked to organization 'Acme Inc'")
	assert.Empty(t, portal.uploadAuthorization(), "no upload is attempted without credentials")
}

func TestCLI_AuthGitHubActionsStoresAccessTokenForLaterCommands(t *testing.T) {
	_, credentialsPath := testutil.WriteConfigFiles(t, "", "")
	fakeGitHubActions(t, testIDToken)
	portal := newFakePortal(t)

	exitCode, stdout, stderr := captureOutput(t, func() int {
		return CLI("1.0", "commit", []string{"--server-url=" + portal.URL, "--org-id=" + testOrgID, "auth", "github-actions"})
	})
	assert.Equal(t, 0, exitCode)
	assert.Empty(t, stdout, "the token is stored, not printed")
	assert.Contains(t, stderr, fmt.Sprintf("Stored access token for organization %s in profile \"default\" (%s), expires at ", testOrgID, credentialsPath))

	credentials := testutil.ReadFile(t, credentialsPath)
	assert.Contains(t, credentials, "[default]\naccess_token = "+testExchangedToken+"\n")
	assert.Regexp(t, `access_token_expires_at = \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`, credentials)

	// A following step without the OIDC environment or an organization id uses the stored token.
	t.Setenv(auth.GitHubActionsIDTokenRequestURLVariable, "")
	t.Setenv(auth.GitHubActionsIDTokenRequestTokenVariable, "")
	path := testutil.WriteSBOM(t)
	exitCode, stderr = captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{"--server-url=" + portal.URL, "--service=test-service", "--service-version=1.0", "sbom", "upload", path})
	})
	assert.Equal(t, 0, exitCode)
	assert.Empty(t, stderr)
	assert.Equal(t, int32(1), portal.exchanges.Load(), "no second exchange")
	assert.Equal(t, "Bearer "+testExchangedToken, portal.uploadAuthorization())
}

func TestCLI_AuthGitHubActionsOutsideGitHubActionsFails(t *testing.T) {
	testutil.WriteConfigFiles(t, "", "")

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{"--org-id=" + testOrgID, "auth", "github-actions"})
	})
	assert.Equal(t, 2, exitCode)
	assert.Contains(t, stderr, "cannot exchange GitHub Actions OIDC token: ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN are not set")
}

func TestCLI_AuthGitHubActionsRequiresOrgID(t *testing.T) {
	testutil.WriteConfigFiles(t, "", "")
	fakeGitHubActions(t, testIDToken)

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{"auth", "github-actions"})
	})
	assert.Equal(t, 2, exitCode)
	assert.Contains(t, stderr, "no organization id is configured")
}

func TestCLI_AuthTokenPrintsResolvedCredential(t *testing.T) {
	testutil.WriteConfigFiles(t, "", "[default]\napi_key = file-key\n")

	exitCode, stdout, stderr := captureOutput(t, func() int {
		return CLI("1.0", "commit", []string{"auth", "token"})
	})
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, "file-key\n", stdout)
	assert.Empty(t, stderr)

	fakeGitHubActions(t, testIDToken)
	portal := newFakePortal(t)
	exitCode, stdout, stderr = captureOutput(t, func() int {
		return CLI("1.0", "commit", []string{"--profile=ci", "--server-url=" + portal.URL, "--org-id=" + testOrgID, "auth", "token"})
	})
	assert.Equal(t, 2, exitCode, "an unknown profile is rejected")
	assert.Contains(t, stderr, `profile "ci" was not found`)
	assert.Empty(t, stdout)

	exitCode, stdout, stderr = captureOutput(t, func() int {
		return CLI("1.0", "commit", []string{"--api-key=", "--server-url=" + portal.URL, "--org-id=" + testOrgID, "auth", "token"})
	})
	assert.Equal(t, 0, exitCode)
	assert.Equal(t, testExchangedToken+"\n", stdout, "an empty --api-key falls through to the exchange")
	assert.Contains(t, stderr, "Exchanged GitHub Actions OIDC token")
}

func TestCLI_AuthUnknownSubcommand(t *testing.T) {
	testutil.WriteConfigFiles(t, "", "")

	exitCode, stderr := captureStderr(t, func() int {
		return CLI("1.0", "commit", []string{"auth", "login"})
	})
	assert.Equal(t, 2, exitCode)
	assert.Contains(t, stderr, "Unrecognized command")
}
