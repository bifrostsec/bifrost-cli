// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAPI_UploadSBOM(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "/api/v2/service/test-service/version/sbom", r.URL.Path)
		query := r.URL.Query()
		assert.Equal(t, "test-version", query.Get("version"))
		assert.Empty(t, query.Get("image"))
		_, hasGitBranch := query["git_branch"]
		_, hasGitCommitSHA := query["git_commit_sha"]
		_, hasGitOrigin := query["git_origin"]
		assert.False(t, hasGitBranch)
		assert.False(t, hasGitCommitSHA)
		assert.False(t, hasGitOrigin)

		// Verify that request body is being read
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.NotEmpty(t, body)

		// Respond with success
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(path)
	}()

	service := "test-service"
	serviceVersion := "test-version"
	api := NewAPI(httpServer.URL, "test-token", DefaultRetryAttempts, DefaultRetryDelay, "", "", "", "")

	err = api.UploadSBOMFile(context.Background(), service, serviceVersion, path)
	assert.NoError(t, err)
}

func TestAPI_UploadSBOM_EscapesServiceAndVersionPathSegments(t *testing.T) {
	service := "team/test-service"
	serviceVersion := "bkimminich/juice-shop@sha256:3f4a1c9e2b8d7f6a5e4d3c2b1a0f9e8d7c6b5a4938271605f4e3d2c1b0a9988"
	expectedPath := fmt.Sprintf(
		"/api/v2/service/%s/version/sbom",
		url.PathEscape(service),
	)
	expectedQuery := url.Values{}
	expectedQuery.Set("version", serviceVersion)

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectedPath, r.URL.EscapedPath())
		assert.Equal(t, expectedQuery.Encode(), r.URL.RawQuery)
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(path)
	}()

	api := NewAPI(httpServer.URL, "test-token", DefaultRetryAttempts, DefaultRetryDelay, "", "", "", "")

	err = api.UploadSBOMFile(context.Background(), service, serviceVersion, path)
	assert.NoError(t, err)
}

func TestAPI_UploadSBOM_IncludesVersionAndGitMetadataQueryParams(t *testing.T) {
	serviceVersion := "test-version"
	gitBranch := "feature/deployments & scans"
	gitCommitSHA := "abc123+digest"
	gitOrigin := "https://github.com/example/project.git?ref=main&token=a+b"
	expectedQuery := url.Values{}
	expectedQuery.Set("version", serviceVersion)
	expectedQuery.Set("git_branch", gitBranch)
	expectedQuery.Set("git_commit_sha", gitCommitSHA)
	expectedQuery.Set("git_origin", gitOrigin)

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectedQuery.Encode(), r.URL.RawQuery)
		assert.Equal(t, serviceVersion, r.URL.Query().Get("version"))
		assert.Equal(t, gitBranch, r.URL.Query().Get("git_branch"))
		assert.Equal(t, gitCommitSHA, r.URL.Query().Get("git_commit_sha"))
		assert.Equal(t, gitOrigin, r.URL.Query().Get("git_origin"))
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(path)
	}()

	api := NewAPI(
		httpServer.URL,
		"test-token",
		DefaultRetryAttempts,
		DefaultRetryDelay,
		gitBranch,
		gitCommitSHA,
		gitOrigin,
		"",
	)

	err = api.UploadSBOMFile(context.Background(), "test-service", serviceVersion, path)
	assert.NoError(t, err)
}

func TestAPI_UploadSBOM_IncludesImageQueryParam(t *testing.T) {
	image := "registry.example.com/team/app@sha256:abc123"
	expectedQuery := url.Values{}
	expectedQuery.Set("image", image)

	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, expectedQuery.Encode(), r.URL.RawQuery)
		assert.Empty(t, r.URL.Query().Get("version"))
		assert.Equal(t, image, r.URL.Query().Get("image"))
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(path)
	}()

	api := NewAPI(httpServer.URL, "test-token", DefaultRetryAttempts, DefaultRetryDelay, "", "", "", image)

	err = api.UploadSBOMFile(context.Background(), "test-service", "", path)
	assert.NoError(t, err)
}

func TestAPI_UploadSBOM_RequiresVersionOrImage(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("request should not be sent when both version and image are missing")
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(path)
	}()

	api := NewAPI(httpServer.URL, "test-token", DefaultRetryAttempts, DefaultRetryDelay, "", "", "", "")

	err = api.UploadSBOMFile(context.Background(), "test-service", "", path)
	assert.EqualError(t, err, "either service version or image is required")
}

func TestAPI_UploadSBOM_Error(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(path)
	}()

	service := "test-service"
	serviceVersion := "test-version"
	api := NewAPI(httpServer.URL, "test-token", DefaultRetryAttempts, DefaultRetryDelay, "", "", "", "")

	err = api.UploadSBOMFile(context.Background(), service, serviceVersion, path)
	assert.Error(t, err)
}

func TestAPI_UploadSBOM_FileNotFound(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	api := NewAPI(httpServer.URL, "test-token", DefaultRetryAttempts, DefaultRetryDelay, "", "", "", "")

	err := api.UploadSBOMFile(context.Background(), "test-service", "test-version", "nonexistent-file.json")
	assert.Error(t, err)
}

func TestAPI_UploadSBOM_NotRegularFile(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	// Create a directory instead of a file
	dirPath := "test-dir"
	err := os.Mkdir(dirPath, 0755)
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(dirPath)
	}()

	api := NewAPI(httpServer.URL, "test-token", DefaultRetryAttempts, DefaultRetryDelay, "", "", "", "")

	err = api.UploadSBOMFile(context.Background(), "test-service", "test-version", dirPath)
	assert.Error(t, err)
}

func TestAPI_UploadSBOM_RetriesTransientFailure(t *testing.T) {
	var attempts atomic.Int32
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(path)
	}()

	client := NewAPI(httpServer.URL, "test-token", 2, time.Millisecond, "", "", "", "")
	internalAPI, ok := client.(*api)
	assert.True(t, ok)
	var retryOutput bytes.Buffer
	internalAPI.retryOutput = &retryOutput

	err = client.UploadSBOMFile(context.Background(), "test-service", "test-version", path)
	assert.NoError(t, err)
	assert.EqualValues(t, 3, attempts.Load())
	assert.Contains(t, retryOutput.String(), "Retrying in 1ms (1/2)")
	assert.Contains(t, retryOutput.String(), "Retrying in 1ms (2/2)")
}

func TestAPI_UploadSBOM_DoesNotRetryClientFailure(t *testing.T) {
	var attempts atomic.Int32
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer httpServer.Close()

	path := "test-sbom.json"
	err := os.WriteFile(path, []byte(`{"name":"test","version":"1.0"}`), 0644)
	assert.NoError(t, err)
	defer func() {
		_ = os.Remove(path)
	}()

	api := NewAPI(httpServer.URL, "test-token", 5, time.Millisecond, "", "", "", "")

	err = api.UploadSBOMFile(context.Background(), "test-service", "test-version", path)
	assert.Error(t, err)
	assert.EqualValues(t, 1, attempts.Load())
}

func TestAPI_NewAPI_NormalizesNegativeRetryConfiguration(t *testing.T) {
	client := NewAPI("https://example.com", "test-token", -1, -1*time.Second, "", "", "", "")
	internalAPI, ok := client.(*api)
	assert.True(t, ok)
	assert.Equal(t, 0, internalAPI.retryAttempts)
	assert.Equal(t, time.Duration(0), internalAPI.retryDelay)
}

func TestShouldRetry_ContextCancellationIsNotRetryable(t *testing.T) {
	assert.False(t, shouldRetry(&requestError{cause: context.Canceled}))
	assert.False(t, shouldRetry(&requestError{cause: context.DeadlineExceeded}))
}

func TestShouldRetry_WrappedContextCancellationIsNotRetryable(t *testing.T) {
	assert.False(t, shouldRetry(&requestError{cause: fmt.Errorf("request failed: %w", context.Canceled)}))
	assert.False(t, shouldRetry(&requestError{cause: fmt.Errorf("request failed: %w", context.DeadlineExceeded)}))
}

func TestShouldRetry_NonContextRequestErrorIsRetryable(t *testing.T) {
	assert.True(t, shouldRetry(&requestError{cause: errors.New("connection reset by peer")}))
}
