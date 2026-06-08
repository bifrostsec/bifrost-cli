// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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
		assert.Equal(t, "/api/v2/service/test-service/version/test-version/sbom", r.URL.Path)

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
	api := NewAPI(httpServer.URL, "test-token", DefaultRetryAttempts, DefaultRetryDelay)

	err = api.UploadSBOMFile(context.Background(), service, serviceVersion, path)
	assert.NoError(t, err)
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
	api := NewAPI(httpServer.URL, "test-token", DefaultRetryAttempts, DefaultRetryDelay)

	err = api.UploadSBOMFile(context.Background(), service, serviceVersion, path)
	assert.Error(t, err)
}

func TestAPI_UploadSBOM_FileNotFound(t *testing.T) {
	httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer httpServer.Close()

	api := NewAPI(httpServer.URL, "test-token", DefaultRetryAttempts, DefaultRetryDelay)

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

	api := NewAPI(httpServer.URL, "test-token", DefaultRetryAttempts, DefaultRetryDelay)

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

	api := NewAPI(httpServer.URL, "test-token", 2, time.Millisecond)

	err = api.UploadSBOMFile(context.Background(), "test-service", "test-version", path)
	assert.NoError(t, err)
	assert.EqualValues(t, 3, attempts.Load())
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

	api := NewAPI(httpServer.URL, "test-token", 5, time.Millisecond)

	err = api.UploadSBOMFile(context.Background(), "test-service", "test-version", path)
	assert.Error(t, err)
	assert.EqualValues(t, 1, attempts.Load())
}

func TestAPI_NewAPI_NormalizesNegativeRetryConfiguration(t *testing.T) {
	client := NewAPI("https://example.com", "test-token", -1, -1*time.Second)
	internalAPI, ok := client.(*api)
	assert.True(t, ok)
	assert.Equal(t, 0, internalAPI.retryAttempts)
	assert.Equal(t, time.Duration(0), internalAPI.retryDelay)
}
