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
	"os"
	"time"
)

const (
	DefaultServerURL     = "https://portal.bifrostsec.com"
	DefaultRetryAttempts = 3
	DefaultRetryDelay    = 2 * time.Second
)

type API interface {
	UploadSBOMFile(ctx context.Context, service string, serviceVersion string, filePath string) error
	UploadSBOMBytes(ctx context.Context, service string, serviceVersion string, sourceName string, content []byte) error
}

type api struct {
	client        http.Client
	serverUrl     string
	token         string
	retryAttempts int
	retryDelay    time.Duration
}

func NewAPI(serverURL string, token string, retryAttempts int, retryDelay time.Duration) API {
	return &api{
		client:        http.Client{},
		serverUrl:     serverURL,
		token:         token,
		retryAttempts: retryAttempts,
		retryDelay:    retryDelay,
	}
}

func (a *api) UploadSBOMFile(ctx context.Context, service string, serviceVersion string, filePath string) error {
	fi, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("SBOM file does not exist at path: %s", filePath)
		}
		return fmt.Errorf("failed to access file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("path is not a regular file: %s", filePath)
	}

	return a.uploadSBOM(ctx, service, serviceVersion, filePath, func() (io.ReadCloser, error) {
		file, err := os.Open(filePath)
		if err != nil {
			return nil, fmt.Errorf("failed to open SBOM file: %w", err)
		}
		return file, nil
	})
}

func (a *api) UploadSBOMBytes(ctx context.Context, service string, serviceVersion string, sourceName string, content []byte) error {
	return a.uploadSBOM(ctx, service, serviceVersion, sourceName, func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(content)), nil
	})
}

func (a *api) uploadSBOM(ctx context.Context, service string, serviceVersion string, sourceName string, openBody func() (io.ReadCloser, error)) error {
	var err error
	for attempt := 0; attempt <= a.retryAttempts; attempt++ {
		err = a.uploadSBOMOnce(ctx, service, serviceVersion, sourceName, openBody)
		if err == nil {
			return nil
		}
		if attempt == a.retryAttempts || !shouldRetry(err) {
			return err
		}
		if err := sleepWithContext(ctx, a.retryDelay); err != nil {
			return err
		}
	}

	return err
}

func (a *api) uploadSBOMOnce(ctx context.Context, service string, serviceVersion string, sourceName string, openBody func() (io.ReadCloser, error)) error {
	file, err := openBody()
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf("%s/api/v2/service/%s/version/%s/sbom", a.serverUrl, service, serviceVersion),
		file,
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Authorization", "Bearer "+a.token)
	req.Header.Add("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return &requestError{cause: err}
	}

	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return &uploadError{
			filePath:   sourceName,
			statusCode: resp.StatusCode,
			status:     resp.Status,
			body:       string(body),
		}
	}

	return nil
}

type uploadError struct {
	filePath   string
	statusCode int
	status     string
	body       string
}

func (e *uploadError) Error() string {
	return fmt.Sprintf("upload failed %s: %s: %s", e.filePath, e.status, e.body)
}

type requestError struct {
	cause error
}

func (e *requestError) Error() string {
	return fmt.Sprintf("failed to send request: %v", e.cause)
}

func (e *requestError) Unwrap() error {
	return e.cause
}

func shouldRetry(err error) bool {
	var uploadErr *uploadError
	if errors.As(err, &uploadErr) {
		return uploadErr.statusCode == http.StatusRequestTimeout ||
			uploadErr.statusCode == http.StatusTooManyRequests ||
			uploadErr.statusCode >= http.StatusInternalServerError
	}
	var reqErr *requestError
	return errors.As(err, &reqErr)
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
