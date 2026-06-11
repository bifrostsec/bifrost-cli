// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
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
}

type api struct {
	client        http.Client
	serverUrl     string
	token         string
	retryAttempts int
	retryDelay    time.Duration
	retryOutput   io.Writer
	gitBranch     string
	gitCommitSHA  string
}

func NewAPI(serverURL string, token string, retryAttempts int, retryDelay time.Duration, gitBranch string, gitCommitSHA string) API {
	if retryAttempts < 0 {
		retryAttempts = 0
	}
	if retryDelay < 0 {
		retryDelay = 0
	}
	return &api{
		client:        http.Client{},
		serverUrl:     serverURL,
		token:         token,
		retryAttempts: retryAttempts,
		retryDelay:    retryDelay,
		retryOutput:   os.Stderr,
		gitBranch:     gitBranch,
		gitCommitSHA:  gitCommitSHA,
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

func (a *api) uploadSBOM(ctx context.Context, service string, serviceVersion string, sourceLabel string, openBody func() (io.ReadCloser, error)) error {
	var err error
	for attempt := 0; attempt <= a.retryAttempts; attempt++ {
		err = a.uploadSBOMOnce(ctx, service, serviceVersion, sourceLabel, openBody)
		if err == nil {
			return nil
		}
		if attempt == a.retryAttempts || !shouldRetry(err) {
			return err
		}
		a.printRetryMessage(sourceLabel, err, attempt+1)
		if err := sleepWithContext(ctx, a.retryDelay); err != nil {
			return err
		}
	}

	return err
}

func (a *api) printRetryMessage(sourceLabel string, err error, retryNumber int) {
	if a.retryOutput == nil {
		return
	}
	_, _ = fmt.Fprintf(
		a.retryOutput,
		"Upload failed for %s: %v. Retrying in %s (%d/%d)\n",
		sourceLabel,
		err,
		a.retryDelay,
		retryNumber,
		a.retryAttempts,
	)
}

func (a *api) uploadSBOMOnce(ctx context.Context, service string, serviceVersion string, sourceLabel string, openBody func() (io.ReadCloser, error)) error {
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

	query := req.URL.Query()
	if a.gitBranch != "" {
		query.Set("git_branch", a.gitBranch)
	}
	if a.gitCommitSHA != "" {
		query.Set("git_commit_sha", a.gitCommitSHA)
	}
	req.URL.RawQuery = query.Encode()

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
			sourceLabel: sourceLabel,
			statusCode:  resp.StatusCode,
			status:      resp.Status,
			body:        string(body),
		}
	}

	return nil
}

type uploadError struct {
	sourceLabel string
	statusCode  int
	status      string
	body        string
}

func (e *uploadError) Error() string {
	return fmt.Sprintf("upload failed %s: %s: %s", e.sourceLabel, e.status, e.body)
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
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
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
