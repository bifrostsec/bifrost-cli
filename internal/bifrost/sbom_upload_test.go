// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

type unexpectedUploadAPI struct{}

func (unexpectedUploadAPI) UploadSBOMFile(context.Context, string, string, string) error {
	return errors.New("upload should not be reached")
}

func TestSBOMUploadTask_StdinCancellationCleansUpTemporaryFile(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("TMPDIR", tempDir)

	stdin, writer, err := os.Pipe()
	assert.NoError(t, err)
	defer func() {
		_ = writer.Close()
	}()
	originalStdin := os.Stdin
	os.Stdin = stdin
	defer func() {
		os.Stdin = originalStdin
		_ = stdin.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	task := sbomUploadTask{
		Options: Options{
			service:        "test-service",
			serviceVersion: "test-version",
		},
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- task.uploadStdinSBOM(ctx, unexpectedUploadAPI{})
	}()

	waitForTemporaryStdinSBOM(t, tempDir)
	cancel()

	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("stdin upload did not stop after cancellation")
	}
	matches, err := filepath.Glob(filepath.Join(tempDir, "bifrost-stdin-sbom-*.json"))
	assert.NoError(t, err)
	assert.Empty(t, matches)
}

func waitForTemporaryStdinSBOM(t *testing.T, dir string) {
	t.Helper()
	deadline := time.After(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	for {
		matches, err := filepath.Glob(filepath.Join(dir, "bifrost-stdin-sbom-*.json"))
		if err != nil {
			t.Fatalf("failed to find temporary stdin SBOM: %v", err)
		}
		if len(matches) > 0 {
			return
		}
		select {
		case <-deadline:
			t.Fatal("temporary stdin SBOM was not created")
		case <-ticker.C:
		}
	}
}
