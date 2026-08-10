// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package bifrost

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type unexpectedUploadAPI struct{}

func (unexpectedUploadAPI) UploadSBOMFile(context.Context, string, string, string) error {
	return errors.New("upload should not be reached")
}

func newBlockingStdinFIFO(t *testing.T) (stdin *os.File, writer *os.File) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdin.fifo")
	require.NoError(t, syscall.Mkfifo(path, 0o600))

	type openResult struct {
		file *os.File
		err  error
	}
	writerResult := make(chan openResult, 1)
	go func() {
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		writerResult <- openResult{file: file, err: err}
	}()

	stdin, err := os.Open(path)
	require.NoError(t, err)
	result := <-writerResult
	require.NoError(t, result.err)
	return stdin, result.file
}

func TestSBOMUploadTask_StdinCancellationCleansUpTemporaryFile(t *testing.T) {
	// This test replaces os.Stdin and must remain serial.
	tempDir := t.TempDir()
	t.Setenv("TMPDIR", tempDir)

	stdin, writer := newBlockingStdinFIFO(t)
	defer func() { _ = writer.Close() }()

	originalStdin := os.Stdin
	os.Stdin = stdin
	defer func() {
		os.Stdin = originalStdin
		_ = stdin.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	task := sbomUploadTask{Options: Options{service: "test-service", serviceVersion: "test-version"}}
	errCh := make(chan error, 1)
	go func() {
		errCh <- task.uploadStdinSBOM(ctx, unexpectedUploadAPI{})
	}()

	waitForTemporaryStdinSBOM(t, tempDir)
	_, err := writer.Write([]byte("{"))
	require.NoError(t, err)
	waitForTemporaryStdinSBOMContent(t, tempDir)
	select {
	case err := <-errCh:
		t.Fatalf("stdin upload finished before cancellation: %v", err)
	default:
	}
	cancel()

	select {
	case err := <-errCh:
		assert.ErrorIs(t, err, context.Canceled)
	case <-time.After(time.Second):
		t.Fatal("stdin upload did not stop after cancellation")
	}

	matches, err := filepath.Glob(filepath.Join(tempDir, "bifrost-stdin-sbom-*.json"))
	assert.NoError(t, err)
	assert.Empty(t, matches, "temporary stdin SBOM was not removed")
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

func waitForTemporaryStdinSBOMContent(t *testing.T, dir string) {
	t.Helper()
	deadline := time.After(time.Second)
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()

	for {
		matches, err := filepath.Glob(filepath.Join(dir, "bifrost-stdin-sbom-*.json"))
		if err != nil {
			t.Fatalf("failed to find temporary stdin SBOM: %v", err)
		}
		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("failed to stat temporary stdin SBOM: %v", err)
			}
			if info.Size() > 0 {
				return
			}
		}
		select {
		case <-deadline:
			t.Fatal("stdin data was not copied to the temporary file")
		case <-ticker.C:
		}
	}
}
