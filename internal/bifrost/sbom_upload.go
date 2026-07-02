// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"context"
	"fmt"
	"io"
	"os"
)

type sbomUploadTask struct {
	Options
	paths []string
}

func NewSBOMUploadTask(opts Options, args []string) (Task, error) {
	if opts.service == "" {
		opts.service = os.Getenv("SERVICE")
		if opts.service == "" {
			return nil, fmt.Errorf("service name is required")
		}
	}
	if opts.serviceVersion == "" {
		opts.serviceVersion = os.Getenv("SERVICE_VERSION")
	}
	if opts.image == "" {
		if image := os.Getenv("IMAGE"); image != "" {
			opts.image = image
		}
		if image := os.Getenv("BIFROST_IMAGE"); image != "" {
			opts.image = image
		}
	}
	if opts.serviceVersion == "" && opts.image == "" {
		return nil, fmt.Errorf("either service version or image is required")
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("at least one SBOM file path is required")
	}
	return &sbomUploadTask{
		Options: opts,
		paths:   args,
	}, nil
}

func (t sbomUploadTask) Run(ctx context.Context) error {
	if len(t.paths) == 0 {
		return fmt.Errorf("no SBOM file paths provided")
	}
	api := NewAPI(APIConfig{
		ServerURL:     t.ServerURL,
		Token:         t.apiKey,
		RetryAttempts: t.retryAttempts,
		RetryDelay:    t.retryDelay,
		GitBranch:     t.gitBranch,
		GitCommitSHA:  t.gitCommitSHA,
		GitOrigin:     t.gitOrigin,
		Image:         t.image,
	})
	stdinConsumed := false
	for _, path := range t.paths {
		if path == "-" {
			if stdinConsumed {
				return fmt.Errorf("stdin can only be used once")
			}
			if err := t.uploadStdinSBOM(ctx, api); err != nil {
				return err
			}
			stdinConsumed = true
			fmt.Printf("Uploaded stdin to %s\n", t.ServerURL)
			continue
		}

		if err := api.UploadSBOMFile(ctx, t.service, t.serviceVersion, path); err != nil {
			return err
		}
		fmt.Printf("Uploaded %s to %s\n", path, t.ServerURL)
	}
	return nil
}

func (t sbomUploadTask) uploadStdinSBOM(ctx context.Context, api API) error {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat stdin: %w", err)
	}
	if fi.Mode()&os.ModeCharDevice != 0 {
		return fmt.Errorf("no SBOM was piped to stdin; pipe or redirect an SBOM, e.g. `cat sbom.json | bifrost ... sbom upload -`")
	}

	tmpFile, err := os.CreateTemp("", "bifrost-stdin-sbom-*.json")
	if err != nil {
		return fmt.Errorf("failed to create temp file for stdin SBOM: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		_ = os.Remove(tmpPath)
	}()

	if _, err := io.Copy(tmpFile, os.Stdin); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to read SBOM from stdin: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to finalize stdin SBOM temp file: %w", err)
	}

	return api.UploadSBOMFile(ctx, t.service, t.serviceVersion, tmpPath)
}
