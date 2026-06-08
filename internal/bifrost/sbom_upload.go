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
		if opts.serviceVersion == "" {
			return nil, fmt.Errorf("service version is required")
		}
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
	api := NewAPI(t.ServerURL, t.apiKey, t.RetryAttempts, t.RetryDelay)
	stdinConsumed := false
	for _, path := range t.paths {
		if path == "-" {
			if stdinConsumed {
				return fmt.Errorf("stdin can only be used once")
			}
			content, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read SBOM from stdin: %w", err)
			}
			if err := api.UploadSBOMBytes(ctx, t.service, t.serviceVersion, "stdin", content); err != nil {
				return err
			}
			stdinConsumed = true
			fmt.Printf("Uploaded stdin to %s\n", t.ServerURL)
			continue
		}

		// Check that file exists and is a regular file before attempting upload
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fmt.Errorf("directory instead of file: %s", path)
		}

		if err := api.UploadSBOMFile(ctx, t.service, t.serviceVersion, path); err != nil {
			return err
		}
		fmt.Printf("Uploaded %s to %s\n", path, t.ServerURL)
	}
	return nil
}
