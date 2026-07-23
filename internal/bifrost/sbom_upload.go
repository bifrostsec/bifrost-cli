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
	paths      []string
	cliVersion string
}

const missingGitMetadataHint = "Hint: no Git metadata was provided. To automatically attach Git metadata, run from a Git repository with --git-auto-detect or set the BIFROST_GIT_AUTO_DETECT=true environment variable. Use --git-repo-path when the repository is elsewhere.\n"
const gitMetadataDetectionMessage = "Git metadata detection from %s:\n  git_branch=%q\n  git_commit_sha=%q\n  git_origin=%q\n"

func NewSBOMUploadTask(opts Options, args []string, cliVersion string) (Task, error) {
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
	}
	if opts.serviceVersion == "" && opts.image == "" {
		return nil, fmt.Errorf("either service version or image is required")
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("at least one SBOM file path is required")
	}
	if opts.gitAutoDetect {
		gitMetadataDetection := discoverGitMetadata(opts.gitRepoPath)
		printGitMetadataDetection(opts.gitRepoPath, gitMetadataDetection)
		opts = applyGitMetadataDetection(opts, gitMetadataDetection.metadata)
	}

	return &sbomUploadTask{
		Options:    opts,
		paths:      args,
		cliVersion: cliVersion,
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
		HTTPTimeout:   t.httpTimeout,
		GitBranch:     t.gitBranch,
		GitCommitSHA:  t.gitCommitSHA,
		GitOrigin:     t.gitOrigin,
		Image:         t.image,
		CliVersion:    t.cliVersion,
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
	t.printGitMetadataHint()
	return nil
}

func printGitMetadataDetection(gitRepoPath string, discovery gitMetadataDiscovery) {
	_, _ = fmt.Fprintf(
		os.Stderr,
		gitMetadataDetectionMessage,
		gitRepoPath,
		discovery.metadata.branch,
		discovery.metadata.commitSHA,
		discovery.metadata.origin,
	)
	for _, err := range discovery.errors {
		_, _ = fmt.Fprintf(os.Stderr, "  error=%q\n", err)
	}
}

func applyGitMetadataDetection(opts Options, metadata gitMetadata) Options {
	if opts.gitBranch == "" {
		opts.gitBranch = metadata.branch
	}
	if opts.gitCommitSHA == "" {
		opts.gitCommitSHA = metadata.commitSHA
	}
	if opts.gitOrigin == "" {
		opts.gitOrigin = metadata.origin
	}
	return opts
}

func (t sbomUploadTask) printGitMetadataHint() {
	if t.gitBranch != "" || t.gitCommitSHA != "" || t.gitOrigin != "" {
		return
	}
	_, _ = fmt.Fprint(os.Stderr, missingGitMetadataHint)
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

	if err := cancelableCopyStdin(ctx, tmpFile, os.Stdin); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to read SBOM from stdin: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to finalize stdin SBOM temp file: %w", err)
	}

	return api.UploadSBOMFile(ctx, t.service, t.serviceVersion, tmpPath)
}

func cancelableCopyStdin(ctx context.Context, destination io.Writer, stdin *os.File) error {
	copyDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(destination, stdin)
		copyDone <- err
	}()

	select {
	case err := <-copyDone:
		return err
	case <-ctx.Done():
		_ = stdin.Close()
		<-copyDone
		return ctx.Err()
	}
}
