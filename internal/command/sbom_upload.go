// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package command

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/bifrostsec/bifrost-cli/internal/auth"
	"github.com/bifrostsec/bifrost-cli/internal/git"
	"github.com/bifrostsec/bifrost-cli/internal/portal"
)

// SBOMUploadOptions are the resolved inputs of `bifrost sbom upload`.
type SBOMUploadOptions struct {
	ServerURL      string
	Service        string
	ServiceVersion string
	Image          string
	RetryAttempts  int
	RetryDelay     time.Duration
	HTTPTimeout    time.Duration
	GitBranch      string
	GitCommitSHA   string
	GitOrigin      string
	// GitRepoPath enables Git metadata detection for fields left empty.
	GitRepoPath string
	CLIVersion  string
}

type sbomUpload struct {
	opts        SBOMUploadOptions
	credentials auth.Resolver
	paths       []string
}

const gitMetadataDetectionMessage = "Git metadata detection from %s:\n  git_branch=%q\n  git_commit_sha=%q\n  git_origin=%q\n"

// NewSBOMUpload validates the options and prepares the upload of paths, where
// "-" stands for standard input.
func NewSBOMUpload(opts SBOMUploadOptions, credentials auth.Resolver, paths []string) (Task, error) {
	if opts.Service == "" {
		return nil, fmt.Errorf("service name is required")
	}
	if opts.ServiceVersion == "" && opts.Image == "" {
		return nil, fmt.Errorf("either service version or image is required")
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("at least one SBOM file path is required")
	}
	if opts.GitRepoPath != "" {
		discovery := git.Discover(opts.GitRepoPath)
		printGitMetadataDetection(opts.GitRepoPath, discovery)
		opts = applyGitMetadata(opts, discovery.Metadata)
	}

	return &sbomUpload{
		opts:        opts,
		credentials: credentials,
		paths:       paths,
	}, nil
}

func (t sbomUpload) Run(ctx context.Context) error {
	if len(t.paths) == 0 {
		return fmt.Errorf("no SBOM file paths provided")
	}
	credentials, err := t.credentials.Resolve(ctx)
	if err != nil {
		return err
	}
	client := portal.NewClient(portal.ClientConfig{
		ServerURL:     t.opts.ServerURL,
		Token:         credentials.Token,
		RetryAttempts: t.opts.RetryAttempts,
		RetryDelay:    t.opts.RetryDelay,
		HTTPTimeout:   t.opts.HTTPTimeout,
		GitBranch:     t.opts.GitBranch,
		GitCommitSHA:  t.opts.GitCommitSHA,
		GitOrigin:     t.opts.GitOrigin,
		Image:         t.opts.Image,
		CliVersion:    t.opts.CLIVersion,
	})
	stdinConsumed := false
	for _, path := range t.paths {
		if path == "-" {
			if stdinConsumed {
				return fmt.Errorf("stdin can only be used once")
			}
			if err := t.uploadStdinSBOM(ctx, client); err != nil {
				return err
			}
			stdinConsumed = true
			fmt.Printf("Uploaded stdin to %s\n", t.opts.ServerURL)
			continue
		}

		if err := client.UploadSBOMFile(ctx, t.opts.Service, t.opts.ServiceVersion, path); err != nil {
			return err
		}
		fmt.Printf("Uploaded %s to %s\n", path, t.opts.ServerURL)
	}
	return nil
}

func printGitMetadataDetection(gitRepoPath string, discovery git.Discovery) {
	_, _ = fmt.Fprintf(
		os.Stderr,
		gitMetadataDetectionMessage,
		gitRepoPath,
		discovery.Metadata.Branch,
		discovery.Metadata.CommitSHA,
		discovery.Metadata.Origin,
	)
	for _, err := range discovery.Errors {
		_, _ = fmt.Fprintf(os.Stderr, "  error=%q\n", err)
	}
}

func applyGitMetadata(opts SBOMUploadOptions, metadata git.Metadata) SBOMUploadOptions {
	if opts.GitBranch == "" {
		opts.GitBranch = metadata.Branch
	}
	if opts.GitCommitSHA == "" {
		opts.GitCommitSHA = metadata.CommitSHA
	}
	if opts.GitOrigin == "" {
		opts.GitOrigin = metadata.Origin
	}
	return opts
}

func (t sbomUpload) uploadStdinSBOM(ctx context.Context, client portal.Client) error {
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

	if err := copyStdinWithContext(ctx, tmpFile, os.Stdin); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to read SBOM from stdin: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to finalize stdin SBOM temp file: %w", err)
	}

	return client.UploadSBOMFile(ctx, t.opts.Service, t.opts.ServiceVersion, tmpPath)
}

func copyStdinWithContext(ctx context.Context, destination io.Writer, stdin *os.File) error {
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(destination, stdin)
		done <- err
	}()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
