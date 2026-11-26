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
	ServerURL          string
	Service            string
	ServiceVersion     string
	Image              string
	RetryAttempts      int
	RetryDelay         time.Duration
	HTTPTimeout        time.Duration
	GitBranch          string
	GitCommitSHA       string
	GitCommitTimestamp string
	GitOrigin          string
	// GitRepoPath enables Git metadata detection for fields left empty.
	GitRepoPath string
	CLIVersion  string
}

type sbomUpload struct {
	opts        SBOMUploadOptions
	credentials auth.Resolver
	paths       []string
	now         func() time.Time
}

// credentialCache hands out a token for each upload and asks the resolver
// again once the current one is about to expire. Credentials are therefore
// first obtained after standard input has been staged and stay fresh across a
// long batch, which matters for short-lived exchanged tokens.
type credentialCache struct {
	resolver auth.Resolver
	now      func() time.Time
	current  auth.Credentials
}

func (c *credentialCache) Token(ctx context.Context) (string, error) {
	if !c.current.Valid(c.now()) {
		credentials, err := c.resolver.Resolve(ctx)
		if err != nil {
			return "", err
		}
		c.current = credentials
	}
	return c.current.Token, nil
}

const gitMetadataDetectionMessage = "Git metadata detection from %s:\n  git_branch=%q\n  git_commit_sha=%q\n  git_commit_timestamp=%q\n  git_origin=%q\n"

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
		now:         time.Now,
	}, nil
}

func (t sbomUpload) Run(ctx context.Context) error {
	if len(t.paths) == 0 {
		return fmt.Errorf("no SBOM file paths provided")
	}
	tokens := &credentialCache{resolver: t.credentials, now: t.now}
	upload := func(ctx context.Context, path string) error {
		token, err := tokens.Token(ctx)
		if err != nil {
			return err
		}
		return t.newClient(token).UploadSBOMFile(ctx, t.opts.Service, t.opts.ServiceVersion, path)
	}

	stdinConsumed := false
	for _, path := range t.paths {
		if path == "-" {
			if stdinConsumed {
				return fmt.Errorf("stdin can only be used once")
			}
			if err := t.uploadStdinSBOM(ctx, upload); err != nil {
				return err
			}
			stdinConsumed = true
			fmt.Printf("Uploaded stdin to %s\n", t.opts.ServerURL)
			continue
		}

		if err := upload(ctx, path); err != nil {
			return err
		}
		fmt.Printf("Uploaded %s to %s\n", path, t.opts.ServerURL)
	}
	return nil
}

func (t sbomUpload) newClient(token string) portal.Client {
	return portal.NewClient(portal.ClientConfig{
		ServerURL:          t.opts.ServerURL,
		Token:              token,
		RetryAttempts:      t.opts.RetryAttempts,
		RetryDelay:         t.opts.RetryDelay,
		HTTPTimeout:        t.opts.HTTPTimeout,
		GitBranch:          t.opts.GitBranch,
		GitCommitSHA:       t.opts.GitCommitSHA,
		GitCommitTimestamp: t.opts.GitCommitTimestamp,
		GitOrigin:          t.opts.GitOrigin,
		Image:              t.opts.Image,
		CliVersion:         t.opts.CLIVersion,
	})
}

func printGitMetadataDetection(gitRepoPath string, discovery git.Discovery) {
	_, _ = fmt.Fprintf(
		os.Stderr,
		gitMetadataDetectionMessage,
		gitRepoPath,
		discovery.Metadata.Branch,
		discovery.Metadata.CommitSHA,
		discovery.Metadata.CommitTimestamp,
		discovery.Metadata.Origin,
	)
	for _, err := range discovery.Errors {
		_, _ = fmt.Fprintf(os.Stderr, "  error=%q\n", err)
	}
}

func applyGitMetadata(opts SBOMUploadOptions, metadata git.Metadata) SBOMUploadOptions {
	// The detected timestamp belongs to the detected commit, so it is not applied to an explicitly provided other commit.
	if opts.GitCommitTimestamp == "" && (opts.GitCommitSHA == "" || opts.GitCommitSHA == metadata.CommitSHA) {
		opts.GitCommitTimestamp = metadata.CommitTimestamp
	}
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

// uploadStdinSBOM stages standard input in a temporary file and hands it to
// upload, so credentials are only needed once the whole SBOM has arrived.
func (t sbomUpload) uploadStdinSBOM(ctx context.Context, upload func(ctx context.Context, path string) error) error {
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

	return upload(ctx, tmpPath)
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
