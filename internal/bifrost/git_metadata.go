// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"fmt"

	git "github.com/go-git/go-git/v5"
)

type gitMetadata struct {
	branch    string
	commitSHA string
	origin    string
}

type gitMetadataDiscovery struct {
	metadata gitMetadata
	errors   []error
}

func discoverGitMetadata(dir string) gitMetadataDiscovery {
	repo, err := git.PlainOpenWithOptions(dir, &git.PlainOpenOptions{
		DetectDotGit:          true,
		EnableDotGitCommonDir: true,
	})
	if err != nil {
		return gitMetadataDiscovery{
			errors: []error{fmt.Errorf("open git repository: %w", err)},
		}
	}

	metadata := gitMetadata{}
	var errors []error
	head, err := repo.Head()
	if err == nil {
		if head.Name().IsBranch() {
			metadata.branch = head.Name().Short()
		}
		metadata.commitSHA = head.Hash().String()
	} else {
		errors = append(errors, fmt.Errorf("read HEAD: %w", err))
	}

	cfg, err := repo.Config()
	if err == nil {
		if origin, ok := cfg.Remotes["origin"]; ok && len(origin.URLs) > 0 {
			metadata.origin = origin.URLs[0]
		}
	} else {
		errors = append(errors, fmt.Errorf("read git config: %w", err))
	}
	return gitMetadataDiscovery{
		metadata: metadata,
		errors:   errors,
	}
}

func gitMetadataRepoPath(path string) string {
	if path == "" {
		return "."
	}
	return path
}
