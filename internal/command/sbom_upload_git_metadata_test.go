// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package command

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bifrostsec/bifrost-cli/internal/git"
)

func TestApplyGitMetadata_CommitTimestamp(t *testing.T) {
	detected := git.Metadata{CommitSHA: "detected-sha", CommitTimestamp: "2026-01-31T12:30:00+01:00"}

	tests := []struct {
		name              string
		opts              SBOMUploadOptions
		expectedTimestamp string
	}{
		{
			name:              "applies detected timestamp when commit SHA is detected",
			opts:              SBOMUploadOptions{},
			expectedTimestamp: detected.CommitTimestamp,
		},
		{
			name:              "applies detected timestamp when explicit commit SHA matches",
			opts:              SBOMUploadOptions{GitCommitSHA: "detected-sha"},
			expectedTimestamp: detected.CommitTimestamp,
		},
		{
			name:              "omits detected timestamp when explicit commit SHA differs",
			opts:              SBOMUploadOptions{GitCommitSHA: "other-sha"},
			expectedTimestamp: "",
		},
		{
			name:              "keeps explicit timestamp",
			opts:              SBOMUploadOptions{GitCommitTimestamp: "2026-02-01T08:00:00Z"},
			expectedTimestamp: "2026-02-01T08:00:00Z",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := applyGitMetadata(tt.opts, detected)
			assert.Equal(t, tt.expectedTimestamp, opts.GitCommitTimestamp)
		})
	}
}
