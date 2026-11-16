// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package command

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bifrostsec/bifrost-cli/internal/auth"
	"github.com/bifrostsec/bifrost-cli/internal/testutil"
)

// expiringResolver issues a new numbered token on every call, each valid for a minute.
type expiringResolver struct {
	now   func() time.Time
	calls int
}

func (r *expiringResolver) Resolve(context.Context) (auth.Credentials, error) {
	r.calls++
	return auth.Credentials{Token: fmt.Sprintf("token-%d", r.calls), ExpiresAt: r.now().Add(time.Minute)}, nil
}

func TestSBOMUpload_RefreshesCredentialsThatExpireDuringABatch(t *testing.T) {
	var authorizations []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorizations = append(authorizations, r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	clock := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	now := func() time.Time { return clock }
	resolver := &expiringResolver{now: now}
	task := sbomUpload{
		opts:        SBOMUploadOptions{ServerURL: server.URL, Service: "svc", ServiceVersion: "1"},
		credentials: resolver,
		paths:       []string{testutil.WriteSBOM(t), testutil.WriteSBOM(t), testutil.WriteSBOM(t)},
		now: func() time.Time {
			defer func() { clock = clock.Add(45 * time.Second) }() // each upload takes a while
			return clock
		},
	}

	require.NoError(t, task.Run(context.Background()))
	assert.Equal(t, []string{"Bearer token-1", "Bearer token-1", "Bearer token-2"}, authorizations,
		"the token is reused while valid and re-resolved once it is about to expire")
	assert.Equal(t, 2, resolver.calls)
}

func TestSBOMUpload_ResolvesCredentialsLazily(t *testing.T) {
	resolver := &expiringResolver{now: time.Now}
	task := sbomUpload{opts: SBOMUploadOptions{Service: "svc", ServiceVersion: "1"}, credentials: resolver, paths: []string{"-"}, now: time.Now}

	tokens := &credentialCache{resolver: resolver, now: time.Now}
	assert.Equal(t, 0, resolver.calls, "nothing is resolved before an upload needs a token")
	token, err := tokens.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "token-1", token)
	token, err = tokens.Token(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "token-1", token, "a valid token is cached")
	assert.Equal(t, 1, resolver.calls)
	_ = task
}
