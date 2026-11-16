// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

// Package auth obtains the bearer token the CLI authenticates to the portal
// with. Credentials come from a provider chain modeled on the AWS CLI: static
// API keys, access tokens cached by `bifrost auth` commands, and the GitHub
// Actions OIDC token exchange.
package auth

import (
	"context"
	"time"

	"github.com/bifrostsec/bifrost-cli/internal/config"
)

// Credentials is a bearer token for the portal API together with where it came from.
type Credentials struct {
	Token  string
	Source string
	// ExpiresAt is zero for credentials without a known expiry, such as API keys.
	ExpiresAt time.Time
}

// Resolver produces the credentials a command should authenticate with.
type Resolver interface {
	Resolve(ctx context.Context) (Credentials, error)
}

// StoreAccessToken caches a short-lived access token in the profile's credentials file.
func StoreAccessToken(cfg *config.Config, credentials Credentials) error {
	cfg.Set(config.MustSetting(config.AccessTokenSetting), credentials.Token)
	expiresAt := config.MustSetting(config.AccessTokenExpiresAtSetting)
	if credentials.ExpiresAt.IsZero() {
		cfg.Unset(expiresAt)
	} else {
		cfg.Set(expiresAt, credentials.ExpiresAt.UTC().Format(time.RFC3339))
	}
	return cfg.Save()
}
