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
	// ServerURL and OrgID record the portal and organization an access token
	// was issued for, so it is only ever presented there. Both are empty for
	// credentials without a known scope, such as API keys.
	ServerURL string
	OrgID     string
}

// ExpirySkew is how long before its real expiry a credential stops being used,
// so a request does not start with a token about to lapse.
const ExpirySkew = 30 * time.Second

// Valid reports whether the credentials hold a token that is not expiring at now.
func (c Credentials) Valid(now time.Time) bool {
	if c.Token == "" {
		return false
	}
	return c.ExpiresAt.IsZero() || now.Add(ExpirySkew).Before(c.ExpiresAt)
}

// Resolver produces the credentials a command should authenticate with.
type Resolver interface {
	Resolve(ctx context.Context) (Credentials, error)
}

// StoreAccessToken caches a short-lived access token in the profile's
// credentials file together with its expiry and scope.
func StoreAccessToken(cfg *config.Config, credentials Credentials) error {
	cfg.Set(config.MustSetting(config.AccessTokenSetting), credentials.Token)
	expiresAt := ""
	if !credentials.ExpiresAt.IsZero() {
		expiresAt = credentials.ExpiresAt.UTC().Format(time.RFC3339)
	}
	for name, value := range map[string]string{
		config.AccessTokenExpiresAtSetting: expiresAt,
		config.AccessTokenServerURLSetting: credentials.ServerURL,
		config.AccessTokenOrgIDSetting:     credentials.OrgID,
	} {
		if value == "" {
			cfg.Unset(config.MustSetting(name))
		} else {
			cfg.Set(config.MustSetting(name), value)
		}
	}
	return cfg.Save()
}
