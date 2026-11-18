// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bifrostsec/bifrost-cli/internal/flagutil"
)

// File identifies which file `config set` writes a setting to. Every setting
// is read from both files, the credentials file taking precedence, so File
// only matters for writes.
type File int

const (
	ConfigFile File = iota
	CredentialsFile
)

// Setting describes a configurable value and every place it can be read from.
type Setting struct {
	// Name is the key used in the config and credentials files, e.g. "server_url".
	Name string
	// Flag is the command-line flag, empty when the setting has no flag.
	Flag string
	// EnvVars lists environment variables in order of precedence.
	EnvVars []string
	// File is the file `config set` writes to.
	File File
	// Secret values are masked in output.
	Secret bool
}

const (
	// AccessTokenSetting and the settings below hold a short-lived credential
	// written by `bifrost auth` commands together with its expiry and the
	// portal and organization it was issued for, so it is never reused
	// elsewhere. A future interactive login flow stores its tokens here as well.
	AccessTokenSetting          = "access_token"
	AccessTokenExpiresAtSetting = "access_token_expires_at"
	AccessTokenServerURLSetting = "access_token_server_url"
	AccessTokenOrgIDSetting     = "access_token_org_id"
)

// Settings is the registry of every configurable value. Adding a setting here
// is enough for it to take part in resolution and the `config` command;
// the matching flag is registered by the cli package.
var Settings = []Setting{
	{Name: "server_url", Flag: "server-url", EnvVars: []string{"BIFROST_SERVER_URL", "SERVER_URL"}, File: ConfigFile},
	{Name: "api_key", Flag: "api-key", EnvVars: []string{"BIFROST_API_KEY"}, File: CredentialsFile, Secret: true},
	{Name: "org_id", Flag: "org-id", EnvVars: []string{"BIFROST_ORG_ID"}, File: ConfigFile},
	{Name: "retry_attempts", Flag: "retry-attempts", EnvVars: []string{"BIFROST_RETRY_ATTEMPTS"}, File: ConfigFile},
	{Name: "retry_delay", Flag: "retry-delay", EnvVars: []string{"BIFROST_RETRY_DELAY"}, File: ConfigFile},
	{Name: "http_timeout", Flag: "http-timeout", EnvVars: []string{"BIFROST_HTTP_TIMEOUT"}, File: ConfigFile},
	{Name: "git_repo_path", Flag: "git-repo-path", EnvVars: []string{"BIFROST_GIT_REPO_PATH"}, File: ConfigFile},
	{Name: AccessTokenSetting, File: CredentialsFile, Secret: true},
	{Name: AccessTokenExpiresAtSetting, File: CredentialsFile},
	{Name: AccessTokenServerURLSetting, File: CredentialsFile},
	{Name: AccessTokenOrgIDSetting, File: CredentialsFile},
}

// Names lists the registered setting names in order.
func Names() []string {
	names := make([]string, 0, len(Settings))
	for _, s := range Settings {
		names = append(names, s.Name)
	}
	return names
}

// LookupSetting finds a setting by its file key, accepting the flag spelling too.
func LookupSetting(name string) (Setting, bool) {
	normalized := strings.ReplaceAll(strings.ToLower(strings.TrimLeft(name, "-")), "-", "_")
	for _, s := range Settings {
		if s.Name == normalized {
			return s, true
		}
	}
	return Setting{}, false
}

// MustSetting returns a registered setting by name and panics otherwise; for
// names that are compile-time constants.
func MustSetting(name string) Setting {
	s, ok := LookupSetting(name)
	if !ok {
		panic(fmt.Sprintf("config: unknown setting %q", name))
	}
	return s
}

// Source tells where a resolved value came from.
type Source string

const (
	SourceCommandLine     Source = "command-line"
	SourceEnvironment     Source = "env"
	SourceConfigFile      Source = "config-file"
	SourceCredentialsFile Source = "credentials-file"
	SourceDefault         Source = "default"
	SourceNotSet          Source = "not set"
)

// FromFile reports whether the source is one of the configuration files.
func (s Source) FromFile() bool {
	return s == SourceConfigFile || s == SourceCredentialsFile
}

// Resolved is a setting together with its effective value and origin.
type Resolved struct {
	Setting
	Value  string
	Source Source
	// Location is the flag, environment variable or file path, depending on Source.
	Location string
}

// IsSet reports whether any source provided a value, including the default.
func (r Resolved) IsSet() bool {
	return r.Source != SourceNotSet
}

// DescribeSource renders the origin for messages, e.g. `environment variable BIFROST_HTTP_TIMEOUT`.
func (r Resolved) DescribeSource() string {
	switch r.Source {
	case SourceCommandLine:
		return "option " + r.Location
	case SourceEnvironment:
		return "environment variable " + r.Location
	case SourceConfigFile, SourceCredentialsFile:
		return fmt.Sprintf("%s %s", r.Source, r.Location)
	default:
		return string(r.Source)
	}
}

// Resolve determines the effective value of every setting and applies values
// from the environment and the profile to flags that were not given on the
// command line, so the variables bound to the flags end up with the resolved
// values. Every Setting with a Flag must be registered in fl.
//
// Every setting is returned even when some values cannot be parsed: those are
// reported in the returned error (one joined error per invalid value) and the
// flag keeps its default, so callers that only inspect or repair the
// configuration can carry on.
func Resolve(fl *flag.FlagSet, cfg *Config) ([]Resolved, error) {
	resolved := make([]Resolved, 0, len(Settings))
	var invalid []error
	for _, s := range Settings {
		r := resolve(fl, cfg, s)
		if s.Flag != "" && (r.Source == SourceEnvironment || r.Source.FromFile()) {
			f := fl.Lookup(s.Flag)
			previous := f.Value.String()
			if err := f.Value.Set(r.Value); err != nil {
				// The standard flag values overwrite the variable even when parsing
				// fails, so put the default back and report the problem.
				_ = f.Value.Set(previous)
				invalid = append(invalid, fmt.Errorf("invalid value %q for %s from %s: %w", r.Value, s.Name, r.DescribeSource(), err))
			}
		}
		resolved = append(resolved, r)
	}
	return resolved, errors.Join(invalid...)
}

func resolve(fl *flag.FlagSet, cfg *Config, s Setting) Resolved {
	r := Resolved{Setting: s, Source: SourceNotSet}
	if s.Flag != "" && flagutil.IsSet(fl, s.Flag) {
		r.Value = fl.Lookup(s.Flag).Value.String()
		r.Source = SourceCommandLine
		r.Location = "--" + s.Flag
		return r
	}
	for _, name := range s.EnvVars {
		if value := os.Getenv(name); value != "" {
			r.Value = value
			r.Source = SourceEnvironment
			r.Location = name
			return r
		}
	}
	if value, source, path, ok := cfg.lookup(s); ok {
		r.Value = value
		r.Source = source
		r.Location = path
		return r
	}
	if s.Flag != "" {
		if f := fl.Lookup(s.Flag); flagutil.HasDefaultValue(f) {
			r.Value = f.DefValue
			r.Source = SourceDefault
		}
	}
	return r
}

// Find returns the resolved setting with the given name, or an unset one.
func Find(resolved []Resolved, name string) Resolved {
	for _, r := range resolved {
		if r.Name == name {
			return r
		}
	}
	return Resolved{Setting: Setting{Name: name}, Source: SourceNotSet}
}
