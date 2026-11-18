// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

// Package config reads and writes the CLI configuration files and resolves
// settings from every source they can come from.
//
// The files follow the AWS CLI layout: a config file for general settings and
// a separate credentials file for secrets, both split into profiles. Settings
// are resolved in order of precedence: command-line flags, environment
// variables, the selected profile in the credentials and config files, then
// built-in defaults.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/bifrostsec/bifrost-cli/internal/ini"
)

const (
	DirName             = ".bifrost"
	ConfigFileName      = "config"
	CredentialsFileName = "credentials"

	DefaultProfile = "default"

	ProfileEnvironmentVariable         = "BIFROST_PROFILE"
	ConfigFileEnvironmentVariable      = "BIFROST_CONFIG_FILE"
	CredentialsFileEnvironmentVariable = "BIFROST_SHARED_CREDENTIALS_FILE"

	// profileSectionPrefix is used for non-default profiles in the config file ("[profile name]"),
	// while the credentials file uses the bare profile name ("[name]"), as the AWS CLI does.
	profileSectionPrefix = "profile "
)

// Config holds the parsed config and credentials files together with the selected profile.
type Config struct {
	Profile string
	// ConfigPath and CredentialsPath are empty when the default location is
	// unknown because there is no home directory; the file is then treated
	// as absent and cannot be written.
	ConfigPath      string
	CredentialsPath string

	// unavailable explains why a default file location is unknown.
	unavailable      error
	config           *ini.File
	credentials      *ini.File
	configDirty      bool
	credentialsDirty bool
}

// Load reads the config and credentials files for a profile. Missing files
// are not an error, and neither is a missing home directory: a container or
// function that passes every setting through flags or the environment must
// still work, so the files are then simply treated as absent.
func Load(profile string) (*Config, error) {
	if profile == "" {
		profile = DefaultProfile
	}
	c := &Config{Profile: profile}
	var err error
	if c.ConfigPath, err = filePath(ConfigFileEnvironmentVariable, ConfigFileName); err != nil {
		c.unavailable = err
	}
	if c.CredentialsPath, err = filePath(CredentialsFileEnvironmentVariable, CredentialsFileName); err != nil {
		c.unavailable = err
	}
	if c.config, err = loadFile(c.ConfigPath); err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	if c.credentials, err = loadFile(c.CredentialsPath); err != nil {
		return nil, fmt.Errorf("failed to read credentials file: %w", err)
	}
	return c, nil
}

// filePath returns the override from the environment, or the default under
// the home directory. The error says why no default could be determined.
func filePath(environmentVariable, fileName string) (string, error) {
	if path := os.Getenv(environmentVariable); path != "" {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("no home directory for the default %s file location (%v)", fileName, err)
	}
	return filepath.Join(home, DirName, fileName), nil
}

func loadFile(path string) (*ini.File, error) {
	if path == "" {
		return &ini.File{}, nil
	}
	return ini.Load(path)
}

// ProfileExists reports whether the selected profile has a section in either file.
func (c *Config) ProfileExists() bool {
	return c.config.HasSection(c.configSection()) || c.credentials.HasSection(c.credentialsSection())
}

// Profiles lists every profile name found in the config and credentials files.
func (c *Config) Profiles() []string {
	var profiles []string
	add := func(name string) {
		if !slices.Contains(profiles, name) {
			profiles = append(profiles, name)
		}
	}
	for _, section := range c.config.Sections() {
		add(strings.TrimPrefix(section, profileSectionPrefix))
	}
	for _, section := range c.credentials.Sections() {
		add(section)
	}
	return profiles
}

// configSection returns the section holding the profile in the config file.
// Non-default profiles are written as "[profile name]", but a bare "[name]"
// section is accepted when it already exists.
func (c *Config) configSection() string {
	if c.Profile == DefaultProfile {
		return DefaultProfile
	}
	prefixed := profileSectionPrefix + c.Profile
	if !c.config.HasSection(prefixed) && c.config.HasSection(c.Profile) {
		return c.Profile
	}
	return prefixed
}

func (c *Config) credentialsSection() string {
	return c.Profile
}

// lookup finds the stored value of a setting for the profile. Like the AWS
// CLI, both files may hold any setting and the credentials file wins, so a
// profile that lives entirely in the credentials file works as expected.
func (c *Config) lookup(s Setting) (value string, source Source, path string, ok bool) {
	if value, ok := c.credentials.Get(c.credentialsSection(), s.Name); ok {
		return value, SourceCredentialsFile, c.CredentialsPath, true
	}
	if value, ok := c.config.Get(c.configSection(), s.Name); ok {
		return value, SourceConfigFile, c.ConfigPath, true
	}
	return "", SourceNotSet, "", false
}

// Get returns the stored value of a setting for the profile.
func (c *Config) Get(s Setting) (string, bool) {
	value, _, _, ok := c.lookup(s)
	return value, ok
}

// Set stores a setting for the profile in the file the setting belongs to.
func (c *Config) Set(s Setting, value string) {
	switch s.File {
	case CredentialsFile:
		c.credentials.Set(c.credentialsSection(), s.Name, value)
		c.credentialsDirty = true
	case ConfigFile:
		c.config.Set(c.configSection(), s.Name, value)
		c.configDirty = true
	}
}

// Unset removes a setting for the profile from both files and reports whether it was present.
func (c *Config) Unset(s Setting) bool {
	removed := false
	if c.credentials.Delete(c.credentialsSection(), s.Name) {
		c.credentialsDirty = true
		removed = true
	}
	if c.config.Delete(c.configSection(), s.Name) {
		c.configDirty = true
		removed = true
	}
	return removed
}

// Save writes back every file that was modified. It fails when a modified
// file has no location, pointing at the environment variable that provides one.
func (c *Config) Save() error {
	if c.configDirty {
		if c.ConfigPath == "" {
			return fmt.Errorf("cannot write config file: %w; set %s to choose a location", c.unavailable, ConfigFileEnvironmentVariable)
		}
		if err := c.config.Save(c.ConfigPath); err != nil {
			return fmt.Errorf("failed to write config file: %w", err)
		}
		c.configDirty = false
	}
	if c.credentialsDirty {
		if c.CredentialsPath == "" {
			return fmt.Errorf("cannot write credentials file: %w; set %s to choose a location", c.unavailable, CredentialsFileEnvironmentVariable)
		}
		if err := c.credentials.Save(c.CredentialsPath); err != nil {
			return fmt.Errorf("failed to write credentials file: %w", err)
		}
		c.credentialsDirty = false
	}
	return nil
}

// MaskSecret hides all but the last four characters, like the AWS CLI does.
func MaskSecret(value string) string {
	const visible = 4
	if len(value) <= visible {
		return "****"
	}
	return strings.Repeat("*", 16) + value[len(value)-visible:]
}

// DisplayPath abbreviates the home directory to "~" for output.
func DisplayPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if rel, err := filepath.Rel(home, path); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.Join("~", rel)
	}
	return path
}
