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
	Profile         string
	ConfigPath      string
	CredentialsPath string

	config           *ini.File
	credentials      *ini.File
	configDirty      bool
	credentialsDirty bool
}

// Load reads the config and credentials files for a profile. Missing files are not an error.
func Load(profile string) (*Config, error) {
	if profile == "" {
		profile = DefaultProfile
	}
	configPath, err := configFilePath()
	if err != nil {
		return nil, err
	}
	credentialsPath, err := credentialsFilePath()
	if err != nil {
		return nil, err
	}
	config, err := ini.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	credentials, err := ini.Load(credentialsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials file: %w", err)
	}
	return &Config{
		Profile:         profile,
		ConfigPath:      configPath,
		CredentialsPath: credentialsPath,
		config:          config,
		credentials:     credentials,
	}, nil
}

func configFilePath() (string, error) {
	if path := os.Getenv(ConfigFileEnvironmentVariable); path != "" {
		return path, nil
	}
	return defaultPath(ConfigFileName)
}

func credentialsFilePath() (string, error) {
	if path := os.Getenv(CredentialsFileEnvironmentVariable); path != "" {
		return path, nil
	}
	return defaultPath(CredentialsFileName)
}

func defaultPath(fileName string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to locate home directory for %s: %w", fileName, err)
	}
	return filepath.Join(home, DirName, fileName), nil
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

// lookup finds the stored value of a setting for the profile, checking the
// credentials file before the config file.
func (c *Config) lookup(s Setting) (value string, source Source, path string, ok bool) {
	if s.File == CredentialsFile {
		if value, ok := c.credentials.Get(c.credentialsSection(), s.Name); ok {
			return value, SourceCredentialsFile, c.CredentialsPath, true
		}
	}
	// Every setting may be stored in the config file, credential settings as a fallback.
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

// Save writes back every file that was modified.
func (c *Config) Save() error {
	if c.configDirty {
		if err := c.config.Save(c.ConfigPath); err != nil {
			return fmt.Errorf("failed to write config file: %w", err)
		}
		c.configDirty = false
	}
	if c.credentialsDirty {
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
