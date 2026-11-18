// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package command

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/bifrostsec/bifrost-cli/internal/config"
)

// ErrConfigValueNotSet is returned by `config get` when the value is absent;
// the CLI exits with status 1 and no message, like `aws configure get`.
var ErrConfigValueNotSet = errors.New("configuration value is not set")

// configCommand implements `bifrost config`, modeled on `aws configure`.
type configCommand struct {
	cfg      *config.Config
	resolved []config.Resolved
	profile  config.Resolved
	args     []string
	input    io.Reader
	output   io.Writer
}

// NewConfig prepares a `config` subcommand given by args; no args means the
// interactive prompt.
func NewConfig(cfg *config.Config, resolved []config.Resolved, profile config.Resolved, args []string) Task {
	return &configCommand{
		cfg:      cfg,
		resolved: resolved,
		profile:  profile,
		args:     args,
		input:    os.Stdin,
		output:   os.Stdout,
	}
}

func (t *configCommand) Run(context.Context) error {
	if len(t.args) == 0 {
		return t.interactive()
	}
	switch subcommand, rest := t.args[0], t.args[1:]; subcommand {
	case "list":
		if len(rest) != 0 {
			return fmt.Errorf("config list takes no arguments")
		}
		return t.list()
	case "list-profiles":
		if len(rest) != 0 {
			return fmt.Errorf("config list-profiles takes no arguments")
		}
		for _, profile := range t.cfg.Profiles() {
			_, _ = fmt.Fprintln(t.output, profile)
		}
		return nil
	case "get":
		if len(rest) != 1 {
			return fmt.Errorf("usage: config get <name>")
		}
		return t.get(rest[0])
	case "set":
		if len(rest) != 2 {
			return fmt.Errorf("usage: config set <name> <value>")
		}
		return t.set(rest[0], rest[1])
	case "unset":
		if len(rest) != 1 {
			return fmt.Errorf("usage: config unset <name>")
		}
		return t.unset(rest[0])
	default:
		return fmt.Errorf("unknown config subcommand %q (expected list, list-profiles, get, set or unset)", subcommand)
	}
}

// interactive prompts for the most common settings and stores them in the profile.
// Pressing enter keeps the current value.
func (t *configCommand) interactive() error {
	prompts := []struct {
		name  string
		label string
	}{
		{name: "api_key", label: "Bifrost API key"},
		{name: "server_url", label: "Server URL"},
	}
	reader := bufio.NewReader(t.input)
	for _, prompt := range prompts {
		s := config.MustSetting(prompt.name)
		current := "None"
		if value, ok := t.cfg.Get(s); ok {
			current = value
			if s.Secret {
				current = config.MaskSecret(value)
			}
		}
		_, _ = fmt.Fprintf(t.output, "%s [%s]: ", prompt.label, current)
		line, err := reader.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("failed to read input: %w", err)
		}
		if value := strings.TrimSpace(line); value != "" {
			t.cfg.Set(s, value)
		}
		if errors.Is(err, io.EOF) {
			_, _ = fmt.Fprintln(t.output)
			break
		}
	}
	return t.cfg.Save()
}

// list prints every setting with its effective value and origin, like `aws configure list`.
func (t *configCommand) list() error {
	w := tabwriter.NewWriter(t.output, 0, 0, 4, ' ', 0)
	_, _ = fmt.Fprintln(w, "Name\tValue\tType\tLocation")
	_, _ = fmt.Fprintln(w, "----\t-----\t----\t--------")
	printRow := func(r config.Resolved) {
		value, source, location := "<not set>", string(r.Source), r.Location
		if r.IsSet() {
			value = r.Value
			if r.Secret {
				value = config.MaskSecret(value)
			}
		}
		if r.Source.FromFile() {
			location = config.DisplayPath(location)
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Name, value, source, location)
	}
	printRow(t.profile)
	for _, r := range t.resolved {
		printRow(r)
	}
	return w.Flush()
}

// get prints the value stored in the profile. Environment variables and flags are
// deliberately ignored so the command reports what is on disk.
func (t *configCommand) get(name string) error {
	s, err := requireSetting(name)
	if err != nil {
		return err
	}
	value, ok := t.cfg.Get(s)
	if !ok {
		return ErrConfigValueNotSet
	}
	_, _ = fmt.Fprintln(t.output, value)
	return nil
}

func (t *configCommand) set(name, value string) error {
	s, err := requireSetting(name)
	if err != nil {
		return err
	}
	t.cfg.Set(s, value)
	return t.cfg.Save()
}

func (t *configCommand) unset(name string) error {
	s, err := requireSetting(name)
	if err != nil {
		return err
	}
	if !t.cfg.Unset(s) {
		return nil
	}
	return t.cfg.Save()
}

func requireSetting(name string) (config.Setting, error) {
	s, ok := config.LookupSetting(name)
	if !ok {
		return config.Setting{}, fmt.Errorf("unknown configuration name %q (expected one of: %s)", name, strings.Join(config.Names(), ", "))
	}
	return s, nil
}
