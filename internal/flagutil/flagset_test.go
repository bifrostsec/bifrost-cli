// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package flagutil

import (
	"bytes"
	"flag"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAliasedFlagSet_AliasesShareValueAndUsage(t *testing.T) {
	fl := NewAliasedFlagSet("", flag.ContinueOnError)
	var help bool
	fl.BoolVar(&help, "help", false, "show help", "h")
	fl.String("server-url", "https://example.com", "server")
	fl.Duration("timeout", 0, "timeout")

	require.NoError(t, fl.Parse([]string{"-h"}))
	assert.True(t, help)
	assert.True(t, IsSet(fl.FlagSet, "h"))
	assert.False(t, IsSet(fl.FlagSet, "help"), "only the spelling used on the command line counts as set")
	assert.False(t, IsSet(fl.FlagSet, "server-url"))

	var out bytes.Buffer
	fl.PrintDefaults(&out)
	assert.Equal(t, `  -help, -h
    show help
  -server-url string
    server (default "https://example.com")
  -timeout duration
    timeout
`, out.String())
}

func TestHasDefaultValue(t *testing.T) {
	fl := flag.NewFlagSet("", flag.ContinueOnError)
	fl.String("empty", "", "")
	fl.String("set", "x", "")
	fl.Int("zero", 0, "")
	fl.Int("three", 3, "")
	fl.Duration("none", 0, "")
	fl.Duration("some", time.Second, "")
	fl.Bool("off", false, "")

	for name, want := range map[string]bool{"empty": false, "set": true, "zero": false, "three": true, "none": false, "some": true, "off": false} {
		assert.Equal(t, want, HasDefaultValue(fl.Lookup(name)), name)
	}
}
