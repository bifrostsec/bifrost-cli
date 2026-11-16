// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

// Package flagutil extends the standard flag package with aliases and helpers
// for inspecting how a flag was set.
package flagutil

import (
	"flag"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sort"
	"strings"
)

// AliasedFlagSet is a flag.FlagSet whose boolean flags can have short aliases
// that are grouped with the main flag in the usage output.
type AliasedFlagSet struct {
	*flag.FlagSet
	aliasGroups map[string][]string
	aliases     []string
}

func NewAliasedFlagSet(name string, errorHandling flag.ErrorHandling) *AliasedFlagSet {
	return &AliasedFlagSet{
		FlagSet:     flag.NewFlagSet(name, errorHandling),
		aliasGroups: make(map[string][]string),
	}
}

func (fl *AliasedFlagSet) BoolVar(value *bool, name string, defaultValue bool, usage string, aliases ...string) {
	fl.FlagSet.BoolVar(value, name, defaultValue, usage)
	if len(aliases) == 0 {
		return
	}

	fl.aliasGroups[name] = aliases
	for _, alias := range aliases {
		fl.aliases = append(fl.aliases, alias)
		fl.FlagSet.BoolVar(value, alias, defaultValue, usage)
	}
}

func (fl *AliasedFlagSet) PrintDefaults(output io.Writer) {
	fl.VisitAll(func(f *flag.Flag) {
		if slices.Contains(fl.aliases, f.Name) {
			return
		}

		flagAliases := fl.aliasGroups[f.Name]
		name := "-" + f.Name
		if len(flagAliases) > 0 {
			name = formatFlagNames(append([]string{f.Name}, flagAliases...))
		}
		printFlagUsage(output, name, f)
	})
}

// formatFlagNames renders names (main flag name first, aliases sorted alphabetically after it)
func formatFlagNames(names []string) string {
	sort.Strings(names[1:])
	for i, name := range names {
		names[i] = "-" + name
	}
	return strings.Join(names, ", ")
}

func printFlagUsage(output io.Writer, name string, f *flag.Flag) {
	valueName, usage := flag.UnquoteUsage(f)
	_, _ = fmt.Fprintf(output, "  %s", name)
	if valueName != "" {
		_, _ = fmt.Fprintf(output, " %s", valueName)
	}
	_, _ = fmt.Fprintf(output, "\n    %s", usage)
	if HasDefaultValue(f) {
		format := " (default %s)"
		if valueName == "string" {
			format = " (default %q)"
		}
		_, _ = fmt.Fprintf(output, format, f.DefValue)
	}
	_, _ = fmt.Fprintln(output)
}

// HasDefaultValue reports whether f's default differs from its type's zero value
func HasDefaultValue(f *flag.Flag) bool {
	valueType := reflect.TypeOf(f.Value)
	zeroValue := reflect.Zero(valueType)
	if valueType.Kind() == reflect.Pointer {
		zeroValue = reflect.New(valueType.Elem())
	}

	defaultValue, ok := zeroValue.Interface().(flag.Value)
	return !ok || f.DefValue != defaultValue.String()
}

// IsSet reports whether the named flag was given on the command line.
func IsSet(fl *flag.FlagSet, name string) bool {
	isSet := false
	fl.Visit(func(f *flag.Flag) {
		if f.Name == name {
			isSet = true
		}
	})
	return isSet
}
