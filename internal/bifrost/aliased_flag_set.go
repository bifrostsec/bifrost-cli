// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"flag"
	"fmt"
	"io"
	"reflect"
	"slices"
	"sort"
	"strings"
)

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
	if hasDefaultValue(f) {
		format := " (default %s)"
		if valueName == "string" {
			format = " (default %q)"
		}
		_, _ = fmt.Fprintf(output, format, f.DefValue)
	}
	_, _ = fmt.Fprintln(output)
}

// hasDefaultValue reports whether f's default differs from its type's zero value
func hasDefaultValue(f *flag.Flag) bool {
	valueType := reflect.TypeOf(f.Value)
	zeroValue := reflect.Zero(valueType)
	if valueType.Kind() == reflect.Ptr {
		zeroValue = reflect.New(valueType.Elem())
	}

	defaultValue, ok := zeroValue.Interface().(flag.Value)
	return !ok || f.DefValue != defaultValue.String()
}
