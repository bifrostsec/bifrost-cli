// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

// Package ini reads and writes the INI style files used for CLI configuration
// and credentials, in the same format as the AWS CLI shared config files.
//
// The in-memory representation keeps the original line order, comments and
// blank lines so that files edited by hand survive a programmatic update.
package ini

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// File is a parsed INI file.
type File struct {
	// leading holds comment and blank lines before the first section header.
	leading  []string
	sections []*section
}

type section struct {
	name  string
	lines []line
}

// line is a single line inside a section. Key is empty for comments and blank lines.
type line struct {
	key   string
	value string
	raw   string
}

// Parse reads an INI document.
func Parse(r io.Reader) (*File, error) {
	file := &File{}
	var current *section
	scanner := bufio.NewScanner(r)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		raw := scanner.Text()
		trimmed := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]"):
			name := strings.TrimSpace(trimmed[1 : len(trimmed)-1])
			if name == "" {
				return nil, fmt.Errorf("line %d: empty section name", lineNumber)
			}
			current = file.section(name)
			if current == nil {
				current = &section{name: name}
				file.sections = append(file.sections, current)
			}
		case trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";"):
			if current == nil {
				file.leading = append(file.leading, raw)
			} else {
				current.lines = append(current.lines, line{raw: raw})
			}
		default:
			key, value, found := strings.Cut(trimmed, "=")
			key = strings.TrimSpace(key)
			if !found || key == "" {
				return nil, fmt.Errorf("line %d: expected `key = value`, got %q", lineNumber, trimmed)
			}
			if current == nil {
				return nil, fmt.Errorf("line %d: %q appears before any [section] header", lineNumber, key)
			}
			current.lines = append(current.lines, line{key: key, value: strings.TrimSpace(value), raw: raw})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return file, nil
}

// Load parses the file at path. A missing file yields an empty File and no error.
func Load(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &File{}, nil
		}
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()
	file, err := Parse(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return file, nil
}

// Sections returns the section names in file order.
func (f *File) Sections() []string {
	names := make([]string, 0, len(f.sections))
	for _, s := range f.sections {
		names = append(names, s.name)
	}
	return names
}

// HasSection reports whether a section with the given name exists.
func (f *File) HasSection(name string) bool {
	return f.section(name) != nil
}

// Get returns the value of key in section. Keys are matched case-insensitively.
func (f *File) Get(sectionName, key string) (string, bool) {
	s := f.section(sectionName)
	if s == nil {
		return "", false
	}
	for i := len(s.lines) - 1; i >= 0; i-- {
		if strings.EqualFold(s.lines[i].key, key) {
			return s.lines[i].value, true
		}
	}
	return "", false
}

// Set assigns value to key in section, creating the section when missing.
func (f *File) Set(sectionName, key, value string) {
	s := f.section(sectionName)
	if s == nil {
		s = &section{name: sectionName}
		if len(f.sections) > 0 {
			f.sections[len(f.sections)-1].ensureTrailingBlankLine()
		}
		f.sections = append(f.sections, s)
	}
	formatted := line{key: key, value: value, raw: fmt.Sprintf("%s = %s", key, value)}
	// Replace the last occurrence, which is the one Get reports as effective.
	for i := len(s.lines) - 1; i >= 0; i-- {
		if strings.EqualFold(s.lines[i].key, key) {
			s.lines[i] = formatted
			return
		}
	}
	// Insert before trailing blank lines so sections stay visually separated.
	insertAt := len(s.lines)
	for insertAt > 0 && s.lines[insertAt-1].key == "" && strings.TrimSpace(s.lines[insertAt-1].raw) == "" {
		insertAt--
	}
	s.lines = append(s.lines[:insertAt], append([]line{formatted}, s.lines[insertAt:]...)...)
}

// Delete removes key from section and reports whether it was present.
func (f *File) Delete(sectionName, key string) bool {
	s := f.section(sectionName)
	if s == nil {
		return false
	}
	deleted := false
	kept := s.lines[:0]
	for _, l := range s.lines {
		if strings.EqualFold(l.key, key) {
			deleted = true
			continue
		}
		kept = append(kept, l)
	}
	s.lines = kept
	return deleted
}

// WriteTo serializes the file.
func (f *File) WriteTo(w io.Writer) (int64, error) {
	var b strings.Builder
	for _, raw := range f.leading {
		b.WriteString(raw)
		b.WriteString("\n")
	}
	for _, s := range f.sections {
		fmt.Fprintf(&b, "[%s]\n", s.name)
		for _, l := range s.lines {
			b.WriteString(l.raw)
			b.WriteString("\n")
		}
	}
	n, err := io.WriteString(w, b.String())
	return int64(n), err
}

// Save writes the file to path, creating parent directories. The content is
// written to a temporary file with owner-only permissions and then moved into
// place, so the result is never partially written and always ends up with mode
// 0600 even when path already existed with wider permissions.
func (f *File) Save(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = os.Remove(tmpPath) // no-op once the rename succeeded
	}()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := f.WriteTo(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func (f *File) section(name string) *section {
	for _, s := range f.sections {
		if s.name == name {
			return s
		}
	}
	return nil
}

func (s *section) ensureTrailingBlankLine() {
	if len(s.lines) == 0 || strings.TrimSpace(s.lines[len(s.lines)-1].raw) != "" {
		s.lines = append(s.lines, line{raw: ""})
	}
}
