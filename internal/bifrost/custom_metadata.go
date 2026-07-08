// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"fmt"
	"strings"
)

// CustomMetadata is user-provided metadata supplied through repeated --metadata flags.
type CustomMetadata map[string]string

// Set implements flag.Value by parsing key=value metadata input.
func (m *CustomMetadata) Set(value string) error {
	metadataName, metadataValue, ok := strings.Cut(value, "=")
	if !ok {
		return fmt.Errorf("metadata must be in key=value format")
	}
	if metadataName == "" {
		return fmt.Errorf("metadata key is required")
	}
	if *m == nil {
		*m = CustomMetadata{}
	}
	(*m)[metadataName] = metadataValue
	return nil
}

// String implements flag.Value. Metadata has no default display value.
func (m *CustomMetadata) String() string {
	return ""
}
