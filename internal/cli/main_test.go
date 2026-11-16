// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"testing"

	"github.com/bifrostsec/bifrost-cli/internal/testutil"
)

func TestMain(m *testing.M) {
	cleanup := testutil.IsolateEnvironment()
	code := m.Run()
	cleanup()
	os.Exit(code)
}
