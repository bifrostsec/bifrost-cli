#!/bin/sh

# Copyright 2026 bifrost security
# SPDX-License-Identifier: Apache-2.0

VERSION=$(git describe --tags --long --dirty)
GIT_COMMIT=$(git rev-parse --short HEAD)

go run -ldflags="-w -s -X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT}" -v ./cmd/bifrost "$@"
