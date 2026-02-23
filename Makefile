VERSION := $(shell git describe --long --dirty)
BUILD_TIME := $(shell date +'%Y%m%dh%H%M%S')
EXEC_NAME = bifrost
BUILD_DIR = build
GOOS = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)
LDFLAGS := -w -s
BUILD_FLAGS := -ldflags='$(LDFLAGS)' -a

help: ## Show this help message
	@echo "Bifrost CLI"
	@echo "Usage: make [target]"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

deps: ## Download Go dependencies
	go mod download
	go mod tidy

build-local: ## Build binary for local architecture
	@eval EXEC_PATH:=$(BUILD_DIR)/$(GOOS)/$(GOARCH)/$(EXEC_NAME)
	@GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build $(BUILD_FLAGS) -o $(EXEC_PATH) .

build: build-local ## Build binary

lint: ## Run linters
	golangci-lint run

test: ## Run tests
	go test -v ./...

tidy: ## Update go.mod to reflect the dependencies used in source code
	go mod tidy

check: tidy lint test ## Run all code quality checks

install: ## Install the binary
	go install -v .

run: ## Run with development settings
	go run -ldflags='$(LDFLAGS)' -v .

clean: ## Clean build artifacts
	rm -rf $(BUILD_DIR)

.PHONY: help