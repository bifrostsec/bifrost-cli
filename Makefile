VERSION := $(shell git describe --long --dirty)
GIT_COMMIT := $(shell git rev-parse HEAD)
EXEC_NAME = bifrost
BUILD_DIR = build
GOOS = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)
LDFLAGS := -w -s
BUILD_FLAGS := -ldflags='$(LDFLAGS) -X main.Version=${VERSION} -X main.GitCommit=${GIT_COMMIT}' -a
TARGETS := linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-386 windows-amd64

help: ## Show this help message
	@echo "bifrost CLI"
	@echo "Usage: make [target]"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

deps: ## Download Go dependencies
	go mod download
	go mod tidy

build: build-$(GOOS)-$(GOARCH) ## Build binary for local architecture

build-%: ## Build binary for specified target OS and architecture (e.g. build-linux-amd64)
	$(eval GOOS := $(word 1, $(subst -, ,$*)))
	$(eval GOARCH := $(word 2, $(subst -, ,$*)))
	GOOS=$(GOOS) GOARCH=$(GOARCH) CGO_ENABLED=0 go build $(BUILD_FLAGS) -o $(BUILD_DIR)/$(EXEC_NAME)-$(GOOS)-$(GOARCH) ./cmd/bifrost

build-all: $(addprefix build-,$(TARGETS)) ## Build binaries for all supported targets

lint: ## Run linters
	docker run --rm -v ${PWD}:/app -w /app golangci/golangci-lint:v2.10.1-alpine golangci-lint run

test: ## Run tests
	go test -v ./...

tidy: ## Update go.mod to reflect the dependencies used in source code
	go mod tidy

check: tidy lint test ## Run all code quality checks

sbom-%: ## Generate SBOM in CycloneDX format for specified target OS and architecture (e.g. sbom-linux-amd64)
	@mkdir -p build
	$(eval GOOS := $(word 1, $(subst -, ,$*)))
	$(eval GOARCH := $(word 2, $(subst -, ,$*)))
	docker run --rm -v ${PWD}:/app -w /app -e GOOS=$(GOOS) -e GOARCH=$(GOARCH) -e CGO_ENABLED=0 cyclonedx/cyclonedx-gomod app -json=true -main cmd/bifrost > build/sbom_application_$*.cdx.json

sbom: $(addprefix sbom-,$(TARGETS)) ## Generate SBOMs for all supported targets

clean: ## Clean build artifacts
	rm -rf $(BUILD_DIR)

.PHONY: help build build-all check sbom clean