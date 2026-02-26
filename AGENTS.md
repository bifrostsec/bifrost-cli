# bifrost CLI - Agent Guide

## Project Overview

bifrost is a command-line tool for interacting with the bifrost security platform.
T

## Application Structure

### Main Entry Point

The application runs from `main.go`, which:
- Exits to the internal `bifrost.CLI()` function for entry point
- Implements the three-layer architecture pattern:

1. **Input Layer** (`bifrost.go` `fromArgs` method)
   - Handles user input via `flag.NewFlagSet`
   - Transforms raw flags into normalized parameters
   - Validates required arguments
   - Retrieves tokens from env vars

2. **Task Layer** (`bifrost.go` methods)
   - Core SBOM upload functionality
   - Performs HTTP POST requests to API endpoint
   - Manages file I/O operations
   - Implements retry and error-handling logic

3. **Output Layer**
   - User-facing error messages
   - Success notifications
   - Usage information

### Key Components

- **CLI function**: Entry point that orchestrates the three layers
- **SBOMUpload struct**: Holds normalized app state (Token, Path)
- **fromArgs method**: Input layer - parses flags and environment variables
- **run method**: Task layer - coordinates upload execution
- **upload method**: Core task logic - HTTP request handling
- **printUsage method**: Output layer - displays help text

### Architecture Pattern

The application follows the three-layer architecture pattern:
- No global state
- Single line `main()` that delegates to `bifrost.CLI()`
- Clean separation of concerns between input processing, task execution, and user output
- Flexible error handling throughout

## API Integration

### Endpoints

- **Upload**: `POST https://portal.bifrostsec.com/api/v2/sbom`

### Required Headers

- `Authorization`: Bearer token (user-provided via CLI flag or environment variables)
- `Content-Type`: `application/json`

### Input Format

- Accepts any file path as SBOM input
- Uploads as JSON text
- File is read and sent as JSON body
- The same token serves as both API and bearer authentication

## Testing and Verification

**IMPORTANT**: When verifying the codebase, always use Makefile targets instead of running `go build`, `go test`, or other direct commands:

### Building

```bash
make build
./bifrost
```

### Using Docker for Linting

The project uses golangci-lint for code quality checks:

```bash
make lint
```

This runs a Docker container with the golangci-lint:v2.10.1-alpine image to perform static analysis on the Go code.

### Running Tests

```bash
make test
```

## Environment Variables

The application supports these environment variables for token authentication:

- `BIFROST_API_TOKEN`: Alternative way to provide the Bifrost API token
- `BIFROST_KEY`: Alternative way to provide the bearer token for authentication (same token used for both)

## Git Repository

- **URL**: `git@github.com:bifrostsec/bifrost-cli.git`
- **Branch**: The default branch is `main`
- **Purpose**: Source code management and CI/CD pipeline integration

## Development Workflow

### Available Make Targets

- `make deps`: Download Go dependencies
- `make build`: Build the application
- `make lint`: Run code linters using Docker
- `make test`: Run tests
- `make tidy`: Update `go.mod`
- `make check`: Run all quality checks (tidy, lint, test)
- `make install`: Install the binary to GOPATH
- `make run`: Run the application with development settings
- `make clean`: Remove build artifacts

### Project Structure

```
.
├── bifrost/
│   └── bifrost.go    # Three-layer architecture implementation
├── main.go            # Entry point
├── go.mod             # Module configuration
├── Makefile           # Build automation
└── README.md          # User documentation
```

## Important Notes

1. **Token Requirement**: Token `BIFROST_KEY` serves as API bearer token - the application exits with an error if token is missing
2. **Architecture Pattern**: Implements the three-layer architecture (input, task, output) based on recommended CLI design patterns
3. **Error Handling**: Implements proper error propagation for file operations and HTTP requests
4. **No Flags Package Global Variables**: Uses local flags through `flag.NewFlagSet()` to avoid global state
5. **linter Configuration**: Uses `.golangci.yml` to disable specific linters for build compatibility

## Architecture Principles

Following best practices from command-line tool guidance:
- Minimal dependencies (no Cobra framework)
- Clear separation of concerns
- Single source of truth for configuration
- Proper error handling and user feedback
- Easy to test and extend