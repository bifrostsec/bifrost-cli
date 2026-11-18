# bifrost CLI - Agent Guide

## Project Overview

bifrost is a command-line tool for interacting with the bifrost security platform. It uploads SBOMs to the portal,
manages local configuration and credentials in the style of the AWS CLI, and can authenticate in GitHub Actions by
exchanging the job's OIDC token for a portal access token.

## Application Structure

### Main Entry Point

The application runs from `cmd/bifrost/main.go`, which delegates to `cli.CLI()` in `internal/cli`. The code is
split into packages along the three-layer architecture pattern; dependencies only point downwards in this list:

1. **Input and output layer** (`internal/cli`)
   - Registers flags via `flag.NewFlagSet` (`RegisterOptions`) and resolves them into the `Options` struct
   - `ResolveOptions` layers command-line flags, environment variables, the selected profile of the
     config/credentials files and built-in defaults, in that order of precedence, then validates
   - Dispatches to a `command.Task`, prints errors, usage and chooses exit codes

2. **Task layer** (`internal/command`)
   - One `Task` per command: `NewSBOMUpload`, `NewConfig`, `NewAuthGitHubActions`, `NewAuthToken`
   - Tasks receive explicit option structs and an `auth.Resolver`; they never read flags or the environment

3. **Domain packages**
   - `internal/auth`: `Credentials`, `Resolver`, the AWS-style credential `Chain`, GitHub Actions OIDC token
     exchange (`GitHubActionsExchange`), `StoreAccessToken`
   - `internal/oauth2`: client for the portal token endpoint (RFC 6749 responses, RFC 8693 token exchange)
   - `internal/retry`: retry policy with exponential backoff and `Retry-After` support, used by the auth requests
   - `internal/portal`: HTTP client for the SBOM upload API with retries, defaults and `UserAgent`
   - `internal/config`: settings registry (`Settings`), config/credentials files and profiles (`Config`),
     precedence resolution (`Resolve`), `MaskSecret`, `DisplayPath`
   - `internal/git`: Git metadata discovery
   - `internal/ini`: INI reader/writer preserving comments and order
   - `internal/flagutil`: `AliasedFlagSet`, `IsSet`, `HasDefaultValue`
   - `internal/testutil`: test-only helpers (`IsolateEnvironment`, `WriteConfigFiles`, `WriteSBOM`)

### Key Components

- **cli.CLI**: entry point that parses flags, resolves options and dispatches to a task
- **cli.Options**: normalized app state for one invocation; mapped onto `command.SBOMUploadOptions` and
  `auth.GitHubActionsOptions` by small methods in `options.go`
- **config.Settings**: table of every configurable value with its file key, flag and environment variables;
  drives both resolution and the `config` command
- **config.Config**: the parsed `~/.bifrost/config` and `~/.bifrost/credentials` files for a profile
- **auth.Chain**: AWS-style provider chain producing the bearer token
- **auth.GitHubActionsExchange** with **oauth2.Client**: fetches the GitHub OIDC token and exchanges it at
  `/oauth2/token` (RFC 8693)
- **command.\***: command implementations behind the `Task` interface
- **cli.printUsage**: help text

### Configuration and Credentials

- Files follow the AWS CLI layout: `~/.bifrost/config` for general settings, `~/.bifrost/credentials` for secrets,
  INI formatted (`internal/ini`), profiles as `[default]` / `[profile <name>]` (config) and `[<name>]` (credentials).
  `BIFROST_CONFIG_FILE`, `BIFROST_SHARED_CREDENTIALS_FILE`, `BIFROST_PROFILE` and `--profile` override locations
  and the profile. A non-default profile must exist for commands that only read it (`sbom upload`, `auth token`),
  which catches typos; `config` and `auth github-actions` may create it.
- Precedence: command-line flag > environment variable > credentials file > config file > default. Both files may
  hold any setting (as in the AWS CLI); `Setting.File` only decides where `config set` writes. Files are saved
  atomically with mode 0600 even when they pre-existed with wider permissions.
- **Adding a setting**: add one entry to `config.Settings` in `internal/config/settings.go` and, if it should have a
  flag, register it in `cli.RegisterOptions` (a test asserts every setting's flag exists). Resolution,
  `config list|get|set|unset` and masking follow from the registry.
- Credential chain order: API key (flag/env/file) > unexpired `access_token` stored in the profile > GitHub Actions
  OIDC token exchange (when `ACTIONS_ID_TOKEN_REQUEST_URL`/`ACTIONS_ID_TOKEN_REQUEST_TOKEN` are set and an
  `org_id` is configured). `bifrost auth github-actions` performs the exchange and, when `GITHUB_ENV` is set,
  exports the token to the later steps of the job as `BIFROST_API_KEY` (printing `::add-mask::` first) so nothing
  outlives the job on a shared runner; with `--store profile` (the default outside Actions) it stores
  `access_token`, `access_token_expires_at`, `access_token_server_url` and `access_token_org_id` in the credentials
  file instead. The chain only reuses a cached token for the server (and organization, when one is given) it was
  issued for.
  `bifrost auth token` prints the resolved token. The upload task resolves credentials lazily through a
  `credentialCache`, after stdin is staged and again whenever the current token is about to expire.
- The OIDC token request and the token exchange retry network errors, 408, 429 and 5xx through `retry.Policy`
  (`retry_attempts`, `retry_delay` with doubling, `Retry-After` honoured); 4xx other than 408/429 are final.
  Mark a failure transient with `retry.Transient`.
- `cli.ResolveOptions` never fails on an invalid stored value; it records it in `ResolvedOptions.Invalid` and
  `cli.ValidateOptions` rejects it for every command except `config`, which prints a warning instead so the value
  can be repaired.
- A future interactive OAuth2 login (`bifrost auth login`) should store its tokens (`access_token`,
  `access_token_expires_at`, `refresh_token`) in the same credentials profile via `auth.StoreAccessToken`, plug
  into `auth.Chain`, and add its grant to `oauth2.Client`, which already handles token endpoint requests and
  error responses.
- Tests must not touch the developer's real files: each package's `TestMain` calls `testutil.IsolateEnvironment`,
  which points `HOME` at a temporary directory and clears all CLI environment variables, and
  `testutil.WriteConfigFiles` sets the file override variables.

### Architecture Pattern

The application follows the three-layer architecture pattern:
- No global state
- Single line `main()` that delegates to `bifrost.CLI()`
- Clean separation of concerns between input processing, task execution, and user output
- Flexible error handling throughout

## API Integration

### Endpoints

- **Upload**: `POST https://portal.bifrostsec.com/api/v2/service/{service}/version/sbom`
- **Token exchange**: `POST https://portal.bifrostsec.com/oauth2/token` with
  `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token_type=urn:ietf:params:oauth:token-type:jwt`
  and `subject_token=<GitHub OIDC token>` (form encoded). The GitHub OIDC token must carry the bifrost organization id
  as audience. The response is a 10 minute `Bearer` access token for the integration API. Errors follow RFC 6749
  (`error`, `error_description`); the endpoint is rate limited to 10 requests per minute per client.

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

Every setting has a `BIFROST_*` environment variable, which overrides the configuration files but not command-line flags:

- `BIFROST_API_KEY`: Bifrost API token used as bearer token
- `BIFROST_SERVER_URL` (legacy alias `SERVER_URL`): portal URL
- `BIFROST_ORG_ID`: organization id used as audience for the GitHub Actions OIDC token exchange
- `BIFROST_RETRY_ATTEMPTS`, `BIFROST_RETRY_DELAY`, `BIFROST_HTTP_TIMEOUT`: HTTP behaviour
- `BIFROST_GIT_REPO_PATH`: repository path for Git metadata detection
- `BIFROST_PROFILE`, `BIFROST_CONFIG_FILE`, `BIFROST_SHARED_CREDENTIALS_FILE`: profile and file locations
- `SERVICE`, `SERVICE_VERSION`, `IMAGE`: per-upload values (not stored in configuration files)
- `ACTIONS_ID_TOKEN_REQUEST_URL`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, `GITHUB_ACTIONS`: provided by GitHub Actions,
  read to perform the OIDC token exchange

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
├── cmd/bifrost/main.go          # Entry point
├── internal/
│   ├── cli/                     # Flag parsing, option resolution, dispatch, usage output
│   ├── command/                 # Tasks: sbom upload, config, auth github-actions, auth token
│   ├── auth/                    # Credential chain, GitHub Actions OIDC exchange, token storage
│   ├── oauth2/                  # OAuth 2.0 token endpoint client (RFC 8693 token exchange)
│   ├── retry/                   # Retry policy: backoff, Retry-After, transient errors
│   ├── portal/                  # Upload HTTP client with retries
│   ├── config/                  # Settings registry, config/credentials files, precedence
│   ├── git/                     # Git metadata detection
│   ├── ini/                     # INI reader/writer preserving comments and order
│   ├── flagutil/                # Flag aliases and helpers
│   └── testutil/                # Shared test helpers
├── go.mod                       # Module configuration
├── Makefile                     # Build automation
└── README.md                    # User documentation
```

## Important Notes

1. **Credential Requirement**: commands that call the portal need a bearer token from the credential chain
   (API key, stored access token, or GitHub Actions OIDC exchange); the application exits with an error
   explaining every source it tried when none is available
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