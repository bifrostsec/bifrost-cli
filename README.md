# bifrost-cli

A command-line tool for uploading SBOM (Software Bill of Materials) files to bifrost.

This repository contains the `bifrost-cli`, which lets you submit SBOMs for a specific service and version to your
bifrost organization. It is intended for local automation and CI/CD workflows where you already produce SBOMs as part of
your build pipeline.

## What is bifrost?

bifrost helps teams understand and reduce real workload risk with runtime security for containerized applications.

Learn more:
- Website: [bifrostsec.com](https://bifrostsec.com/)
- Documentation: [docs.bifrostsec.com](https://docs.bifrostsec.com/)
- Portal: [portal.bifrostsec.com](https://portal.bifrostsec.com/)

## Get Started

To use the CLI, you first need a bifrost account and an API token.

1. Create an account or sign in to the [bifrost portal](https://portal.bifrostsec.com/).
2. Create an API token for your organization in the organization settings.
3. Choose how you want to install the CLI.

   ### Install with Homebrew (macOS and Linux):

    ```bash
    brew install bifrostsec/tap/bifrost-cli
    ```

   This installs the `bifrost` command from the [bifrostsec/homebrew-tap](https://github.com/bifrostsec/homebrew-tap)
   tap. To update later:

    ```bash
    brew update
    brew upgrade bifrost-cli
    ```

   *(Windows is not covered by Homebrew — use one of the options below.)*

   ### Download the released executable:

    ```bash
    # Example for macOS on Apple Silicon
    curl -L -o bifrost https://github.com/bifrostsec/bifrost-cli/releases/latest/download/bifrost-darwin-arm64
    chmod +x ./bifrost
    ```

   *macOS note: the current macOS release binaries are not signed with an Apple Developer certificate. When you first
   run `./bifrost`, macOS may block it with a warning such as:*

   > **“bifrost” Not Opened**  
   > Apple could not verify “bifrost” is free of malware that may harm your Mac or compromise your privacy

   To allow the binary to run on macOS:

    1. Try to run `./bifrost` once so macOS registers the blocked executable.
    2. Open `System Settings` > `Privacy & Security`.
    3. Scroll down to the `Security` section and click `Allow Anyway` for `bifrost`.
    4. Confirm with your login password if prompted.
    5. Run `./bifrost` again.

   *The `Allow Anyway` button is only shown for a limited time after the blocked launch attempt, so if you do not see
   it, run `./bifrost` again and return to `Privacy & Security`.*

   Release assets are published at:

    - [github.com/bifrostsec/bifrost-cli/releases/latest](https://github.com/bifrostsec/bifrost-cli/releases/latest)

   Available executable names include:

    - `bifrost-darwin-amd64`
    - `bifrost-darwin-arm64`
    - `bifrost-linux-amd64`
    - `bifrost-linux-arm64`
    - `bifrost-windows-386`
    - `bifrost-windows-amd64`

   ### Or build the CLI from source:

    ```bash
    make build
    ```

4. Store the API token locally (it is written to `~/.bifrost/credentials`), or pass it with `BIFROST_API_KEY` /
   `--api-key` on every call:

```bash
./bifrost config
```

5. Upload an SBOM for a service, version, and image:

```bash
./bifrost --service=name --service-version=34ha353 --image=registry.example.com/team/app:34ha353 sbom upload /path/to/sbom.json
```

The API token is sent as a bearer token when the CLI uploads the SBOM. In GitHub Actions the CLI can authenticate
without a stored token at all, see [GitHub Actions](#github-actions).

## Usage

The CLI uploads one or more SBOM files and associates them with a bifrost service and service version.

```bash
./bifrost --service=my-service --service-version=1.2.3 --image=registry.example.com/team/app:1.2.3 sbom upload /path/to/sbom.json
```

You can also read an SBOM from standard input by using `-` as the path:

```bash
cat /path/to/sbom.json | ./bifrost --service=my-service --service-version=1.2.3 --image=registry.example.com/team/app:1.2.3 sbom upload -
```

You can control retry behavior for transient upload failures:

```bash
./bifrost --service=my-service --service-version=1.2.3 --image=registry.example.com/team/app:1.2.3 --retry-attempts=5 --retry-delay=5s sbom upload /path/to/sbom.json
```

Git metadata is optional. You can attach it manually:

```bash
./bifrost --service=my-service --service-version=1.2.3 --image=registry.example.com/team/app:1.2.3 --git-branch=main --git-commit-sha=abc123 --git-origin=https://github.com/example/project.git sbom upload /path/to/sbom.json
```

You can also automatically fill in missing Git metadata by providing the repository path. Use `.` for the current
directory:

```bash
./bifrost --service=my-service --service-version=1.2.3 --git-repo-path=. sbom upload /path/to/sbom.json
```

The path can be absolute or relative to the current directory:

```bash
./bifrost --service=my-service --service-version=1.2.3 --git-repo-path=/path/to/repo sbom upload /path/to/sbom.json
```

The repository path can also be exported as an environment variable:

```bash
export BIFROST_GIT_REPO_PATH=.
./bifrost --service=my-service --service-version=1.2.3 sbom upload /path/to/sbom.json
```

When neither `--git-repo-path` nor `BIFROST_GIT_REPO_PATH` is provided, bifrost does not automatically detect Git
metadata.

Example with Trivy generating a CycloneDX SBOM for a container image and piping it directly to bifrost:

```bash
trivy image --format cyclonedx <image> | ./bifrost --service=my-service --service-version=1.2.3 --image=<image> sbom upload -
```

Example with GitHub CLI exporting the repository dependency graph SBOM and piping the SPDX document to bifrost:

```bash
gh api \
  -H "Accept: application/vnd.github+json" \
  -H "X-GitHub-Api-Version: 2026-03-10" \
  /repos/OWNER/REPO/dependency-graph/sbom \
  --jq '.sbom' | ./bifrost --service=my-service --service-version=1.2.3 --image=ghcr.io/OWNER/REPO:1.2.3 sbom upload -
```

## Configuration

The CLI reads settings from configuration files in the same way as the AWS CLI. Every setting can be given on the
command line, in an environment variable, or stored in a profile in the configuration files. Values are resolved in
this order of precedence:

1. Command-line options, e.g. `--server-url`.
2. Environment variables, e.g. `BIFROST_SERVER_URL`.
3. The selected profile in `~/.bifrost/credentials`, then `~/.bifrost/config`.
4. Built-in defaults.

General settings live in `~/.bifrost/config` and secrets in `~/.bifrost/credentials`. Both files are INI formatted
and, as in the AWS CLI, either file may hold any setting; values in the credentials file win. The `default` profile is
used unless `--profile` or `BIFROST_PROFILE` selects another one. A non-default profile is written as `[profile <name>]`
in the config file and as `[<name>]` in the credentials file.

```ini
# ~/.bifrost/config
[default]
server_url = https://portal.bifrostsec.com
http_timeout = 45s

[profile ci]
org_id = org_01m2fwhfjmfdcv7cm1b23xg7qa
```

```ini
# ~/.bifrost/credentials
[default]
api_key = <your API token>
```

Use `BIFROST_CONFIG_FILE` and `BIFROST_SHARED_CREDENTIALS_FILE` to read the files from other locations.

The `config` command manages the files, so you never have to edit them by hand:

```bash
./bifrost config                              # prompt for the API key and server URL
./bifrost config list                         # show every setting, its value and where it comes from
./bifrost config list-profiles                # list the profiles found in both files
./bifrost config get server_url               # print a stored value (exit status 1 when unset)
./bifrost config set http_timeout 45s         # store a value in the selected profile
./bifrost --profile ci config set org_id org_01m2fwhfjmfdcv7cm1b23xg7qa
./bifrost config unset api_key                # remove a stored value
```

Settings that can be stored: `server_url`, `api_key`, `org_id`, `retry_attempts`, `retry_delay`, `http_timeout` and
`git_repo_path`, plus the `access_token`, `access_token_expires_at`, `access_token_server_url` and
`access_token_org_id` entries that `bifrost auth` commands write. Secrets are masked in `config list` output, and the
files are always written with owner-only permissions. The `config` commands keep working when a stored value is
invalid, so a mistake can be inspected with `config list` and repaired with `config set` or `config unset`.

### Credentials

When a command needs to authenticate, the CLI takes the first credential it finds:

1. An API key from `--api-key`, `BIFROST_API_KEY`, or the `api_key` setting of the profile.
2. An unexpired access token stored in the profile by a `bifrost auth` command, provided it was issued by the
   selected server and, when an organization id is given, for that organization.
3. In GitHub Actions, an access token obtained by exchanging the job's OIDC token (see below).

`bifrost auth token` prints the credential the CLI would use, which is handy for debugging or for passing the token to
other tools.

## GitHub Actions

In a GitHub Actions workflow the CLI can authenticate without any stored secret. GitHub issues the job an OIDC token,
and the CLI exchanges it at the portal's OAuth 2.0 token endpoint (`/oauth2/token`, [RFC 8693] Token Exchange) for a
short-lived bifrost access token (valid for 10 minutes). For this to work:

- The GitHub organization that owns the repository must be linked to your bifrost organization in the portal.
- The job needs `permissions: id-token: write`.
- The CLI needs your bifrost organization id (`org_...`) via `--org-id`, `BIFROST_ORG_ID`, or the `org_id` setting.
  It is used as the audience of the OIDC token.

The exchange happens automatically when the CLI runs in GitHub Actions with an organization id and no API key:

```yaml
jobs:
  sbom:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    env:
      BIFROST_ORG_ID: ${{ vars.BIFROST_ORG_ID }}
    steps:
      - uses: actions/checkout@v6
      - run: trivy image --format cyclonedx $IMAGE > sbom.json
      - run: bifrost --service=my-service --service-version=${{ github.sha }} --image=$IMAGE --git-repo-path=. sbom upload sbom.json
```

Alternatively, exchange the token once with `bifrost auth github-actions`, which stores the access token in the runner's
`~/.bifrost/credentials`. Later steps in the same job then authenticate without `BIFROST_ORG_ID`:

```yaml
      - run: bifrost --org-id ${{ vars.BIFROST_ORG_ID }} auth github-actions
      - run: bifrost --service=my-service --service-version=${{ github.sha }} sbom upload sbom.json
```

On self-hosted runners shared between jobs, prefer the automatic exchange so no token is written to disk.

[RFC 8693]: https://www.rfc-editor.org/rfc/rfc8693.html

## Options

| Option              | Required    | Environment variable(s)                                 | Description                                                                                                                                           |
|---------------------|-------------|---------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--api-key`         | Conditional | `BIFROST_API_KEY`                                       | Bifrost API key used for authentication. Not needed when an access token is stored by `bifrost auth` or when running in GitHub Actions with `--org-id`. |
| `--profile`         | No          | `BIFROST_PROFILE`                                       | Profile to read from the configuration files. Defaults to `default`.                                                                                  |
| `--org-id`          | No          | `BIFROST_ORG_ID`                                        | Bifrost organization id used to exchange a GitHub Actions OIDC token for an access token.                                                             |
| `--service`         | Yes         | `SERVICE`                                               | Name of the service.                                                                                                                                  |
| `--service-version` | Conditional | `SERVICE_VERSION`                                       | Service version for the uploaded SBOM. Required unless an image is provided.                                                                          |
| `--image`           | Conditional | `IMAGE`                                                 | Container image reference for the uploaded SBOM. Required unless a service version is provided.                                                       |
| `--server-url`      | No          | `BIFROST_SERVER_URL`, `SERVER_URL`                      | URL to the bifrost server.                                                                                                                            |
| `--retry-attempts`  | No          | `BIFROST_RETRY_ATTEMPTS`                                | Number of retry attempts for transient upload failures.                                                                                               |
| `--retry-delay`     | No          | `BIFROST_RETRY_DELAY`                                   | Delay between upload retry attempts.                                                                                                                  |
| `--http-timeout`    | No          | `BIFROST_HTTP_TIMEOUT`                                  | Maximum duration to wait for an HTTP request. Defaults to 30 seconds.                                                                                 |
| `--git-branch`      | No          |                                                         | Git branch name to attach to the upload.                                                                                                              |
| `--git-commit-sha`  | No          |                                                         | Git commit SHA to attach to the upload.                                                                                                               |
| `--git-origin`      | No          |                                                         | Git origin URL to attach to the upload.                                                                                                               |
| `--git-repo-path`   | No          | `BIFROST_GIT_REPO_PATH`                                 | Git repository path used for automatic Git metadata detection.                                                                                        |
| `--version`, `-V`   | No          |                                                         | Print the CLI version and build commit, then exit.                                                                                                    |
| `--help`, `-h`      | No          |                                                         | Show help and exit.                                                                                                                                   |

Options marked with an environment variable can also be stored in the configuration files under the setting name with
underscores, e.g. `server_url` for `--server-url`. `BIFROST_CONFIG_FILE` and `BIFROST_SHARED_CREDENTIALS_FILE` override
the configuration file locations.

## Useful Links

- Website: [bifrostsec.com](https://bifrostsec.com/)
- Documentation: [docs.bifrostsec.com](https://docs.bifrostsec.com/)
- Releases: [github.com/bifrostsec/bifrost-cli/releases/latest](https://github.com/bifrostsec/bifrost-cli/releases/latest)
- Getting started guide: [docs.bifrostsec.com/guides/get-started](https://docs.bifrostsec.com/guides/get-started/)
- SBOM reference: [https://docs.bifrostsec.com/reference/sbom/](https://docs.bifrostsec.com/reference/sbom/)
- API reference: [docs.bifrostsec.com/api/v2](https://docs.bifrostsec.com/api/v2/)
- Portal: [portal.bifrostsec.com](https://portal.bifrostsec.com/)

## License

Apache-2.0. See [LICENSE](LICENSE).
