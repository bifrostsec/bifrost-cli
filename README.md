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

4. Upload an SBOM for a service, version, and image:

```bash
BIFROST_API_KEY=my-key ./bifrost --service=name --service-version=34ha353 --image=registry.example.com/team/app:34ha353 sbom upload /path/to/sbom.json
```

The API token is sent as a bearer token when the CLI uploads the SBOM.

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

You can also enable automatic Git metadata detection. When enabled, bifrost fills in missing Git metadata from the
current Git repository when those values are available:

```bash
./bifrost --service=my-service --service-version=1.2.3 --git-auto-detect sbom upload /path/to/sbom.json
```

To detect metadata from a specific path:

```bash
./bifrost --service=my-service --service-version=1.2.3 --git-auto-detect --git-repo-path=/path/to/repo sbom upload /path/to/sbom.json
```

You can enable automatic Git metadata detection with:

- The `BIFROST_GIT_AUTO_DETECT=true` environment variable
- The `--git-auto-detect` flag

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

## Options

| Option                       | Required    | Environment variable(s)            | Description                                                                                       |
|------------------------------|-------------|------------------------------------|---------------------------------------------------------------------------------------------------|
| `--api-key`                  | Yes         | `BIFROST_API_KEY`                  | Bifrost API key used for authentication.                                                          |
| `--service`                  | Yes         | `SERVICE`                          | Name of the service.                                                                              |
| `--service-version`          | Conditional | `SERVICE_VERSION`                  | Service version for the uploaded SBOM. Required unless an image is provided.                      |
| `--image`                    | Conditional | `IMAGE`                            | Container image reference for the uploaded SBOM. Required unless a service version is provided.   |
| `--server-url`               | No          | `SERVER_URL`, `BIFROST_SERVER_URL` | URL to the bifrost server.                                                                        |
| `--retry-attempts`           | No          |                                    | Number of retry attempts for transient upload failures.                                           |
| `--retry-delay`              | No          |                                    | Delay between upload retry attempts.                                                              |
| `--git-branch`               | No          |                                    | Git branch name to attach to the upload.                                                          |
| `--git-commit-sha`           | No          |                                    | Git commit SHA to attach to the upload.                                                           |
| `--git-origin`               | No          |                                    | Git origin URL to attach to the upload.                                                           |
| `--git-repo-path`            | No          |                                    | Git repository path used for automatic Git metadata detection. Defaults to the current directory. |
| `--git-auto-detect`          | No          | `BIFROST_GIT_AUTO_DETECT`          | Automatically fill missing Git metadata from the current Git repository when available.           |
| `--help`                     | No          |                                    | Show help and exit.                                                                               |

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
