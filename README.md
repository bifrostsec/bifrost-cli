# bifrost-cli

A command-line tool for uploading SBOM (Software Bill of Materials) files to bifrost.

This repository contains the `bifrost-cli`, which lets you submit SBOMs for a specific service and version to your bifrost organization. It is intended for local automation and CI/CD workflows where you already produce SBOMs as part of your build pipeline.

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
3. Build the CLI:

```bash
make build
```

4. Upload an SBOM for a service and version:

```bash
BIFROST_API_KEY=my-key ./bifrost --service=name --service-version=34ha353 sbom upload /path/to/sbom.json
```

The API token is sent as a bearer token when the CLI uploads the SBOM.

## Usage

The CLI uploads one or more SBOM files and associates them with a bifrost service and service version.

```bash
./bifrost --service=my-service --service-version=1.2.3 sbom upload /path/to/sbom.json
```

You can provide the API token through:

- The `BIFROST_API_KEY` environment variable
- The `--api-key` flag

## Useful Links

- Website: [bifrostsec.com](https://bifrostsec.com/)
- Documentation: [docs.bifrostsec.com](https://docs.bifrostsec.com/)
- Getting started guide: [docs.bifrostsec.com/guides/get-started](https://docs.bifrostsec.com/guides/get-started/)
- SBOM reference: [https://docs.bifrostsec.com/reference/sbom/](https://docs.bifrostsec.com/reference/sbom/)
- API reference: [docs.bifrostsec.com/api/v2](https://docs.bifrostsec.com/api/v2/)
- Portal: [portal.bifrostsec.com](https://portal.bifrostsec.com/)

## License

Apache-2.0. See [LICENSE](LICENSE).
