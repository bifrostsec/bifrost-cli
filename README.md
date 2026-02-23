# Bifrost

A command-line tool for uploading SBOM (Software Bill of Materials) files to Bifrost Security Platform.

## Usage

```bash
./bifrost -sbom <path> -api-token <token> -token <bearer>
```

### Arguments

- `-sbom`: Local path to the SBOM file to upload
- `-api-token`: Bifrost API token (can also be set via `BIFROST_API_TOKEN` environment variable)
- `-token`: Bearer token for API authentication (can also be set via `BIFROST_TOKEN` environment variable)

### Environment Variables

- `BIFROST_API_TOKEN`: Bifrost API token
- `BIFROST_TOKEN`: Bearer token for API authentication

### Examples

```bash
# Using command-line arguments
./bifrost-cli -sbom ./my.sbom -api-token YOUR_API_TOKEN -token YOUR_BEARER_TOKEN

# Using environment variables
export BIFROST_API_TOKEN=YOUR_API_TOKEN
export BIFROST_TOKEN=YOUR_BEARER_TOKEN
./bifrost-cli -sbom ./my.sbom

# Using only SBOM path and API token (with default environment variable for bearer token)
./bifrost-cli -sbom ./my.sbom -api-token YOUR_API_TOKEN
```