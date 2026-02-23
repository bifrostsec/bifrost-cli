package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

type Config struct {
	Token    string
	SBOMPath string
	APIToken string
}

func main() {
	config := Config{}

	fs := flag.NewFlagSet("bifrost-cli", flag.ExitOnError)
	fs.StringVar(&config.APIToken, "api-token", "", "Bifrost API token (can also be set via BIFROST_API_TOKEN env var)")
	fs.StringVar(&config.Token, "token", "", "Bearer token for API authentication (can also be set via BIFROST_TOKEN env var)")
	fs.StringVar(&config.SBOMPath, "sbom", "", "Local path to SBOM file to upload")
	fs.Parse(os.Args[1:])

	if config.APIToken == "" {
		config.APIToken = os.Getenv("BIFROST_API_TOKEN")
	}

	if config.Token == "" {
		config.Token = os.Getenv("BIFROST_TOKEN")
	}

	if config.SBOMPath == "" {
		fmt.Printf("Error: SBOM path is required\n\nUsage:\n  bifrost-cli -sbom <path> -api-token <token> [-token <bearer>]\n\nExample:\n  bifrost-cli -sbom ./my.sbom -api-token YOUR_API_TOKEN\n  bifrost-cli -sbom ./my.sbom -token YOUR_BEARER_TOKEN\n")
		os.Exit(1)
	}

	if config.APIToken == "" {
		fmt.Printf("Error: Bifrost API token is required\n\nUsage:\n  bifrost-cli -sbom <path> -api-token <token> [-token <bearer>]\n  bifrost-cli -sbom <path> -api-token <token> -token <bearer>\n  bifrost-cli -sbom <path> -api-token <token>\n\nBIFROST_API_TOKEN environment variable can also be used\n")
		os.Exit(1)
	}

	if config.Token == "" {
		fmt.Printf("Error: Bearer token is required\n\nUsage:\n  bifrost-cli -sbom <path> -api-token <token> -token <bearer>\n\nBIFROST_TOKEN environment variable can also be used\n")
		os.Exit(1)
	}

	err := uploadSBOM(config.SBOMPath, config.Token, config.APIToken)
	if err != nil {
		fmt.Printf("Error uploading SBOM: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Successfully uploaded SBOM")
}

func uploadSBOM(sbomPath, bearerToken, apiToken string) error {
	file, err := os.Open(sbomPath)
	if err != nil {
		return fmt.Errorf("failed to open SBOM file: %w", err)
	}
	defer file.Close()

	_ = strings.TrimPrefix(sbomPath, "./")

	req, err := http.NewRequest(
		"POST",
		"https://portal.bifrostsec.com/api/v2/sbom",
		file,
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+bearerToken)
	req.Header.Set("X-API-Token", apiToken)
	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}
