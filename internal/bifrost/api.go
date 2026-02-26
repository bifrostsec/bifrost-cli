package bifrost

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
)

const (
	DefaultServerURL = "https://portal.bifrostsec.com"
)

type API interface {
	UploadSBOM(ctx context.Context, service string, serviceVersion string, filePath string) error
}

type api struct {
	client    http.Client
	serverUrl string
	token     string
}

func NewAPI(serverURL string, token string) API {
	return &api{
		client:    http.Client{},
		serverUrl: serverURL,
		token:     token,
	}
}

func (a *api) UploadSBOM(ctx context.Context, service string, serviceVersion string, filePath string) error {
	fi, err := os.Stat(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("SBOM file does not exist at path: %s", filePath)
		}
		return fmt.Errorf("failed to access file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("path is not a regular file: %s", filePath)
	}

	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open SBOM file: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		fmt.Sprintf("%s/api/v2/service/%s/version/%s/sbom", a.serverUrl, service, serviceVersion),
		file,
	)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Add("Authorization", "Bearer "+a.token)
	req.Header.Add("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}

	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("upload failed %s: %s: %s", filePath, resp.Status, string(body))
	}

	return nil
}
