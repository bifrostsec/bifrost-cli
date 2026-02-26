package bifrost

import (
	"context"
	"fmt"
	"os"
)

type sbomUploadTask struct {
	Options
	paths []string
}

func NewSBOMUploadTask(opts Options, args []string) (Task, error) {
	if opts.service == "" {
		opts.service = os.Getenv("SERVICE")
		if opts.service == "" {
			return nil, fmt.Errorf("service name is required")
		}
	}
	if opts.serviceVersion == "" {
		opts.serviceVersion = os.Getenv("SERVICE_VERSION")
		if opts.serviceVersion == "" {
			return nil, fmt.Errorf("service version is required")
		}
	}
	if len(args) == 0 {
		return nil, fmt.Errorf("at least one SBOM file path is required")
	}
	return &sbomUploadTask{
		Options: opts,
		paths:   args,
	}, nil
}

func (t sbomUploadTask) Run(ctx context.Context) error {
	if len(t.paths) == 0 {
		return fmt.Errorf("no SBOM file paths provided")
	}
	api := NewAPI(t.ServerURL, t.apiKey)
	for _, path := range t.paths {
		// Check that file exists and is a regular file before attempting upload
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fmt.Errorf("directory instead of file: %s", path)
		}

		if err := api.UploadSBOM(ctx, t.service, t.serviceVersion, path); err != nil {
			return err
		}
		fmt.Printf("Uploaded %s to %s\n", path, t.ServerURL)
	}
	return nil
}
