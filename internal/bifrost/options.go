// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package bifrost

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"
)

type Options struct {
	ServerURL      string
	apiKey         string
	service        string
	serviceVersion string
	RetryAttempts  int
	RetryDelay     time.Duration
}

func RegisterOptions(fl *flag.FlagSet, opts *Options) {
	fl.StringVar(&opts.ServerURL, "server-url", DefaultServerURL, "URL to bifrost server")
	fl.StringVar(&opts.apiKey, "api-key", "", "Bifrost API key")
	fl.StringVar(&opts.service, "service", "", "Name of the service")
	fl.StringVar(&opts.serviceVersion, "service-version", "", "Version of the service")
	fl.IntVar(&opts.RetryAttempts, "retry-attempts", DefaultRetryAttempts, "Number of retry attempts for transient upload failures")
	fl.DurationVar(&opts.RetryDelay, "retry-delay", DefaultRetryDelay, "Delay between upload retry attempts")
}

func ValidateBaseOptions(opts *Options) error {
	if u := os.Getenv("SERVER_URL"); u != "" {
		opts.ServerURL = u
	}
	if u := os.Getenv("BIFROST_SERVER_URL"); u != "" {
		opts.ServerURL = u
	}
	_, err := url.Parse(opts.ServerURL)
	if err != nil {
		return err
	}

	if opts.apiKey == "" {
		opts.apiKey = os.Getenv("BIFROST_API_KEY")
		if opts.apiKey == "" {
			return fmt.Errorf("API key is required")
		}
	}
	if opts.RetryAttempts < 0 {
		return fmt.Errorf("retry attempts must be zero or greater")
	}
	if opts.RetryDelay < 0 {
		return fmt.Errorf("retry delay must be zero or greater")
	}

	return nil
}
