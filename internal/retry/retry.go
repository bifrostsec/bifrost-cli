// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

// Package retry re-runs an operation whose failure was marked transient,
// waiting with exponential backoff or for as long as the server asked.
package retry

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"
)

const (
	// DefaultMaxDelay caps the exponential backoff between attempts.
	DefaultMaxDelay = 30 * time.Second
	// DefaultMaxRetryAfter caps a wait requested by the server through Retry-After.
	DefaultMaxRetryAfter = 2 * time.Minute
)

// TransientError marks a failure that is worth retrying, such as a network
// error, a 429 or a 5xx response. RetryAfter carries the wait the server asked
// for, zero when it did not say.
type TransientError struct {
	Err        error
	RetryAfter time.Duration
}

func (e *TransientError) Error() string { return e.Err.Error() }
func (e *TransientError) Unwrap() error { return e.Err }

// Transient wraps err so that Policy.Do retries it.
func Transient(err error, retryAfter time.Duration) error {
	return &TransientError{Err: err, RetryAfter: retryAfter}
}

// Policy decides how many times to retry and how long to wait in between.
// The zero value never retries.
type Policy struct {
	// Attempts is the number of retries after the first try.
	Attempts int
	// Delay is the wait before the first retry; it doubles on every retry
	// up to MaxDelay (DefaultMaxDelay when zero).
	Delay    time.Duration
	MaxDelay time.Duration
	// MaxRetryAfter caps a wait requested by the server (DefaultMaxRetryAfter when zero).
	MaxRetryAfter time.Duration
	// Notify, when set, is called before each wait with the failure that caused it.
	Notify func(err error, attempt, attempts int, wait time.Duration)
	// Sleep waits for d or until ctx ends; nil uses a timer. Tests inject it.
	Sleep func(ctx context.Context, d time.Duration) error
}

// Do runs fn until it succeeds, fails with an error that is not transient,
// the context ends, or the retries are used up. The last error is returned,
// or the context's error once the context has ended.
func (p Policy) Do(ctx context.Context, fn func(ctx context.Context) error) error {
	for attempt := 0; ; attempt++ {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		var transient *TransientError
		if attempt >= p.Attempts || !errors.As(err, &transient) {
			return err
		}
		wait := p.wait(attempt, transient.RetryAfter)
		if p.Notify != nil {
			p.Notify(err, attempt+1, p.Attempts, wait)
		}
		if err := p.sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// wait is the backoff for the given retry, or the server-requested wait when
// that is longer; both are capped.
func (p Policy) wait(attempt int, retryAfter time.Duration) time.Duration {
	maxDelay := p.MaxDelay
	if maxDelay <= 0 {
		maxDelay = DefaultMaxDelay
	}
	wait := p.Delay
	for i := 0; i < attempt && wait < maxDelay; i++ {
		wait *= 2
	}
	wait = min(max(wait, 0), maxDelay)

	maxRetryAfter := p.MaxRetryAfter
	if maxRetryAfter <= 0 {
		maxRetryAfter = DefaultMaxRetryAfter
	}
	if retryAfter > wait {
		wait = min(retryAfter, maxRetryAfter)
	}
	return wait
}

func (p Policy) sleep(ctx context.Context, d time.Duration) error {
	if p.Sleep != nil {
		return p.Sleep(ctx, d)
	}
	if d <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// RetryAfter reads the Retry-After header of resp, given either as a number of
// seconds or as an HTTP date, and returns the wait it asks for; zero when the
// header is absent, malformed or in the past.
func RetryAfter(resp *http.Response, now time.Time) time.Duration {
	value := resp.Header.Get("Retry-After")
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		return max(time.Duration(seconds)*time.Second, 0)
	}
	if at, err := http.ParseTime(value); err == nil {
		return max(at.Sub(now), 0)
	}
	return 0
}

// IsTransientStatus reports whether an HTTP status is worth retrying.
func IsTransientStatus(status int) bool {
	return status == http.StatusRequestTimeout ||
		status == http.StatusTooManyRequests ||
		status >= http.StatusInternalServerError
}
