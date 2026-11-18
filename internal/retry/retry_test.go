// Copyright 2026 bifrost security
// SPDX-License-Identifier: Apache-2.0

package retry

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingPolicy returns a policy whose waits are recorded instead of slept.
func recordingPolicy(attempts int, delay time.Duration) (Policy, *[]time.Duration) {
	waits := &[]time.Duration{}
	return Policy{
		Attempts: attempts,
		Delay:    delay,
		Sleep: func(_ context.Context, d time.Duration) error {
			*waits = append(*waits, d)
			return nil
		},
	}, waits
}

func TestDo_SucceedsWithoutWaiting(t *testing.T) {
	policy, waits := recordingPolicy(3, time.Second)
	calls := 0
	err := policy.Do(context.Background(), func(context.Context) error { calls++; return nil })
	require.NoError(t, err)
	assert.Equal(t, 1, calls)
	assert.Empty(t, *waits)
}

func TestDo_RetriesTransientFailuresWithBackoff(t *testing.T) {
	policy, waits := recordingPolicy(6, time.Second)
	var notified []int
	policy.Notify = func(err error, attempt, attempts int, wait time.Duration) {
		assert.EqualError(t, err, "boom")
		assert.Equal(t, 6, attempts)
		notified = append(notified, attempt)
	}
	calls := 0
	err := policy.Do(context.Background(), func(context.Context) error {
		calls++
		if calls < 7 {
			return Transient(errors.New("boom"), 0)
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, 7, calls)
	assert.Equal(t, []time.Duration{1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second}, *waits, "doubling is capped at DefaultMaxDelay")
	assert.Equal(t, []int{1, 2, 3, 4, 5, 6}, notified)
}

func TestDo_GivesUpAfterAttempts(t *testing.T) {
	policy, waits := recordingPolicy(2, 0)
	calls := 0
	err := policy.Do(context.Background(), func(context.Context) error {
		calls++
		return Transient(errors.New("still down"), 0)
	})
	require.EqualError(t, err, "still down")
	assert.Equal(t, 3, calls, "one try plus two retries")
	assert.Equal(t, []time.Duration{0, 0}, *waits, "a zero delay retries immediately")

	var transient *TransientError
	assert.True(t, errors.As(err, &transient), "the returned error keeps its wrapping")
}

func TestDo_DoesNotRetryOtherErrors(t *testing.T) {
	policy, waits := recordingPolicy(3, time.Second)
	calls := 0
	err := policy.Do(context.Background(), func(context.Context) error {
		calls++
		return errors.New("bad request")
	})
	require.EqualError(t, err, "bad request")
	assert.Equal(t, 1, calls)
	assert.Empty(t, *waits)
}

func TestDo_HonoursRetryAfterWithinCap(t *testing.T) {
	policy, waits := recordingPolicy(2, time.Second)
	policy.MaxRetryAfter = 45 * time.Second
	requested := []time.Duration{10 * time.Second, 10 * time.Minute}
	calls := 0
	err := policy.Do(context.Background(), func(context.Context) error {
		calls++
		if calls <= 2 {
			return Transient(errors.New("rate limited"), requested[calls-1])
		}
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, []time.Duration{10 * time.Second, 45 * time.Second}, *waits, "the server's wait wins over backoff but is capped")

	policy, waits = recordingPolicy(1, 5*time.Second)
	calls = 0
	_ = policy.Do(context.Background(), func(context.Context) error {
		calls++
		return Transient(errors.New("rate limited"), time.Second)
	})
	assert.Equal(t, []time.Duration{5 * time.Second}, *waits, "a shorter Retry-After does not shrink the backoff")
}

func TestDo_StopsWhenContextEnds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	policy := Policy{Attempts: 5, Delay: time.Hour}
	calls := 0
	err := policy.Do(ctx, func(context.Context) error {
		calls++
		cancel()
		return Transient(errors.New("boom"), 0)
	})
	assert.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, calls)

	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	err = Policy{Attempts: 1, Delay: time.Hour}.Do(ctx, func(context.Context) error {
		return Transient(errors.New("boom"), 0)
	})
	assert.ErrorIs(t, err, context.Canceled, "a cancelled context is not slept on")
}

func TestZeroPolicyNeverRetries(t *testing.T) {
	calls := 0
	err := Policy{}.Do(context.Background(), func(context.Context) error {
		calls++
		return Transient(errors.New("boom"), 0)
	})
	require.EqualError(t, err, "boom")
	assert.Equal(t, 1, calls)
}

func TestRetryAfter(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	response := func(value string) *http.Response {
		resp := &http.Response{Header: http.Header{}}
		if value != "" {
			resp.Header.Set("Retry-After", value)
		}
		return resp
	}
	assert.Equal(t, time.Duration(0), RetryAfter(response(""), now))
	assert.Equal(t, 7*time.Second, RetryAfter(response("7"), now))
	assert.Equal(t, time.Duration(0), RetryAfter(response("-3"), now))
	assert.Equal(t, 90*time.Second, RetryAfter(response(now.Add(90*time.Second).Format(http.TimeFormat)), now))
	assert.Equal(t, time.Duration(0), RetryAfter(response(now.Add(-time.Minute).Format(http.TimeFormat)), now), "a date in the past means no wait")
	assert.Equal(t, time.Duration(0), RetryAfter(response("soon"), now))
}

func TestIsTransientStatus(t *testing.T) {
	for status, want := range map[int]bool{200: false, 400: false, 401: false, 408: true, 429: true, 500: true, 502: true, 503: true, 504: true} {
		assert.Equal(t, want, IsTransientStatus(status), status)
	}
}
