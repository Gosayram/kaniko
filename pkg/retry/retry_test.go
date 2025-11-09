/*
Copyright 2024 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package retry

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetry_SuccessOnFirstAttempt(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.MaxAttempts = 3

	attempts := 0
	fn := func() error {
		attempts++
		return nil
	}

	err := Retry(ctx, config, fn)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if attempts != 1 {
		t.Errorf("Expected 1 attempt, got: %d", attempts)
	}
}

func TestRetry_SuccessAfterRetries(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.MaxAttempts = 3
	config.InitialDelay = 10 * time.Millisecond

	attempts := 0
	fn := func() error {
		attempts++
		if attempts < 2 {
			return errors.New("temporary error")
		}
		return nil
	}

	err := Retry(ctx, config, fn)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if attempts != 2 {
		t.Errorf("Expected 2 attempts, got: %d", attempts)
	}
}

func TestRetry_MaxRetriesExceeded(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.MaxAttempts = 3
	config.InitialDelay = 10 * time.Millisecond

	attempts := 0
	fn := func() error {
		attempts++
		return errors.New("persistent error")
	}

	err := Retry(ctx, config, fn)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if !errors.Is(err, ErrMaxRetriesExceeded) {
		t.Errorf("Expected ErrMaxRetriesExceeded, got: %v", err)
	}
	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got: %d", attempts)
	}
}

func TestRetry_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	config := DefaultRetryConfig()
	config.MaxAttempts = 5
	config.InitialDelay = 100 * time.Millisecond

	attempts := 0
	fn := func() error {
		attempts++
		if attempts == 1 {
			cancel() // Cancel after first attempt
		}
		return errors.New("error")
	}

	err := Retry(ctx, config, fn)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Expected context.Canceled, got: %v", err)
	}
	if attempts > 2 {
		t.Errorf("Expected at most 2 attempts, got: %d", attempts)
	}
}

func TestRetry_NonRetryableError(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.MaxAttempts = 3
	config.RetryableErrors = func(err error) bool {
		return err.Error() != "non-retryable"
	}

	attempts := 0
	fn := func() error {
		attempts++
		return errors.New("non-retryable")
	}

	err := Retry(ctx, config, fn)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if err.Error() != "non-retryable" {
		t.Errorf("Expected 'non-retryable' error, got: %v", err)
	}
	if attempts != 1 {
		t.Errorf("Expected 1 attempt (no retries for non-retryable), got: %d", attempts)
	}
}

func TestRetryWithResult_SuccessOnFirstAttempt(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.MaxAttempts = 3

	attempts := 0
	fn := func() (string, error) {
		attempts++
		return "success", nil
	}

	result, err := RetryWithResult(ctx, config, fn)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if result != "success" {
		t.Errorf("Expected 'success', got: %s", result)
	}
	if attempts != 1 {
		t.Errorf("Expected 1 attempt, got: %d", attempts)
	}
}

func TestRetryWithResult_SuccessAfterRetries(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.MaxAttempts = 3
	config.InitialDelay = 10 * time.Millisecond

	attempts := 0
	fn := func() (int, error) {
		attempts++
		if attempts < 2 {
			return 0, errors.New("temporary error")
		}
		return 42, nil
	}

	result, err := RetryWithResult(ctx, config, fn)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}
	if result != 42 {
		t.Errorf("Expected 42, got: %d", result)
	}
	if attempts != 2 {
		t.Errorf("Expected 2 attempts, got: %d", attempts)
	}
}

func TestRetryWithResult_MaxRetriesExceeded(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.MaxAttempts = 3
	config.InitialDelay = 10 * time.Millisecond

	attempts := 0
	fn := func() (string, error) {
		attempts++
		return "", errors.New("persistent error")
	}

	result, err := RetryWithResult(ctx, config, fn)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if !errors.Is(err, ErrMaxRetriesExceeded) {
		t.Errorf("Expected ErrMaxRetriesExceeded, got: %v", err)
	}
	if result != "" {
		t.Errorf("Expected empty string, got: %s", result)
	}
	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got: %d", attempts)
	}
}

func TestIsRetryableError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "timeout error",
			err:      errors.New("timeout error"),
			expected: true,
		},
		{
			name:     "connection error",
			err:      errors.New("connection refused"),
			expected: true,
		},
		{
			name:     "network error",
			err:      errors.New("network unreachable"),
			expected: true,
		},
		{
			name:     "temporary error",
			err:      errors.New("temporary failure"),
			expected: true,
		},
		{
			name:     "unavailable error",
			err:      errors.New("service unavailable"),
			expected: true,
		},
		{
			name:     "rate limit error",
			err:      errors.New("rate limit exceeded"),
			expected: true,
		},
		{
			name:     "too many requests",
			err:      errors.New("too many requests"),
			expected: true,
		},
		{
			name:     "non-retryable error",
			err:      errors.New("invalid input"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsRetryableError(tt.err)
			if result != tt.expected {
				t.Errorf("IsRetryableError(%v) = %v, expected %v", tt.err, result, tt.expected)
			}
		})
	}
}

func TestRetryConfigBuilder(t *testing.T) {
	builder := NewRetryConfigBuilder()
	config := builder.
		WithMaxAttempts(5).
		WithInitialDelay(2 * time.Second).
		WithMaxDelay(60 * time.Second).
		WithBackoff(3.0).
		WithRetryableErrors(func(err error) bool {
			return err.Error() == "retryable"
		}).
		Build()

	if config.MaxAttempts != 5 {
		t.Errorf("Expected MaxAttempts=5, got: %d", config.MaxAttempts)
	}
	if config.InitialDelay != 2*time.Second {
		t.Errorf("Expected InitialDelay=2s, got: %v", config.InitialDelay)
	}
	if config.MaxDelay != 60*time.Second {
		t.Errorf("Expected MaxDelay=60s, got: %v", config.MaxDelay)
	}
	if config.Backoff != 3.0 {
		t.Errorf("Expected Backoff=3.0, got: %f", config.Backoff)
	}
	if config.RetryableErrors == nil {
		t.Error("Expected RetryableErrors function, got nil")
	} else {
		if !config.RetryableErrors(errors.New("retryable")) {
			t.Error("Expected retryable error to be retryable")
		}
		if config.RetryableErrors(errors.New("not retryable")) {
			t.Error("Expected non-retryable error to not be retryable")
		}
	}
}

func TestRetry_ExponentialBackoff(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.MaxAttempts = 4
	config.InitialDelay = 10 * time.Millisecond
	config.MaxDelay = 100 * time.Millisecond
	config.Backoff = 2.0

	attempts := 0
	delays := []time.Duration{}
	startTime := time.Now()

	fn := func() error {
		attempts++
		if attempts > 1 {
			elapsed := time.Since(startTime)
			delays = append(delays, elapsed)
		}
		if attempts < 4 {
			return errors.New("error")
		}
		return nil
	}

	err := Retry(ctx, config, fn)
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Check that delays are approximately exponential (with some tolerance)
	if len(delays) >= 2 {
		ratio := float64(delays[1]) / float64(delays[0])
		if ratio < 1.5 || ratio > 3.0 {
			t.Errorf("Expected exponential backoff, got delays: %v, ratio: %f", delays, ratio)
		}
	}
}

func TestRetry_MaxDelayLimit(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.MaxAttempts = 5
	config.InitialDelay = 50 * time.Millisecond
	config.MaxDelay = 100 * time.Millisecond
	config.Backoff = 3.0 // This would exceed MaxDelay

	attempts := 0
	fn := func() error {
		attempts++
		if attempts < 5 {
			return errors.New("error")
		}
		return nil
	}

	startTime := time.Now()
	err := Retry(ctx, config, fn)
	duration := time.Since(startTime)

	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Total duration should be less than if MaxDelay wasn't applied
	// With backoff 3.0: 50ms, 150ms (capped at 100ms), 300ms (capped at 100ms), 900ms (capped at 100ms)
	// Expected: ~350ms total
	if duration > 500*time.Millisecond {
		t.Errorf("Expected duration to respect MaxDelay, got: %v", duration)
	}
}

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	if config.MaxAttempts != 3 {
		t.Errorf("Expected MaxAttempts=3, got: %d", config.MaxAttempts)
	}
	if config.InitialDelay != 1*time.Second {
		t.Errorf("Expected InitialDelay=1s, got: %v", config.InitialDelay)
	}
	if config.MaxDelay != 30*time.Second {
		t.Errorf("Expected MaxDelay=30s, got: %v", config.MaxDelay)
	}
	if config.Backoff != 2.0 {
		t.Errorf("Expected Backoff=2.0, got: %f", config.Backoff)
	}
	if config.RetryableErrors == nil {
		t.Error("Expected RetryableErrors function, got nil")
	}
}

func TestRetryConfig_String(t *testing.T) {
	config := RetryConfig{
		MaxAttempts:  5,
		InitialDelay: 2 * time.Second,
		MaxDelay:     60 * time.Second,
		Backoff:      3.0,
	}

	str := config.String()
	expected := "RetryConfig(maxAttempts=5, initialDelay=2s, maxDelay=1m0s, backoff=3.00)"
	if str != expected {
		t.Errorf("Expected %q, got %q", expected, str)
	}
}

func TestRetry_ZeroMaxAttempts(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()
	config.MaxAttempts = 0

	attempts := 0
	fn := func() error {
		attempts++
		return errors.New("error")
	}

	err := Retry(ctx, config, fn)
	if err == nil {
		t.Error("Expected error, got nil")
	}
	if attempts != 1 {
		t.Errorf("Expected 1 attempt (defaults to 1), got: %d", attempts)
	}
}
