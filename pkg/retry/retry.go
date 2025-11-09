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

// Package retry provides retry mechanism with exponential backoff
// for improved error handling and recovery
package retry

import (
	"context"
	"fmt"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	// DefaultMaxAttempts is the default maximum number of retry attempts
	DefaultMaxAttempts = 3
	// DefaultMaxDelay is the default maximum delay between retries
	DefaultMaxDelay = 30 * time.Second
	// DefaultBackoff is the default exponential backoff multiplier
	DefaultBackoff = 2.0
	// PercentageMultiplier is used to convert ratio to percentage
	PercentageMultiplier = 100.0
)

// RetryConfig defines retry configuration
//
//nolint:revive // stuttering name is intentional for public API clarity
type RetryConfig struct {
	// MaxAttempts is the maximum number of retry attempts
	MaxAttempts int

	// InitialDelay is the initial delay before first retry
	InitialDelay time.Duration

	// MaxDelay is the maximum delay between retries
	MaxDelay time.Duration

	// Backoff is the exponential backoff multiplier
	Backoff float64

	// RetryableErrors is a function that determines if an error is retryable
	RetryableErrors func(error) bool
}

// DefaultRetryConfig returns a default retry configuration
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:  DefaultMaxAttempts,
		InitialDelay: 1 * time.Second,
		MaxDelay:     DefaultMaxDelay,
		Backoff:      DefaultBackoff,
		RetryableErrors: func(_ error) bool {
			// Default: retry on all errors
			return true
		},
	}
}

// ErrMaxRetriesExceeded is returned when max retries are exceeded
var ErrMaxRetriesExceeded = errors.New("max retries exceeded")

// Retry executes a function with retry logic
func Retry(ctx context.Context, config RetryConfig, fn func() error) error {
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = 1
	}

	var lastErr error
	delay := config.InitialDelay

	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Execute function
		err := fn()
		if err == nil {
			if attempt > 0 {
				logrus.Debugf("Operation succeeded after %d retries", attempt)
			}
			return nil
		}

		lastErr = err

		// Check if error is retryable
		if config.RetryableErrors != nil && !config.RetryableErrors(err) {
			logrus.Debugf("Error is not retryable: %v", err)
			return err
		}

		// Don't sleep after last attempt
		if attempt < config.MaxAttempts-1 {
			logrus.Debugf("Retry attempt %d/%d after %v (error: %v)", attempt+1, config.MaxAttempts, delay, err)

			// Wait with exponential backoff
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}

			// Calculate next delay
			delay = time.Duration(float64(delay) * config.Backoff)
			if delay > config.MaxDelay {
				delay = config.MaxDelay
			}
		}
	}

	return errors.Wrapf(ErrMaxRetriesExceeded, "last error: %v", lastErr)
}

// RetryWithResult executes a function with retry logic and returns a result
//
//nolint:revive // stuttering name is intentional for public API clarity
func RetryWithResult[T any](ctx context.Context, config RetryConfig, fn func() (T, error)) (T, error) {
	var zero T
	if config.MaxAttempts <= 0 {
		config.MaxAttempts = 1
	}

	var lastErr error
	delay := config.InitialDelay

	for attempt := 0; attempt < config.MaxAttempts; attempt++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		default:
		}

		// Execute function
		result, err := fn()
		if err == nil {
			if attempt > 0 {
				logrus.Debugf("Operation succeeded after %d retries", attempt)
			}
			return result, nil
		}

		lastErr = err

		// Check if error is retryable
		if config.RetryableErrors != nil && !config.RetryableErrors(err) {
			logrus.Debugf("Error is not retryable: %v", err)
			return zero, err
		}

		// Don't sleep after last attempt
		if attempt < config.MaxAttempts-1 {
			logrus.Debugf("Retry attempt %d/%d after %v (error: %v)", attempt+1, config.MaxAttempts, delay, err)

			// Wait with exponential backoff
			select {
			case <-ctx.Done():
				return zero, ctx.Err()
			case <-time.After(delay):
			}

			// Calculate next delay
			delay = time.Duration(float64(delay) * config.Backoff)
			if delay > config.MaxDelay {
				delay = config.MaxDelay
			}
		}
	}

	return zero, errors.Wrapf(ErrMaxRetriesExceeded, "last error: %v", lastErr)
}

// IsRetryableError checks if an error is retryable
func IsRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Network errors are typically retryable
	errStr := err.Error()
	retryablePatterns := []string{
		"timeout",
		"connection",
		"network",
		"temporary",
		"unavailable",
		"rate limit",
		"too many requests",
	}

	for _, pattern := range retryablePatterns {
		if contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	if substr == "" {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	// Simple case-insensitive contains
	sLower := toLower(s)
	substrLower := toLower(substr)
	for i := 0; i <= len(sLower)-len(substrLower); i++ {
		if sLower[i:i+len(substrLower)] == substrLower {
			return true
		}
	}
	return false
}

// toLower converts string to lowercase (simple implementation)
func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		result[i] = c
	}
	return string(result)
}

// RetryConfigBuilder helps build retry configurations
//
//nolint:revive // stuttering name is intentional for public API clarity
type RetryConfigBuilder struct {
	config RetryConfig
}

// NewRetryConfigBuilder creates a new retry config builder
func NewRetryConfigBuilder() *RetryConfigBuilder {
	return &RetryConfigBuilder{
		config: DefaultRetryConfig(),
	}
}

// WithMaxAttempts sets the maximum number of attempts
func (b *RetryConfigBuilder) WithMaxAttempts(attempts int) *RetryConfigBuilder {
	b.config.MaxAttempts = attempts
	return b
}

// WithInitialDelay sets the initial delay
func (b *RetryConfigBuilder) WithInitialDelay(delay time.Duration) *RetryConfigBuilder {
	b.config.InitialDelay = delay
	return b
}

// WithMaxDelay sets the maximum delay
func (b *RetryConfigBuilder) WithMaxDelay(delay time.Duration) *RetryConfigBuilder {
	b.config.MaxDelay = delay
	return b
}

// WithBackoff sets the backoff multiplier
func (b *RetryConfigBuilder) WithBackoff(backoff float64) *RetryConfigBuilder {
	b.config.Backoff = backoff
	return b
}

// WithRetryableErrors sets the retryable error function
func (b *RetryConfigBuilder) WithRetryableErrors(fn func(error) bool) *RetryConfigBuilder {
	b.config.RetryableErrors = fn
	return b
}

// Build builds the retry configuration
func (b *RetryConfigBuilder) Build() RetryConfig {
	return b.config
}

// String returns a string representation of the config
func (c RetryConfig) String() string {
	return fmt.Sprintf("RetryConfig(maxAttempts=%d, initialDelay=%v, maxDelay=%v, backoff=%.2f)",
		c.MaxAttempts, c.InitialDelay, c.MaxDelay, c.Backoff)
}
