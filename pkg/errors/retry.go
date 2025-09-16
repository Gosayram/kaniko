/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package errors provides enhanced error handling with retry logic and error classification.
package errors

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// RetryConfig configuration for retry operations.
type RetryConfig struct {
	MaxAttempts   int
	BaseDelay     time.Duration
	MaxDelay      time.Duration
	JitterFactor  float64
	BackoffFactor float64
}

// Default retry configuration constants
const (
	defaultMaxAttempts   = 5
	defaultBaseDelay     = 100 * time.Millisecond
	defaultMaxDelay      = 30 * time.Second
	defaultJitterFactor  = 0.2
	defaultBackoffFactor = 2.0
)

// DefaultRetryConfig returns a sensible default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:   defaultMaxAttempts,
		BaseDelay:     defaultBaseDelay,
		MaxDelay:      defaultMaxDelay,
		JitterFactor:  defaultJitterFactor,
		BackoffFactor: defaultBackoffFactor,
	}
}

// ErrorType classifies errors for better handling and metrics.
type ErrorType string

const (
	// ErrorTypeNetwork represents network-related errors (retryable)
	ErrorTypeNetwork ErrorType = "network"
	// ErrorTypeTimeout represents timeout-related errors (retryable)
	ErrorTypeTimeout ErrorType = "timeout"
	// ErrorTypeConnection represents connection-related errors (retryable)
	ErrorTypeConnection ErrorType = "connection"

	// ErrorTypeRateLimit represents rate limit errors from registries (retryable)
	ErrorTypeRateLimit ErrorType = "rate_limit"
	// ErrorTypeAuth represents authentication errors (not retryable)
	ErrorTypeAuth ErrorType = "authentication"
	// ErrorTypePermission represents permission errors (not retryable)
	ErrorTypePermission ErrorType = "permission"
	// ErrorTypeNotFound represents resource not found errors (not retryable)
	ErrorTypeNotFound ErrorType = "not_found"

	// ErrorTypeBuild represents build-related errors (usually not retryable)
	ErrorTypeBuild ErrorType = "build"
	// ErrorTypeConfig represents configuration errors (not retryable)
	ErrorTypeConfig ErrorType = "configuration"
	// ErrorTypeValidation represents validation errors (not retryable)
	ErrorTypeValidation ErrorType = "validation"

	// ErrorTypeResource represents resource-related system errors (retryable)
	ErrorTypeResource ErrorType = "resource"
	// ErrorTypeIO represents I/O-related errors (some may be retryable)
	ErrorTypeIO ErrorType = "io"
	// ErrorTypeUnknown represents unknown error types
	ErrorTypeUnknown ErrorType = "unknown"
)

// ClassifiedError wraps an error with classification information.
type ClassifiedError struct {
	error
	Type      ErrorType
	Retryable bool
	Context   map[string]string
}

// Error returns the error message with classification info.
func (e *ClassifiedError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Type, e.error.Error())
}

// Unwrap returns the underlying error.
func (e *ClassifiedError) Unwrap() error {
	return e.error
}

// ClassifyError analyzes an error and returns a classified version.
func ClassifyError(err error) *ClassifiedError {
	if err == nil {
		return nil
	}

	classified := &ClassifiedError{
		error:   err,
		Type:    ErrorTypeUnknown,
		Context: make(map[string]string),
	}

	errorMsg := strings.ToLower(err.Error())

	// Check error types in order of priority
	if classifyNetworkError(errorMsg, classified) {
		return classified
	}
	if classifyTimeoutError(errorMsg, classified) {
		return classified
	}
	if classifyRateLimitError(errorMsg, classified) {
		return classified
	}
	if classifyAuthError(errorMsg, classified) {
		return classified
	}
	if classifyPermissionError(errorMsg, classified) {
		return classified
	}
	if classifyNotFoundError(errorMsg, classified) {
		return classified
	}
	if classifyIOError(errorMsg, classified) {
		return classified
	}

	return classified
}

// classifyNetworkError checks if the error is network-related
func classifyNetworkError(errorMsg string, classified *ClassifiedError) bool {
	if strings.Contains(errorMsg, "network") ||
		strings.Contains(errorMsg, "connection") ||
		strings.Contains(errorMsg, "socket") ||
		strings.Contains(errorMsg, "dial") {
		classified.Type = ErrorTypeNetwork
		classified.Retryable = true
		return true
	}
	return false
}

// classifyTimeoutError checks if the error is timeout-related
func classifyTimeoutError(errorMsg string, classified *ClassifiedError) bool {
	if strings.Contains(errorMsg, "timeout") ||
		strings.Contains(errorMsg, "deadline") ||
		strings.Contains(errorMsg, "context deadline") {
		classified.Type = ErrorTypeTimeout
		classified.Retryable = true
		return true
	}
	return false
}

// classifyRateLimitError checks if the error is rate limit-related
func classifyRateLimitError(errorMsg string, classified *ClassifiedError) bool {
	if strings.Contains(errorMsg, "rate limit") ||
		strings.Contains(errorMsg, "429") ||
		strings.Contains(errorMsg, "too many requests") {
		classified.Type = ErrorTypeRateLimit
		classified.Retryable = true
		return true
	}
	return false
}

// classifyAuthError checks if the error is authentication-related
func classifyAuthError(errorMsg string, classified *ClassifiedError) bool {
	if strings.Contains(errorMsg, "auth") ||
		strings.Contains(errorMsg, "unauthorized") ||
		strings.Contains(errorMsg, "401") ||
		strings.Contains(errorMsg, "credential") {
		classified.Type = ErrorTypeAuth
		classified.Retryable = false
		return true
	}
	return false
}

// classifyPermissionError checks if the error is permission-related
func classifyPermissionError(errorMsg string, classified *ClassifiedError) bool {
	if strings.Contains(errorMsg, "permission") ||
		strings.Contains(errorMsg, "403") ||
		strings.Contains(errorMsg, "forbidden") {
		classified.Type = ErrorTypePermission
		classified.Retryable = false
		return true
	}
	return false
}

// classifyNotFoundError checks if the error is not found-related
func classifyNotFoundError(errorMsg string, classified *ClassifiedError) bool {
	if strings.Contains(errorMsg, "not found") ||
		strings.Contains(errorMsg, "404") ||
		strings.Contains(errorMsg, "no such") {
		classified.Type = ErrorTypeNotFound
		classified.Retryable = false
		return true
	}
	return false
}

// classifyIOError checks if the error is I/O-related
func classifyIOError(errorMsg string, classified *ClassifiedError) bool {
	if strings.Contains(errorMsg, "io") ||
		strings.Contains(errorMsg, "file") ||
		strings.Contains(errorMsg, "disk") ||
		strings.Contains(errorMsg, "space") {
		classified.Type = ErrorTypeIO
		classified.Retryable = true // Some IO errors might be temporary
		return true
	}
	return false
}

// WithRetry executes a function with retry logic based on error classification.
func WithRetry(ctx context.Context, config RetryConfig, operation func() error) error {
	start := time.Now()

	var lastErr error
	var attempt int

	for attempt = 0; attempt < config.MaxAttempts; attempt++ {
		if attempt > 0 {
			delay := calculateDelay(config, attempt)
			logrus.Infof("Retrying operation (attempt %d/%d, delay: %v)",
				attempt+1, config.MaxAttempts, delay)

			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return errors.Wrap(ctx.Err(), "operation canceled during retry")
			}
		}

		err := operation()
		if err == nil {
			return nil
		}

		lastErr = err
		classified := ClassifyError(err)

		if !classified.Retryable {
			logrus.Debugf("Non-retryable error: %s", classified.Error())
			break
		}

		logrus.Warnf("Retryable error (attempt %d/%d): %s",
			attempt+1, config.MaxAttempts, classified.Error())
	}

	duration := time.Since(start)
	_ = duration // avoid unused variable warning

	if lastErr != nil {
		return errors.Wrapf(lastErr, "operation failed after %d attempts (duration: %v)", attempt, duration)
	}

	return nil
}

// calculateDelay computes the delay for a retry attempt with jitter and backoff.
func calculateDelay(config RetryConfig, attempt int) time.Duration {
	if attempt == 0 {
		return 0
	}

	// Exponential backoff
	delay := config.BaseDelay * time.Duration(config.BackoffFactor*float64(attempt))
	if delay > config.MaxDelay {
		delay = config.MaxDelay
	}

	// Add jitter using crypto/rand for secure random number generation
	jitter, err := secureRandomFloat64()
	if err != nil {
		// Fallback to zero jitter if crypto random fails
		jitter = 0
	}
	jitterAmount := jitter * config.JitterFactor * float64(delay)
	delay += time.Duration(jitterAmount)

	return delay
}

// IsRetryableError checks if an error is classified as retryable.
func IsRetryableError(err error) bool {
	classified := ClassifyError(err)
	return classified.Retryable
}

// WithContext adds context information to an error.
func WithContext(err error, key, value string) error {
	if err == nil {
		return nil
	}

	classified := ClassifyError(err)
	classified.Context[key] = value
	return classified
}

// Wrapf wraps an error with classification and formatting.
func Wrapf(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}

	classified := ClassifyError(err)
	wrapped := errors.Wrapf(err, format, args...)
	classified.error = wrapped
	return classified
}

// New creates a new classified error.
func New(errorType ErrorType, message string) error {
	return &ClassifiedError{
		error:     errors.New(message),
		Type:      errorType,
		Retryable: isTypeRetryable(errorType),
		Context:   make(map[string]string),
	}
}

// isTypeRetryable determines if an error type is generally retryable.
func isTypeRetryable(errorType ErrorType) bool {
	switch errorType {
	case ErrorTypeNetwork, ErrorTypeTimeout, ErrorTypeConnection, ErrorTypeRateLimit:
		return true
	case ErrorTypeIO: // Some IO errors might be retryable
		return true
	default:
		return false
	}
}

// ClassifyHTTPError classifies HTTP errors based on status code.
func ClassifyHTTPError(statusCode int, message string) error {
	var errorType ErrorType
	var retryable bool

	switch {
	case statusCode == 0:
		errorType = ErrorTypeNetwork
		retryable = true
	case statusCode == http.StatusTooManyRequests || statusCode == 429:
		errorType = ErrorTypeRateLimit
		retryable = true
	case statusCode == http.StatusRequestTimeout || statusCode == 408:
		errorType = ErrorTypeTimeout
		retryable = true
	case statusCode >= http.StatusInternalServerError:
		errorType = ErrorTypeNetwork // Server errors
		retryable = true
	case statusCode == http.StatusUnauthorized || statusCode == 401:
		errorType = ErrorTypeAuth
		retryable = false
	case statusCode == http.StatusForbidden || statusCode == 403:
		errorType = ErrorTypePermission
		retryable = false
	case statusCode == http.StatusNotFound || statusCode == 404:
		errorType = ErrorTypeNotFound
		retryable = false
	default:
		errorType = ErrorTypeUnknown
		retryable = false
	}

	return &ClassifiedError{
		error:     fmt.Errorf("HTTP %d: %s", statusCode, message),
		Type:      errorType,
		Retryable: retryable,
		Context:   map[string]string{"status_code": fmt.Sprintf("%d", statusCode)},
	}
}

// RetryWithBackoff executes a function with exponential backoff retry.
func RetryWithBackoff(ctx context.Context, operation func() error, opts ...func(*RetryConfig)) error {
	config := DefaultRetryConfig()
	for _, opt := range opts {
		opt(&config)
	}

	return WithRetry(ctx, config, operation)
}

// WithMaxAttempts sets the maximum number of retry attempts.
func WithMaxAttempts(attempts int) func(*RetryConfig) {
	return func(c *RetryConfig) {
		c.MaxAttempts = attempts
	}
}

// WithBaseDelay sets the base delay for retries.
func WithBaseDelay(delay time.Duration) func(*RetryConfig) {
	return func(c *RetryConfig) {
		c.BaseDelay = delay
	}
}

// WithMaxDelay sets the maximum delay between retries.
func WithMaxDelay(delay time.Duration) func(*RetryConfig) {
	return func(c *RetryConfig) {
		c.MaxDelay = delay
	}
}

// secureRandomFloat64 generates a cryptographically secure random float64 between 0 and 1
func secureRandomFloat64() (float64, error) {
	var buf [8]byte
	_, err := rand.Read(buf[:])
	if err != nil {
		return 0, err
	}

	// Convert the random bytes to a uint64
	randomUint := binary.BigEndian.Uint64(buf[:])

	// Convert to float64 in range [0, 1)
	// We use 2^53-1 as the maximum value to avoid precision issues
	const maxUint53 = 1<<53 - 1
	return float64(randomUint&maxUint53) / float64(maxUint53), nil
}
