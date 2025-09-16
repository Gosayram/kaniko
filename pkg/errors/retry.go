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
	"fmt"
	"math/rand"
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

// DefaultRetryConfig returns a sensible default retry configuration.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:   5,
		BaseDelay:     100 * time.Millisecond,
		MaxDelay:      30 * time.Second,
		JitterFactor:  0.2,
		BackoffFactor: 2.0,
	}
}

// ErrorType classifies errors for better handling and metrics.
type ErrorType string

const (
	// Network errors (retryable)
	ErrorTypeNetwork    ErrorType = "network"
	ErrorTypeTimeout    ErrorType = "timeout"
	ErrorTypeConnection ErrorType = "connection"

	// Registry errors
	ErrorTypeRateLimit  ErrorType = "rate_limit"
	ErrorTypeAuth       ErrorType = "authentication"
	ErrorTypePermission ErrorType = "permission"
	ErrorTypeNotFound   ErrorType = "not_found"

	// Build errors (usually not retryable)
	ErrorTypeBuild      ErrorType = "build"
	ErrorTypeConfig     ErrorType = "configuration"
	ErrorTypeValidation ErrorType = "validation"

	// System errors
	ErrorTypeResource ErrorType = "resource"
	ErrorTypeIO       ErrorType = "io"
	ErrorTypeUnknown  ErrorType = "unknown"
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

	// Network-related errors
	if strings.Contains(errorMsg, "network") ||
		strings.Contains(errorMsg, "connection") ||
		strings.Contains(errorMsg, "socket") ||
		strings.Contains(errorMsg, "dial") {
		classified.Type = ErrorTypeNetwork
		classified.Retryable = true
		return classified
	}

	// Timeout errors
	if strings.Contains(errorMsg, "timeout") ||
		strings.Contains(errorMsg, "deadline") ||
		strings.Contains(errorMsg, "context deadline") {
		classified.Type = ErrorTypeTimeout
		classified.Retryable = true
		return classified
	}

	// Rate limiting
	if strings.Contains(errorMsg, "rate limit") ||
		strings.Contains(errorMsg, "429") ||
		strings.Contains(errorMsg, "too many requests") {
		classified.Type = ErrorTypeRateLimit
		classified.Retryable = true
		return classified
	}

	// Authentication errors
	if strings.Contains(errorMsg, "auth") ||
		strings.Contains(errorMsg, "unauthorized") ||
		strings.Contains(errorMsg, "401") ||
		strings.Contains(errorMsg, "credential") {
		classified.Type = ErrorTypeAuth
		classified.Retryable = false
		return classified
	}

	// Permission errors
	if strings.Contains(errorMsg, "permission") ||
		strings.Contains(errorMsg, "403") ||
		strings.Contains(errorMsg, "forbidden") {
		classified.Type = ErrorTypePermission
		classified.Retryable = false
		return classified
	}

	// Not found errors
	if strings.Contains(errorMsg, "not found") ||
		strings.Contains(errorMsg, "404") ||
		strings.Contains(errorMsg, "no such") {
		classified.Type = ErrorTypeNotFound
		classified.Retryable = false
		return classified
	}

	// I/O errors
	if strings.Contains(errorMsg, "io") ||
		strings.Contains(errorMsg, "file") ||
		strings.Contains(errorMsg, "disk") ||
		strings.Contains(errorMsg, "space") {
		classified.Type = ErrorTypeIO
		classified.Retryable = true // Some IO errors might be temporary
		return classified
	}

	return classified
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
				return errors.Wrap(ctx.Err(), "operation cancelled during retry")
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

	// Add jitter
	jitter := rand.Float64() * config.JitterFactor * float64(delay)
	delay = delay + time.Duration(jitter)

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
	case statusCode >= 500:
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
