/*
Copyright 2018 Google LLC

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

package errors

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestDefaultRetryConfig(t *testing.T) {
	config := DefaultRetryConfig()

	if config.MaxAttempts != defaultMaxAttempts {
		t.Errorf("Expected MaxAttempts=%d, got %d", defaultMaxAttempts, config.MaxAttempts)
	}

	if config.BaseDelay != defaultBaseDelay {
		t.Errorf("Expected BaseDelay=%v, got %v", defaultBaseDelay, config.BaseDelay)
	}

	if config.MaxDelay != defaultMaxDelay {
		t.Errorf("Expected MaxDelay=%v, got %v", defaultMaxDelay, config.MaxDelay)
	}

	if config.JitterFactor != defaultJitterFactor {
		t.Errorf("Expected JitterFactor=%v, got %v", defaultJitterFactor, config.JitterFactor)
	}

	if config.BackoffFactor != defaultBackoffFactor {
		t.Errorf("Expected BackoffFactor=%v, got %v", defaultBackoffFactor, config.BackoffFactor)
	}
}

func TestClassifyError_Nil(t *testing.T) {
	classified := ClassifyError(nil)
	if classified != nil {
		t.Error("ClassifyError(nil) should return nil")
	}
}

func TestClassifyError_Network(t *testing.T) {
	err := errors.New("network error")
	classified := ClassifyError(err)

	if classified == nil {
		t.Fatal("ClassifyError should not return nil for non-nil error")
	}

	if classified.Type != ErrorTypeNetwork {
		t.Errorf("Expected ErrorTypeNetwork, got %v", classified.Type)
	}

	if !classified.Retryable {
		t.Error("Network errors should be retryable")
	}
}

func TestClassifyError_Timeout(t *testing.T) {
	testCases := []string{
		"timeout error",
		"deadline exceeded",
		"context deadline exceeded",
	}

	for _, msg := range testCases {
		err := errors.New(msg)
		classified := ClassifyError(err)

		if classified.Type != ErrorTypeTimeout {
			t.Errorf("Expected ErrorTypeTimeout for %q, got %v", msg, classified.Type)
		}

		if !classified.Retryable {
			t.Errorf("Timeout errors should be retryable for %q", msg)
		}
	}
}

func TestClassifyError_RateLimit(t *testing.T) {
	testCases := []string{
		"rate limit exceeded",
		"429 too many requests",
		"too many requests",
	}

	for _, msg := range testCases {
		err := errors.New(msg)
		classified := ClassifyError(err)

		if classified.Type != ErrorTypeRateLimit {
			t.Errorf("Expected ErrorTypeRateLimit for %q, got %v", msg, classified.Type)
		}

		if !classified.Retryable {
			t.Errorf("Rate limit errors should be retryable for %q", msg)
		}
	}
}

func TestClassifyError_Auth(t *testing.T) {
	testCases := []string{
		"authentication failed",
		"unauthorized",
		"401 unauthorized",
		"credential error",
	}

	for _, msg := range testCases {
		err := errors.New(msg)
		classified := ClassifyError(err)

		if classified.Type != ErrorTypeAuth {
			t.Errorf("Expected ErrorTypeAuth for %q, got %v", msg, classified.Type)
		}

		if classified.Retryable {
			t.Errorf("Auth errors should not be retryable for %q", msg)
		}
	}
}

func TestClassifyError_Permission(t *testing.T) {
	testCases := []string{
		"permission denied",
		"403 forbidden",
		"forbidden",
	}

	for _, msg := range testCases {
		err := errors.New(msg)
		classified := ClassifyError(err)

		if classified.Type != ErrorTypePermission {
			t.Errorf("Expected ErrorTypePermission for %q, got %v", msg, classified.Type)
		}

		if classified.Retryable {
			t.Errorf("Permission errors should not be retryable for %q", msg)
		}
	}
}

func TestClassifyError_NotFound(t *testing.T) {
	testCases := []string{
		"not found",
		"404 not found",
		"no such file",
	}

	for _, msg := range testCases {
		err := errors.New(msg)
		classified := ClassifyError(err)

		if classified.Type != ErrorTypeNotFound {
			t.Errorf("Expected ErrorTypeNotFound for %q, got %v", msg, classified.Type)
		}

		if classified.Retryable {
			t.Errorf("NotFound errors should not be retryable for %q", msg)
		}
	}
}

func TestClassifyError_IO(t *testing.T) {
	testCases := []string{
		"io error",
		"file error",
		"disk full",
		"no space left",
	}

	for _, msg := range testCases {
		err := errors.New(msg)
		classified := ClassifyError(err)

		if classified.Type != ErrorTypeIO {
			t.Errorf("Expected ErrorTypeIO for %q, got %v", msg, classified.Type)
		}
	}
}

func TestClassifiedError_Error(t *testing.T) {
	err := errors.New("test error")
	classified := &ClassifiedError{
		error:     err,
		Type:      ErrorTypeNetwork,
		Retryable: true,
	}

	errorMsg := classified.Error()
	if !strings.Contains(errorMsg, "[network]") {
		t.Errorf("Error message should contain error type, got %q", errorMsg)
	}

	if !strings.Contains(errorMsg, "test error") {
		t.Errorf("Error message should contain original error, got %q", errorMsg)
	}
}

func TestClassifiedError_Unwrap(t *testing.T) {
	originalErr := errors.New("original error")
	classified := &ClassifiedError{
		error: originalErr,
	}

	unwrapped := classified.Unwrap()
	if unwrapped != originalErr {
		t.Error("Unwrap() should return the original error")
	}
}

func TestWithRetry_Success(t *testing.T) {
	ctx := context.Background()
	config := DefaultRetryConfig()

	attempts := 0
	err := WithRetry(ctx, config, func() error {
		attempts++
		return nil
	})

	if err != nil {
		t.Errorf("WithRetry should not return error on success, got %v", err)
	}

	if attempts != 1 {
		t.Errorf("Expected 1 attempt, got %d", attempts)
	}
}

func TestWithRetry_RetryableError(t *testing.T) {
	ctx := context.Background()
	config := RetryConfig{
		MaxAttempts:   3,
		BaseDelay:     10 * time.Millisecond,
		MaxDelay:      100 * time.Millisecond,
		JitterFactor:  0.1,
		BackoffFactor: 2.0,
	}

	attempts := 0
	err := WithRetry(ctx, config, func() error {
		attempts++
		if attempts < 3 {
			return errors.New("network error")
		}
		return nil
	})

	if err != nil {
		t.Errorf("WithRetry should succeed after retries, got %v", err)
	}

	if attempts != 3 {
		t.Errorf("Expected 3 attempts, got %d", attempts)
	}
}

func TestWithRetry_NonRetryableError(t *testing.T) {
	ctx := context.Background()
	config := RetryConfig{
		MaxAttempts:   3,
		BaseDelay:     10 * time.Millisecond,
		MaxDelay:      100 * time.Millisecond,
		JitterFactor:  0.1,
		BackoffFactor: 2.0,
	}

	attempts := 0
	err := WithRetry(ctx, config, func() error {
		attempts++
		return errors.New("authentication failed")
	})

	if err == nil {
		t.Error("WithRetry should return error for non-retryable errors")
	}

	if attempts != 1 {
		t.Errorf("Expected 1 attempt for non-retryable error, got %d", attempts)
	}
}

func TestWithRetry_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	config := RetryConfig{
		MaxAttempts:   5,
		BaseDelay:     50 * time.Millisecond,
		MaxDelay:      200 * time.Millisecond,
		JitterFactor:  0.1,
		BackoffFactor: 2.0,
	}

	attempts := 0
	cancel() // Cancel immediately

	err := WithRetry(ctx, config, func() error {
		attempts++
		return errors.New("network error")
	})

	if err == nil {
		t.Error("WithRetry should return error when context is cancelled")
	}

	if !strings.Contains(err.Error(), "canceled") {
		t.Errorf("Error should mention cancellation, got %v", err)
	}
}

func TestIsRetryableError(t *testing.T) {
	testCases := []struct {
		err       error
		retryable bool
	}{
		{errors.New("network error"), true},
		{errors.New("timeout"), true},
		{errors.New("authentication failed"), false},
		{errors.New("permission denied"), false},
		{errors.New("not found"), false},
		{errors.New("unknown error"), false},
	}

	for _, tc := range testCases {
		result := IsRetryableError(tc.err)
		if result != tc.retryable {
			t.Errorf("IsRetryableError(%q) = %v, expected %v", tc.err.Error(), result, tc.retryable)
		}
	}
}

func TestWithContext(t *testing.T) {
	err := errors.New("test error")
	classified := WithContext(err, "key", "value")

	if classified == nil {
		t.Fatal("WithContext should not return nil")
	}

	ce, ok := classified.(*ClassifiedError)
	if !ok {
		t.Fatal("WithContext should return ClassifiedError")
	}

	if ce.Context["key"] != "value" {
		t.Errorf("Expected context key=value, got %v", ce.Context)
	}
}

func TestWithContext_Nil(t *testing.T) {
	result := WithContext(nil, "key", "value")
	if result != nil {
		t.Error("WithContext(nil) should return nil")
	}
}

func TestWrapf(t *testing.T) {
	err := errors.New("original error")
	wrapped := Wrapf(err, "wrapped: %s", "test")

	if wrapped == nil {
		t.Fatal("Wrapf should not return nil")
	}

	errorMsg := wrapped.Error()
	if !strings.Contains(errorMsg, "wrapped: test") {
		t.Errorf("Error message should contain wrapped message, got %q", errorMsg)
	}
}

func TestWrapf_Nil(t *testing.T) {
	result := Wrapf(nil, "format: %s", "test")
	if result != nil {
		t.Error("Wrapf(nil) should return nil")
	}
}

func TestNew(t *testing.T) {
	err := New(ErrorTypeNetwork, "test error")

	if err == nil {
		t.Fatal("New should not return nil")
	}

	ce, ok := err.(*ClassifiedError)
	if !ok {
		t.Fatal("New should return ClassifiedError")
	}

	if ce.Type != ErrorTypeNetwork {
		t.Errorf("Expected ErrorTypeNetwork, got %v", ce.Type)
	}

	if !ce.Retryable {
		t.Error("Network errors should be retryable")
	}
}

func TestClassifyHTTPError(t *testing.T) {
	testCases := []struct {
		statusCode int
		errorType  ErrorType
		retryable  bool
	}{
		{0, ErrorTypeNetwork, true},
		{429, ErrorTypeRateLimit, true},
		{408, ErrorTypeTimeout, true},
		{500, ErrorTypeNetwork, true},
		{401, ErrorTypeAuth, false},
		{403, ErrorTypePermission, false},
		{404, ErrorTypeNotFound, false},
		{200, ErrorTypeUnknown, false},
	}

	for _, tc := range testCases {
		err := ClassifyHTTPError(tc.statusCode, "test message")

		ce, ok := err.(*ClassifiedError)
		if !ok {
			t.Fatalf("ClassifyHTTPError should return ClassifiedError for status %d", tc.statusCode)
		}

		if ce.Type != tc.errorType {
			t.Errorf("Expected %v for status %d, got %v", tc.errorType, tc.statusCode, ce.Type)
		}

		if ce.Retryable != tc.retryable {
			t.Errorf("Expected retryable=%v for status %d, got %v", tc.retryable, tc.statusCode, ce.Retryable)
		}
	}
}

func TestRetryWithBackoff(t *testing.T) {
	ctx := context.Background()

	attempts := 0
	err := RetryWithBackoff(ctx, func() error {
		attempts++
		if attempts < 2 {
			return errors.New("network error")
		}
		return nil
	})

	if err != nil {
		t.Errorf("RetryWithBackoff should succeed, got %v", err)
	}

	if attempts != 2 {
		t.Errorf("Expected 2 attempts, got %d", attempts)
	}
}

func TestRetryWithBackoff_WithOptions(t *testing.T) {
	ctx := context.Background()

	attempts := 0
	err := RetryWithBackoff(ctx, func() error {
		attempts++
		if attempts < 2 {
			return errors.New("network error")
		}
		return nil
	}, WithMaxAttempts(5), WithBaseDelay(10*time.Millisecond))

	if err != nil {
		t.Errorf("RetryWithBackoff should succeed, got %v", err)
	}

	if attempts != 2 {
		t.Errorf("Expected 2 attempts, got %d", attempts)
	}
}

func TestCalculateDelay(t *testing.T) {
	config := RetryConfig{
		BaseDelay:     100 * time.Millisecond,
		MaxDelay:      1 * time.Second,
		JitterFactor:  0.1,
		BackoffFactor: 2.0,
	}

	// Test first attempt (should be 0)
	delay := calculateDelay(config, 0)
	if delay != 0 {
		t.Errorf("Expected delay=0 for attempt 0, got %v", delay)
	}

	// Test exponential backoff
	delay1 := calculateDelay(config, 1)
	delay2 := calculateDelay(config, 2)

	if delay2 <= delay1 {
		t.Errorf("Delay should increase with attempts: delay1=%v, delay2=%v", delay1, delay2)
	}

	// Test max delay cap (with jitter, delay can slightly exceed MaxDelay)
	config.MaxAttempts = 10
	delayLarge := calculateDelay(config, 10)
	// Jitter can add up to JitterFactor * MaxDelay, so allow some margin
	maxAllowedDelay := config.MaxDelay + time.Duration(float64(config.MaxDelay)*config.JitterFactor)
	if delayLarge > maxAllowedDelay {
		t.Errorf("Delay should not exceed MaxDelay + jitter: %v > %v", delayLarge, maxAllowedDelay)
	}
}

func TestIsTypeRetryable(t *testing.T) {
	testCases := []struct {
		errorType ErrorType
		retryable bool
	}{
		{ErrorTypeNetwork, true},
		{ErrorTypeTimeout, true},
		{ErrorTypeConnection, true},
		{ErrorTypeRateLimit, true},
		{ErrorTypeIO, true},
		{ErrorTypeAuth, false},
		{ErrorTypePermission, false},
		{ErrorTypeNotFound, false},
		{ErrorTypeBuild, false},
		{ErrorTypeConfig, false},
		{ErrorTypeValidation, false},
		{ErrorTypeUnknown, false},
	}

	for _, tc := range testCases {
		result := isTypeRetryable(tc.errorType)
		if result != tc.retryable {
			t.Errorf("isTypeRetryable(%v) = %v, expected %v", tc.errorType, result, tc.retryable)
		}
	}
}

func TestClassifyHTTPError_StatusCodes(t *testing.T) {
	// Test all HTTP status code classifications
	statusCodes := []struct {
		code      int
		errorType ErrorType
		retryable bool
	}{
		{http.StatusTooManyRequests, ErrorTypeRateLimit, true},
		{http.StatusRequestTimeout, ErrorTypeTimeout, true},
		{http.StatusInternalServerError, ErrorTypeNetwork, true},
		{http.StatusBadGateway, ErrorTypeNetwork, true},
		{http.StatusServiceUnavailable, ErrorTypeNetwork, true},
		{http.StatusUnauthorized, ErrorTypeAuth, false},
		{http.StatusForbidden, ErrorTypePermission, false},
		{http.StatusNotFound, ErrorTypeNotFound, false},
	}

	for _, tc := range statusCodes {
		err := ClassifyHTTPError(tc.code, "test")
		ce := err.(*ClassifiedError)

		if ce.Type != tc.errorType {
			t.Errorf("Status %d: expected %v, got %v", tc.code, tc.errorType, ce.Type)
		}

		if ce.Retryable != tc.retryable {
			t.Errorf("Status %d: expected retryable=%v, got %v", tc.code, tc.retryable, ce.Retryable)
		}
	}
}
