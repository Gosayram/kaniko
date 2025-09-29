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

// Package retry provides intelligent retry mechanisms for handling transient failures
package retry

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Gosayram/kaniko/pkg/debug"
)

const (
	// UnknownOperation represents an unknown operation name
	UnknownOperation = "unknown"
	// UnknownRegistry represents an unknown registry name
	UnknownRegistry = "unknown"
	// UnknownPlatform represents an unknown platform name
	UnknownPlatform = "unknown"
	// DefaultMaxAttempts is the default maximum number of retry attempts
	DefaultMaxAttempts = 3
	// DefaultInitialDelay is the default initial delay for retries
	DefaultInitialDelay = 1 * time.Second
	// DefaultMaxDelay is the default maximum delay for retries
	DefaultMaxDelay = 60 * time.Second
	// DefaultBaseMultiplier is the default base multiplier for exponential backoff
	DefaultBaseMultiplier = 2.0
	// NetworkMaxAttempts is the maximum number of attempts for network errors
	NetworkMaxAttempts = 5
	// NetworkInitialDelay is the initial delay for network errors
	NetworkInitialDelay = 500 * time.Millisecond
	// NetworkMaxDelay is the maximum delay for network errors
	NetworkMaxDelay = 30 * time.Second
	// NetworkBaseMultiplier is the base multiplier for network errors
	NetworkBaseMultiplier = 1.5
	// RegistryMaxAttempts is the maximum number of attempts for registry errors
	RegistryMaxAttempts = 4
	// RegistryInitialDelay is the initial delay for registry errors
	RegistryInitialDelay = 2 * time.Second
	// RegistryMaxDelay is the maximum delay for registry errors
	RegistryMaxDelay = 120 * time.Second
	// RegistryBaseMultiplier is the base multiplier for registry errors
	RegistryBaseMultiplier = 2.5
	// RateLimitMaxAttempts is the maximum number of attempts for rate limiting errors
	RateLimitMaxAttempts = 6
	// RateLimitInitialDelay is the initial delay for rate limiting errors
	RateLimitInitialDelay = 5 * time.Second
	// RateLimitMaxDelay is the maximum delay for rate limiting errors
	RateLimitMaxDelay = 300 * time.Second
	// RateLimitBaseMultiplier is the base multiplier for rate limiting errors (golden ratio)
	RateLimitBaseMultiplier = 1.618
	// AuthMaxAttempts is the maximum number of attempts for authentication errors
	AuthMaxAttempts = 2
	// AuthInitialDelay is the initial delay for authentication errors
	AuthInitialDelay = 1 * time.Second
	// AuthMaxDelay is the maximum delay for authentication errors
	AuthMaxDelay = 10 * time.Second
	// AuthBaseMultiplier is the base multiplier for authentication errors
	AuthBaseMultiplier = 1.0
	// TimeoutMaxAttempts is the maximum number of attempts for timeout errors
	TimeoutMaxAttempts = 3
	// TimeoutInitialDelay is the initial delay for timeout errors
	TimeoutInitialDelay = 1 * time.Second
	// TimeoutMaxDelay is the maximum delay for timeout errors
	TimeoutMaxDelay = 30 * time.Second
	// TimeoutBaseMultiplier is the base multiplier for timeout errors
	TimeoutBaseMultiplier = 2.0
	// RecentSuccessMinutes is the time window for considering recent success
	RecentSuccessMinutes = 5
	// HighFailureThreshold is the threshold for high failure rate
	HighFailureThreshold = 5
	// MaxTimeoutAttempts is the maximum number of attempts when timeout patterns are detected
	MaxTimeoutAttempts = 6
	// LowSeverityMaxAttempts is the maximum number of attempts for low severity errors
	LowSeverityMaxAttempts = 8
	// JitterMinMultiplier is the minimum jitter multiplier
	JitterMinMultiplier = 0.5
	// JitterMaxMultiplier is the maximum jitter multiplier
	JitterMaxMultiplier = 1.0
	// JitterPercentage is the percentage of delay to use for jitter
	JitterPercentage = 0.5
	// FibonacciCap is the cap for fibonacci sequence to prevent overflow
	FibonacciCap = 1000
	// CommonErrorsLimit is the limit for common errors to keep
	CommonErrorsLimit = 10

	// SuccessDelayMultiplier is the multiplier for success delay
	SuccessDelayMultiplier = 0.5
	// SuccessMaxDelayMultiplier is the multiplier for success max delay
	SuccessMaxDelayMultiplier = 0.8
	// TimeoutAttemptsMultiplier is the multiplier for timeout attempts
	TimeoutAttemptsMultiplier = 1.5
	// CriticalDelayMultiplier is the multiplier for critical delay
	CriticalDelayMultiplier = 2.0
	// CriticalMaxDelayMultiplier is the multiplier for critical max delay
	CriticalMaxDelayMultiplier = 1.5
	// HighDelayMultiplier is the multiplier for high delay
	HighDelayMultiplier = 1.5
	// LowDelayMultiplier is the multiplier for low delay
	LowDelayMultiplier = 0.7
	// ConnectionRefusedAttempts is the number of attempts for connection refused errors
	ConnectionRefusedAttempts = 2
	// RandomDivisor is the divisor for random number generation
	RandomDivisor = 1000
	// FibonacciCapValue is the cap value for fibonacci sequence
	FibonacciCapValue = 1000
	// AverageLatencyDivisor is divisor for average latency calculation
	AverageLatencyDivisor = 2
)

// ErrorClassifier classifies different types of errors
type ErrorClassifier struct {
	classification map[string]ErrorType
}

// ErrorType represents the type of error
type ErrorType int

const (
	// ErrorTypeUnknown represents an unknown error type
	ErrorTypeUnknown ErrorType = iota
	// ErrorTypeNetwork represents network-related errors
	ErrorTypeNetwork
	// ErrorTypeRegistry represents registry-related errors
	ErrorTypeRegistry
	// ErrorTypeRateLimit represents rate limiting errors
	ErrorTypeRateLimit
	// ErrorTypeAuthentication represents authentication errors
	ErrorTypeAuthentication
	// ErrorTypeTimeout represents timeout errors
	ErrorTypeTimeout
	// ErrorTypeResourceExhaustion represents resource exhaustion errors
	ErrorTypeResourceExhaustion
	// ErrorTypeTemporary represents temporary errors
	ErrorTypeTemporary
	// ErrorTypePermanent represents permanent errors
	ErrorTypePermanent
)

// ErrorClassification contains classification information for an error
type ErrorClassification struct {
	Type        ErrorType `json:"type"`
	IsRetryable bool      `json:"isRetryable"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
}

// ContextAnalyzer analyzes the context of operations
type ContextAnalyzer struct {
	mu      sync.RWMutex
	history map[string]*OperationContext
}

// OperationContext contains context information about an operation
type OperationContext struct {
	Operation      string        `json:"operation"`
	Registry       string        `json:"registry"`
	Platform       string        `json:"platform"`
	AttemptCount   int           `json:"attemptCount"`
	SuccessCount   int           `json:"successCount"`
	FailureCount   int           `json:"failureCount"`
	LastAttempt    time.Time     `json:"lastAttempt"`
	LastSuccess    time.Time     `json:"lastSuccess"`
	LastFailure    time.Time     `json:"lastFailure"`
	CommonErrors   []string      `json:"commonErrors"`
	AverageLatency time.Duration `json:"averageLatency"`
}

// StrategySelector selects the optimal retry strategy
type StrategySelector struct {
	mu         sync.RWMutex
	strategies map[string]*Strategy
}

// Strategy defines retry behavior for different scenarios
type Strategy struct {
	BackoffAlgorithm string        `json:"backoffAlgorithm"`
	MaxAttempts      int           `json:"maxAttempts"`
	InitialDelay     time.Duration `json:"initialDelay"`
	MaxDelay         time.Duration `json:"maxDelay"`
	Jitter           bool          `json:"jitter"`
	ContextAware     bool          `json:"contextAware"`
	Adaptive         bool          `json:"adaptive"`
	BaseMultiplier   float64       `json:"baseMultiplier"`
}

// IntelligentRetry manages intelligent retry logic
type IntelligentRetry struct {
	errorClassifier  *ErrorClassifier
	contextAnalyzer  *ContextAnalyzer
	strategySelector *StrategySelector
}

// NewIntelligentRetry creates a new intelligent retry instance
func NewIntelligentRetry() *IntelligentRetry {
	ir := &IntelligentRetry{
		errorClassifier:  NewErrorClassifier(),
		contextAnalyzer:  NewContextAnalyzer(),
		strategySelector: NewStrategySelector(),
	}

	// Initialize with default strategies
	ir.initializeDefaultStrategies()

	return ir
}

// NewErrorClassifier creates a new error classifier
func NewErrorClassifier() *ErrorClassifier {
	return &ErrorClassifier{
		classification: make(map[string]ErrorType),
	}
}

// NewContextAnalyzer creates a new context analyzer
func NewContextAnalyzer() *ContextAnalyzer {
	return &ContextAnalyzer{
		history: make(map[string]*OperationContext),
	}
}

// NewStrategySelector creates a new strategy selector
func NewStrategySelector() *StrategySelector {
	return &StrategySelector{
		strategies: make(map[string]*Strategy),
	}
}

// initializeDefaultStrategies initializes default retry strategies
func (ir *IntelligentRetry) initializeDefaultStrategies() {
	strategies := map[string]*Strategy{
		"default": {
			BackoffAlgorithm: "exponential",
			MaxAttempts:      DefaultMaxAttempts,
			InitialDelay:     DefaultInitialDelay,
			MaxDelay:         DefaultMaxDelay,
			Jitter:           true,
			ContextAware:     true,
			Adaptive:         true,
			BaseMultiplier:   DefaultBaseMultiplier,
		},
		"network": {
			BackoffAlgorithm: "exponential",
			MaxAttempts:      NetworkMaxAttempts,
			InitialDelay:     NetworkInitialDelay,
			MaxDelay:         NetworkMaxDelay,
			Jitter:           true,
			ContextAware:     true,
			Adaptive:         true,
			BaseMultiplier:   NetworkBaseMultiplier,
		},
		"registry": {
			BackoffAlgorithm: "exponential",
			MaxAttempts:      RegistryMaxAttempts,
			InitialDelay:     RegistryInitialDelay,
			MaxDelay:         RegistryMaxDelay,
			Jitter:           true,
			ContextAware:     true,
			Adaptive:         true,
			BaseMultiplier:   RegistryBaseMultiplier,
		},
		"rate-limit": {
			BackoffAlgorithm: "fibonacci",
			MaxAttempts:      RateLimitMaxAttempts,
			InitialDelay:     RateLimitInitialDelay,
			MaxDelay:         RateLimitMaxDelay,
			Jitter:           true,
			ContextAware:     true,
			Adaptive:         true,
			BaseMultiplier:   RateLimitBaseMultiplier,
		},
		"authentication": {
			BackoffAlgorithm: "linear",
			MaxAttempts:      AuthMaxAttempts,
			InitialDelay:     AuthInitialDelay,
			MaxDelay:         AuthMaxDelay,
			Jitter:           false,
			ContextAware:     false,
			Adaptive:         false,
			BaseMultiplier:   AuthBaseMultiplier,
		},
		"timeout": {
			BackoffAlgorithm: "exponential",
			MaxAttempts:      TimeoutMaxAttempts,
			InitialDelay:     TimeoutInitialDelay,
			MaxDelay:         TimeoutMaxDelay,
			Jitter:           true,
			ContextAware:     true,
			Adaptive:         true,
			BaseMultiplier:   TimeoutBaseMultiplier,
		},
	}

	ir.strategySelector.mu.Lock()
	defer ir.strategySelector.mu.Unlock()

	for name, strategy := range strategies {
		ir.strategySelector.strategies[name] = strategy
	}

	debug.LogComponent("retry", "Initialized %d default retry strategies", len(strategies))
}

// ClassifyError classifies an error and determines if it's retryable
func (ec *ErrorClassifier) ClassifyError(err error) ErrorClassification {
	if err == nil {
		return ErrorClassification{
			Type:        ErrorTypeUnknown,
			IsRetryable: false,
			Severity:    "info",
			Description: "No error occurred",
		}
	}

	errorStr := err.Error()

	// Check for network errors
	if ec.isNetworkError(errorStr) {
		return ErrorClassification{
			Type:        ErrorTypeNetwork,
			IsRetryable: true,
			Severity:    "medium",
			Description: "Network connectivity issue detected",
		}
	}

	// Check for registry errors
	if ec.isRegistryError(errorStr) {
		return ErrorClassification{
			Type:        ErrorTypeRegistry,
			IsRetryable: true,
			Severity:    "high",
			Description: "Registry communication error detected",
		}
	}

	// Check for rate limiting
	if ec.isRateLimitError(errorStr) {
		return ErrorClassification{
			Type:        ErrorTypeRateLimit,
			IsRetryable: true,
			Severity:    "high",
			Description: "Rate limiting detected",
		}
	}

	// Check for authentication errors
	if ec.isAuthenticationError(errorStr) {
		return ErrorClassification{
			Type:        ErrorTypeAuthentication,
			IsRetryable: false,
			Severity:    "critical",
			Description: "Authentication error detected",
		}
	}

	// Check for timeout errors
	if ec.isTimeoutError(errorStr) {
		return ErrorClassification{
			Type:        ErrorTypeTimeout,
			IsRetryable: true,
			Severity:    "medium",
			Description: "Timeout detected",
		}
	}

	// Check for resource exhaustion
	if ec.isResourceExhaustionError(errorStr) {
		return ErrorClassification{
			Type:        ErrorTypeResourceExhaustion,
			IsRetryable: true,
			Severity:    "high",
			Description: "Resource exhaustion detected",
		}
	}

	// Check for temporary errors
	if ec.isTemporaryError(errorStr) {
		return ErrorClassification{
			Type:        ErrorTypeTemporary,
			IsRetryable: true,
			Severity:    "low",
			Description: "Temporary error detected",
		}
	}

	// Default to permanent error
	return ErrorClassification{
		Type:        ErrorTypePermanent,
		IsRetryable: false,
		Severity:    "critical",
		Description: "Permanent error detected",
	}
}

// isNetworkError checks if the error is network-related
func (ec *ErrorClassifier) isNetworkError(errorStr string) bool {
	networkPatterns := []string{
		"connection refused",
		"connection reset",
		"network is unreachable",
		"no route to host",
		"timeout",
		"temporary failure",
		"DNS",
		"resolve",
		" dial ",
		"network error",
	}

	for _, pattern := range networkPatterns {
		if strings.Contains(strings.ToLower(errorStr), pattern) {
			return true
		}
	}

	// Check for specific network errors
	// Note: These checks are commented out because 'net' package is not imported
	// In a real implementation, you would uncomment these lines and import 'net'

	return false
}

// isRegistryError checks if the error is registry-related
func (ec *ErrorClassifier) isRegistryError(errorStr string) bool {
	registryPatterns := []string{
		"registry",
		"manifest unknown",
		"blob unknown",
		"unauthorized",
		"denied",
		"repository not found",
		"tag not found",
		"manifest",
		"layer",
		"push access denied",
		"pull access denied",
	}

	for _, pattern := range registryPatterns {
		if strings.Contains(strings.ToLower(errorStr), pattern) {
			return true
		}
	}

	return false
}

// isRateLimitError checks if the error is rate limiting related
func (ec *ErrorClassifier) isRateLimitError(errorStr string) bool {
	rateLimitPatterns := []string{
		"too many requests",
		"rate limit",
		"quota exceeded",
		"request limit",
		"429",
		"rate limiting",
		"throttled",
	}

	for _, pattern := range rateLimitPatterns {
		if strings.Contains(strings.ToLower(errorStr), pattern) {
			return true
		}
	}

	// Check for HTTP 429 status code
	if strings.Contains(errorStr, "429") {
		return true
	}

	return false
}

// isAuthenticationError checks if the error is authentication related
func (ec *ErrorClassifier) isAuthenticationError(errorStr string) bool {
	authPatterns := []string{
		"authentication",
		"unauthorized",
		"invalid token",
		"token expired",
		"access denied",
		"permission denied",
		"credentials",
		"401",
		"403",
	}

	for _, pattern := range authPatterns {
		if strings.Contains(strings.ToLower(errorStr), pattern) {
			return true
		}
	}

	// Check for HTTP 401 and 403 status codes
	if strings.Contains(errorStr, "401") || strings.Contains(errorStr, "403") {
		return true
	}

	return false
}

// isTimeoutError checks if the error is timeout related
func (ec *ErrorClassifier) isTimeoutError(errorStr string) bool {
	timeoutPatterns := []string{
		"timeout",
		"context deadline exceeded",
		"deadline exceeded",
		"timed out",
	}

	for _, pattern := range timeoutPatterns {
		if strings.Contains(strings.ToLower(errorStr), pattern) {
			return true
		}
	}

	return false
}

// isResourceExhaustionError checks if the error is resource exhaustion related
func (ec *ErrorClassifier) isResourceExhaustionError(errorStr string) bool {
	resourcePatterns := []string{
		"no space left",
		"disk full",
		"memory",
		"out of memory",
		"resource exhausted",
		"quota exceeded",
	}

	for _, pattern := range resourcePatterns {
		if strings.Contains(strings.ToLower(errorStr), pattern) {
			return true
		}
	}

	return false
}

// isTemporaryError checks if the error is temporary
func (ec *ErrorClassifier) isTemporaryError(errorStr string) bool {
	temporaryPatterns := []string{
		"temporary",
		"try again",
		"retry",
		"later",
		"unavailable",
		"service unavailable",
	}

	for _, pattern := range temporaryPatterns {
		if strings.Contains(strings.ToLower(errorStr), pattern) {
			return true
		}
	}

	return false
}

// DetermineStrategy determines the optimal retry strategy based on error type and context
func (ir *IntelligentRetry) DetermineStrategy(_ context.Context, operation string, err error) Strategy {
	// Classify the error
	classification := ir.errorClassifier.ClassifyError(err)

	// Get operation context
	contextInfo := ir.contextAnalyzer.GetOperationContext(operation)

	// Select base strategy based on error type
	baseStrategyName := ir.getBaseStrategyName(classification.Type)

	// Get the base strategy
	ir.strategySelector.mu.RLock()
	baseStrategy := ir.strategySelector.strategies[baseStrategyName]
	ir.strategySelector.mu.RUnlock()

	if baseStrategy == nil {
		baseStrategy = ir.strategySelector.strategies["default"]
	}

	// Create a copy of the strategy to modify
	strategy := *baseStrategy

	// Adjust strategy based on context
	if strategy.ContextAware && contextInfo != nil {
		ir.adjustStrategyBasedOnContext(&strategy, contextInfo, classification)
	}

	// Adjust strategy based on error severity
	ir.adjustStrategyBasedOnSeverity(&strategy, classification)

	debug.LogComponent("retry", "Selected strategy for %s: %+v (error type: %v)", operation, strategy, classification.Type)

	return strategy
}

// getBaseStrategyName gets the base strategy name for an error type
func (ir *IntelligentRetry) getBaseStrategyName(errorType ErrorType) string {
	switch errorType {
	case ErrorTypeNetwork:
		return "network"
	case ErrorTypeRegistry:
		return "registry"
	case ErrorTypeRateLimit:
		return "rate-limit"
	case ErrorTypeAuthentication:
		return "authentication"
	case ErrorTypeTimeout:
		return "timeout"
	case ErrorTypeResourceExhaustion:
		return "network" // Treat resource exhaustion like network errors
	case ErrorTypeTemporary:
		return "default"
	default:
		return "default"
	}
}

// adjustStrategyBasedOnContext adjusts the strategy based on operation context
// nolint:gocritic // importShadow: 'context' parameter is intentionally named differently from imported package
func (ir *IntelligentRetry) adjustStrategyBasedOnContext(
	strategy *Strategy, opContext *OperationContext, _ ErrorClassification,
) {
	// If the operation has a high failure rate, reduce max attempts
	if opContext.FailureCount > opContext.SuccessCount && opContext.FailureCount > HighFailureThreshold {
		strategy.MaxAttempts = intMax(1, strategy.MaxAttempts-1)
		debug.LogComponent("retry", "Reduced max attempts due to high failure rate: %d", strategy.MaxAttempts)
	}

	// If the operation has been successful recently, we can be more aggressive
	if time.Since(opContext.LastSuccess) < RecentSuccessMinutes*time.Minute &&
		opContext.SuccessCount > opContext.FailureCount {
		strategy.InitialDelay = time.Duration(float64(strategy.InitialDelay) * SuccessDelayMultiplier)
		strategy.MaxDelay = time.Duration(float64(strategy.MaxDelay) * SuccessMaxDelayMultiplier)
		debug.LogComponent("retry", "Reduced delays due to recent success")
	}

	// If the operation has common timeout errors, increase timeout
	hasTimeout := false
	for _, err := range opContext.CommonErrors {
		if ir.errorClassifier.isTimeoutError(err) {
			hasTimeout = true
			break
		}
	}

	if hasTimeout {
		strategy.MaxAttempts = intMin(strategy.MaxAttempts+1, MaxTimeoutAttempts)
		strategy.MaxDelay = time.Duration(float64(strategy.MaxDelay) * TimeoutAttemptsMultiplier)
		debug.LogComponent("retry", "Increased attempts and delays due to timeout patterns")
	}
}

// adjustStrategyBasedOnSeverity adjusts the strategy based on error severity
func (ir *IntelligentRetry) adjustStrategyBasedOnSeverity(strategy *Strategy, classification ErrorClassification) {
	switch classification.Severity {
	case "critical":
		// For critical errors, be more conservative
		strategy.MaxAttempts = intMax(1, strategy.MaxAttempts-1)
		strategy.InitialDelay = time.Duration(float64(strategy.InitialDelay) * CriticalDelayMultiplier)
		strategy.MaxDelay = time.Duration(float64(strategy.MaxDelay) * CriticalMaxDelayMultiplier)
	case "high":
		// For high severity errors, be slightly conservative
		strategy.MaxAttempts = intMax(1, strategy.MaxAttempts-1)
		strategy.InitialDelay = time.Duration(float64(strategy.InitialDelay) * HighDelayMultiplier)
	case "low":
		// For low severity errors, be more aggressive
		strategy.MaxAttempts = intMin(strategy.MaxAttempts+1, LowSeverityMaxAttempts)
		strategy.InitialDelay = time.Duration(float64(strategy.InitialDelay) * LowDelayMultiplier)
	}
}

// ShouldRetry determines if an operation should be retried
func (ir *IntelligentRetry) ShouldRetry(ctx context.Context, attempt int, err error) bool {
	// Check if context is canceled
	if ctxErr := ctx.Err(); ctxErr != nil {
		debug.LogComponent("retry", "Context canceled, not retrying: %v", ctxErr)
		return false
	}

	// Classify the error
	classification := ir.errorClassifier.ClassifyError(err)

	// If the error is not retryable, don't retry
	if !classification.IsRetryable {
		debug.LogComponent("retry", "Error is not retryable: %v", classification.Description)
		return false
	}

	// Get the strategy for this operation
	operation := getOperationFromContext(ctx)
	strategy := ir.DetermineStrategy(ctx, operation, err)

	// Check if we've exceeded max attempts
	if attempt >= strategy.MaxAttempts {
		debug.LogComponent("retry", "Max attempts (%d) exceeded for operation %s", strategy.MaxAttempts, operation)
		return false
	}

	// Check for rate limiting specifically
	if classification.Type == ErrorTypeRateLimit {
		// For rate limiting, we should retry but with increased delays
		debug.LogComponent("retry", "Rate limiting detected, will retry with increased delay")
		return true
	}

	// Check for network errors with specific conditions
	if classification.Type == ErrorTypeNetwork {
		// For network errors, check if it's a connection refused error
		if strings.Contains(strings.ToLower(err.Error()), "connection refused") {
			// Connection refused might indicate a service that's down
			if attempt >= ConnectionRefusedAttempts {
				debug.LogComponent("retry", "Multiple connection refused errors, giving up")
				return false
			}
		}
	}

	// For temporary errors, always retry
	if classification.Type == ErrorTypeTemporary {
		debug.LogComponent("retry", "Temporary error detected, will retry")
		return true
	}

	// Default behavior: retry if we haven't exceeded max attempts
	debug.LogComponent("retry", "Will retry operation %s (attempt %d/%d)", operation, attempt+1, strategy.MaxAttempts)
	return true
}

// GetNextDelay calculates the next delay for a retry attempt
func (ir *IntelligentRetry) GetNextDelay(ctx context.Context, attempt int, err error) time.Duration {
	// Get the strategy for this operation
	operation := getOperationFromContext(ctx)
	strategy := ir.DetermineStrategy(ctx, operation, err)

	var delay time.Duration

	switch strategy.BackoffAlgorithm {
	case "exponential":
		delay = calculateExponentialDelay(strategy.InitialDelay, attempt, strategy.BaseMultiplier, strategy.MaxDelay)
	case "fibonacci":
		delay = calculateFibonacciDelay(strategy.InitialDelay, attempt, strategy.MaxDelay)
	case "linear":
		delay = calculateLinearDelay(strategy.InitialDelay, attempt, strategy.BaseMultiplier, strategy.MaxDelay)
	default:
		delay = calculateExponentialDelay(strategy.InitialDelay, attempt, strategy.BaseMultiplier, strategy.MaxDelay)
	}

	// Add jitter if enabled
	if strategy.Jitter {
		delay = addJitter(delay)
	}

	// Ensure delay doesn't exceed max delay
	if delay > strategy.MaxDelay {
		delay = strategy.MaxDelay
	}

	debug.LogComponent("retry", "Calculated delay for attempt %d: %v", attempt+1, delay)
	return delay
}

// RecordOperation records the result of an operation for future analysis
func (ir *IntelligentRetry) RecordOperation(_ context.Context, operation string, err error, duration time.Duration) {
	ir.contextAnalyzer.RecordOperation(operation, err, duration)
}

// GetOperationStats returns statistics for an operation
func (ir *IntelligentRetry) GetOperationStats(operation string) *OperationContext {
	return ir.contextAnalyzer.GetOperationContext(operation)
}

// calculateExponentialDelay calculates exponential backoff delay
func calculateExponentialDelay(initialDelay time.Duration, attempt int,
	multiplier float64, maxDelay time.Duration) time.Duration {
	delay := float64(initialDelay) * math.Pow(multiplier, float64(attempt))
	if delay > float64(maxDelay) {
		return maxDelay
	}
	return time.Duration(delay)
}

// calculateFibonacciDelay calculates fibonacci backoff delay
func calculateFibonacciDelay(initialDelay time.Duration, attempt int, maxDelay time.Duration) time.Duration {
	if attempt <= 0 {
		return initialDelay
	}

	// Fibonacci sequence: 1, 1, 2, 3, 5, 8, 13, 21, 34, 55...
	fib := make([]int, attempt+1)
	fib[0] = 1
	if attempt >= 1 {
		fib[1] = 1
	}

	for i := 2; i <= attempt; i++ {
		fib[i] = fib[i-1] + fib[i-2]
		if fib[i] > FibonacciCap { // Cap the fibonacci number to prevent overflow
			fib[i] = FibonacciCapValue
		}
	}

	delay := time.Duration(fib[attempt]) * initialDelay
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

// calculateLinearDelay calculates linear backoff delay
func calculateLinearDelay(initialDelay time.Duration, attempt int,
	multiplier float64, maxDelay time.Duration) time.Duration {
	delay := time.Duration(float64(initialDelay) * float64(attempt) * multiplier)
	if delay > maxDelay {
		return maxDelay
	}
	return delay
}

// addJitter adds random jitter to delay
func addJitter(delay time.Duration) time.Duration {
	if delay == 0 {
		return 0
	}

	// Add jitter between 0 and 50% of the delay
	jitter := time.Duration(float64(delay) * JitterPercentage *
		(JitterMinMultiplier + (JitterMaxMultiplier-JitterMinMultiplier)*randFloat()))
	return delay + jitter
}

// randFloat returns a random float between 0.0 and 1.0
func randFloat() float64 {
	// In a real implementation, this would use a proper random number generator
	// For now, return a pseudo-random value
	return float64(time.Now().UnixNano()%RandomDivisor) / float64(RandomDivisor)
}

// getOperationFromContext extracts operation name from context
func getOperationFromContext(ctx context.Context) string {
	if operation := ctx.Value("operation"); operation != nil {
		if op, ok := operation.(string); ok {
			return op
		}
	}
	return UnknownOperation
}

// intMin returns the minimum of two integers
func intMin(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// intMax returns the maximum of two integers
func intMax(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// ContextAnalyzer methods

// RecordOperation records an operation result
func (ca *ContextAnalyzer) RecordOperation(operation string, err error, duration time.Duration) {
	ca.mu.Lock()
	defer ca.mu.Unlock()

	key := operation
	if registryAndPlatform := ca.getRegistryAndPlatform(operation); registryAndPlatform != "" {
		key = registryAndPlatform
	}

	if _, exists := ca.history[key]; !exists {
		ca.history[key] = &OperationContext{
			Operation:    operation,
			AttemptCount: 0,
			SuccessCount: 0,
			FailureCount: 0,
			CommonErrors: make([]string, 0),
		}
	}

	ctx := ca.history[key]
	ctx.AttemptCount++
	ctx.LastAttempt = time.Now()

	if err == nil {
		ctx.SuccessCount++
		ctx.LastSuccess = time.Now()
	} else {
		ctx.FailureCount++
		ctx.LastFailure = time.Now()
		ctx.CommonErrors = append(ctx.CommonErrors, err.Error())

		// Keep only the last CommonErrorsLimit common errors
		if len(ctx.CommonErrors) > CommonErrorsLimit {
			ctx.CommonErrors = ctx.CommonErrors[len(ctx.CommonErrors)-10:]
		}
	}

	// Update average latency
	if ctx.AverageLatency == 0 {
		ctx.AverageLatency = duration
	} else {
		ctx.AverageLatency = (ctx.AverageLatency + duration) / AverageLatencyDivisor
	}
}

// GetOperationContext returns context information for an operation
func (ca *ContextAnalyzer) GetOperationContext(operation string) *OperationContext {
	ca.mu.RLock()
	defer ca.mu.RUnlock()

	key := operation
	if registryAndPlatform := ca.getRegistryAndPlatform(operation); registryAndPlatform != "" {
		key = registryAndPlatform
	}

	if ctx, exists := ca.history[key]; exists {
		return ctx
	}
	return nil
}

// getRegistryAndPlatform extracts registry and platform from operation string
func (ca *ContextAnalyzer) getRegistryAndPlatform(operation string) string {
	// This is a simplified implementation. In a real implementation,
	// you would parse the operation string to extract registry and platform.

	// Look for common patterns
	if strings.Contains(operation, "registry") && strings.Contains(operation, "platform") {
		return fmt.Sprintf("%s-%s", extractRegistry(operation), extractPlatform(operation))
	}

	return ""
}

// extractRegistry extracts registry name from operation string
func extractRegistry(operation string) string {
	// Simple regex to extract registry
	re := regexp.MustCompile(`registry:([^:]+)`)
	matches := re.FindStringSubmatch(operation)
	if len(matches) > 1 {
		return matches[1]
	}
	return UnknownRegistry
}

// extractPlatform extracts platform from operation string
func extractPlatform(operation string) string {
	// Simple regex to extract platform
	re := regexp.MustCompile(`platform:([^:]+)`)
	matches := re.FindStringSubmatch(operation)
	if len(matches) > 1 {
		return matches[1]
	}
	return UnknownPlatform
}
