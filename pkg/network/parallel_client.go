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

package network

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
)

// ParallelClientConfig holds configuration for parallel HTTP client
type ParallelClientConfig struct {
	MaxConcurrency    int           // Maximum concurrent requests
	RequestTimeout    time.Duration // Individual request timeout
	RetryAttempts     int           // Number of retry attempts
	RetryDelay        time.Duration // Delay between retries
	EnableCompression bool          // Enable gzip compression
	UserAgent         string        // User agent string
}

// DefaultParallelClientConfig returns default configuration
func DefaultParallelClientConfig() *ParallelClientConfig {
	return &ParallelClientConfig{
		MaxConcurrency:    defaultMaxConcurrency,
		RequestTimeout:    DefaultResponseTimeout,
		RetryAttempts:     defaultRetryAttempts,
		RetryDelay:        defaultRetryDelay * time.Second,
		EnableCompression: true,
		UserAgent:         "kaniko-optimized/1.0",
	}
}

// ParallelClient provides optimized HTTP client with parallel requests
type ParallelClient struct {
	config     *ParallelClientConfig
	pool       *ConnectionPool
	client     *http.Client
	stats      *ParallelClientStats
	statsMutex sync.RWMutex
	workerPool chan struct{}
}

// ParallelClientStats holds statistics about parallel client usage
type ParallelClientStats struct {
	TotalRequests      int64         `json:"total_requests"`
	SuccessfulRequests int64         `json:"successful_requests"`
	FailedRequests     int64         `json:"failed_requests"`
	RetryAttempts      int64         `json:"retry_attempts"`
	AverageLatency     time.Duration `json:"average_latency"`
	TotalBytes         int64         `json:"total_bytes"`
	LastReset          time.Time     `json:"last_reset"`
}

// NewParallelClient creates a new parallel HTTP client
func NewParallelClient(config *ParallelClientConfig, pool *ConnectionPool) *ParallelClient {
	if config == nil {
		config = DefaultParallelClientConfig()
	}

	if pool == nil {
		logrus.Warn("Connection pool is nil, creating default pool")
		pool = NewConnectionPool(nil)
	}

	httpClient := pool.GetClient()
	if httpClient == nil {
		logrus.Error("Failed to get HTTP client from pool, creating default client")
		httpClient = &http.Client{
			Timeout: DefaultRequestTimeout,
		}
	}

	client := &ParallelClient{
		config: config,
		pool:   pool,
		client: httpClient,
		stats: &ParallelClientStats{
			LastReset: time.Now(),
		},
		workerPool: make(chan struct{}, config.MaxConcurrency),
	}

	logrus.Info("Parallel HTTP client initialized")
	return client
}

// ParallelRequest represents a parallel HTTP request
type ParallelRequest struct {
	URL     string
	Method  string
	Headers map[string]string
	Body    io.Reader
	Timeout time.Duration
}

// ParallelResponse represents a parallel HTTP response
type ParallelResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
	Error      error
	Latency    time.Duration
}

// ExecuteParallel executes multiple HTTP requests in parallel
func (pc *ParallelClient) ExecuteParallel(ctx context.Context, requests []ParallelRequest) ([]ParallelResponse, error) {
	if len(requests) == 0 {
		return nil, fmt.Errorf("no requests provided")
	}

	logrus.Infof("Executing %d requests in parallel", len(requests))
	start := time.Now()

	// Create response slice
	responses := make([]ParallelResponse, len(requests))

	// Use errgroup for parallel execution
	g, ctx := errgroup.WithContext(ctx)

	// Execute requests in parallel
	for i, req := range requests {
		i, req := i, req // Capture for closure
		g.Go(func() error {
			// Acquire worker
			select {
			case pc.workerPool <- struct{}{}:
				defer func() { <-pc.workerPool }()
			case <-ctx.Done():
				return ctx.Err()
			}

			// Execute request
			response := pc.executeRequest(ctx, req)
			responses[i] = response

			// Update statistics
			pc.updateStats(response)

			return response.Error
		})
	}

	// Wait for all requests to complete
	if err := g.Wait(); err != nil {
		logrus.Warnf("Some parallel requests failed: %v", err)
	}

	totalTime := time.Since(start)
	logrus.Infof("Parallel execution completed in %v", totalTime)

	return responses, nil
}

// executeRequest executes a single HTTP request with retry logic
func (pc *ParallelClient) executeRequest(ctx context.Context, req ParallelRequest) ParallelResponse {
	start := time.Now()

	// Create request context with timeout
	requestCtx := ctx
	if req.Timeout > 0 {
		var cancel context.CancelFunc
		requestCtx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	} else if pc.config.RequestTimeout > 0 {
		var cancel context.CancelFunc
		requestCtx, cancel = context.WithTimeout(ctx, pc.config.RequestTimeout)
		defer cancel()
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(requestCtx, req.Method, req.URL, req.Body)
	if err != nil {
		return ParallelResponse{
			Error:   fmt.Errorf("failed to create request: %w", err),
			Latency: time.Since(start),
		}
	}

	// Set headers
	for key, value := range req.Headers {
		httpReq.Header.Set(key, value)
	}

	// Set default headers
	httpReq.Header.Set("User-Agent", pc.config.UserAgent)
	if pc.config.EnableCompression {
		httpReq.Header.Set("Accept-Encoding", "gzip")
	}

	// Execute request with retry logic
	var resp *http.Response
	var lastErr error

	for attempt := 0; attempt <= pc.config.RetryAttempts; attempt++ {
		if attempt > 0 {
			pc.recordRetry()
			select {
			case <-time.After(pc.config.RetryDelay * time.Duration(attempt)):
			case <-requestCtx.Done():
				return ParallelResponse{
					Error:   requestCtx.Err(),
					Latency: time.Since(start),
				}
			}
		}

		if pc.client == nil {
			lastErr = fmt.Errorf("HTTP client is nil")
			break
		}

		resp, lastErr = pc.client.Do(httpReq)
		if lastErr == nil {
			break
		}

		logrus.Debugf("Request attempt %d failed: %v", attempt+1, lastErr)
	}

	if lastErr != nil {
		return ParallelResponse{
			Error:   fmt.Errorf("request failed after %d attempts: %w", pc.config.RetryAttempts+1, lastErr),
			Latency: time.Since(start),
		}
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ParallelResponse{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Error:      fmt.Errorf("failed to read response body: %w", err),
			Latency:    time.Since(start),
		}
	}

	latency := time.Since(start)
	logrus.Debugf("Request completed: %s %s -> %d (%v)", req.Method, req.URL, resp.StatusCode, latency)

	return ParallelResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
		Latency:    latency,
	}
}

// updateStats updates client statistics
func (pc *ParallelClient) updateStats(response ParallelResponse) {
	pc.statsMutex.Lock()
	defer pc.statsMutex.Unlock()

	pc.stats.TotalRequests++
	pc.stats.TotalBytes += int64(len(response.Body))

	if response.Error != nil {
		pc.stats.FailedRequests++
	} else {
		pc.stats.SuccessfulRequests++
	}

	// Update average latency using exponential moving average
	if pc.stats.AverageLatency == 0 {
		pc.stats.AverageLatency = response.Latency
	} else {
		pc.stats.AverageLatency = (pc.stats.AverageLatency + response.Latency) / averageDivisor
	}
}

// recordRetry records a retry attempt
func (pc *ParallelClient) recordRetry() {
	pc.statsMutex.Lock()
	defer pc.statsMutex.Unlock()
	pc.stats.RetryAttempts++
}

// GetStats returns client statistics
func (pc *ParallelClient) GetStats() *ParallelClientStats {
	pc.statsMutex.RLock()
	defer pc.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := *pc.stats
	return &stats
}

// LogStats logs client statistics
func (pc *ParallelClient) LogStats() {
	stats := pc.GetStats()

	logrus.Infof("Parallel Client Statistics:")
	logrus.Infof("   Total Requests: %d", stats.TotalRequests)
	logrus.Infof("   Successful: %d, Failed: %d", stats.SuccessfulRequests, stats.FailedRequests)
	logrus.Infof("   Retry Attempts: %d", stats.RetryAttempts)
	logrus.Infof("   Average Latency: %v", stats.AverageLatency)
	logrus.Infof("   Total Bytes: %d", stats.TotalBytes)

	if stats.TotalRequests > 0 {
		successRate := float64(stats.SuccessfulRequests) / float64(stats.TotalRequests) * percentageBase
		logrus.Infof("   Success Rate: %.2f%%", successRate)
	}
}
