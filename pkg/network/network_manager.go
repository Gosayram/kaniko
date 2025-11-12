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
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/sirupsen/logrus"
)

// ManagerConfig holds configuration for the network manager
type ManagerConfig struct {
	// Connection pool settings
	MaxIdleConns        int           // Maximum idle connections per host
	MaxIdleConnsPerHost int           // Maximum idle connections per host
	MaxConnsPerHost     int           // Maximum connections per host
	IdleConnTimeout     time.Duration // Idle connection timeout

	// Parallel client settings
	MaxConcurrency int           // Maximum concurrent requests
	RequestTimeout time.Duration // Request timeout
	RetryAttempts  int           // Number of retry attempts
	RetryDelay     time.Duration // Delay between retries

	// Registry client settings
	EnableParallelPull bool   // Enable parallel layer pulling
	EnableCompression  bool   // Enable compression
	UserAgent          string // User agent string

	// Cache settings
	EnableDNSOptimization bool          // Enable DNS caching
	DNSCacheTimeout       time.Duration // DNS cache timeout
	EnableManifestCache   bool          // Enable manifest caching
	ManifestCacheTimeout  time.Duration // Manifest cache timeout
}

// DefaultManagerConfig returns default configuration
func DefaultManagerConfig() *ManagerConfig {
	return &ManagerConfig{
		// Connection pool settings
		MaxIdleConns:        defaultMaxIdleConns,
		MaxIdleConnsPerHost: defaultMaxIdleConnsPerHost,
		MaxConnsPerHost:     defaultMaxConnsPerHost,
		IdleConnTimeout:     DefaultIdleConnTimeout,

		// Parallel client settings
		MaxConcurrency: defaultMaxConcurrency,
		RequestTimeout: DefaultRequestTimeout, // Use RequestTimeout, not ResponseTimeout
		RetryAttempts:  defaultRetryAttempts,
		RetryDelay:     1 * time.Second,

		// Registry client settings
		EnableParallelPull: true,
		EnableCompression:  true,
		UserAgent:          "kaniko-optimized/1.0",

		// Cache settings
		EnableDNSOptimization: true,
		DNSCacheTimeout:       DefaultDNSCacheTimeout,
		EnableManifestCache:   true,
		ManifestCacheTimeout:  DefaultManifestCacheTimeout,
	}
}

// Manager provides optimized network operations
type Manager struct {
	config         *ManagerConfig
	connectionPool *ConnectionPool
	registryClient *RegistryClient
	stats          *ManagerStats
	statsMutex     sync.RWMutex
	initialized    bool
	initMutex      sync.Mutex
}

// Global network manager instance (initialized on first use)
var (
	globalNetworkManager   *Manager
	globalNetworkManagerMu sync.Mutex
)

// ManagerStats holds statistics about network manager usage
type ManagerStats struct {
	TotalRequests      int64         `json:"total_requests"`
	SuccessfulRequests int64         `json:"successful_requests"`
	FailedRequests     int64         `json:"failed_requests"`
	AverageLatency     time.Duration `json:"average_latency"`
	TotalBytes         int64         `json:"total_bytes"`
	LastReset          time.Time     `json:"last_reset"`
}

// NewManager creates a new network manager
func NewManager(config *ManagerConfig) *Manager {
	if config == nil {
		config = DefaultManagerConfig()
	}

	manager := &Manager{
		config: config,
		stats: &ManagerStats{
			LastReset: time.Now(),
		},
	}

	// Set as global instance (per performance plan: optimize connection pooling)
	globalNetworkManagerMu.Lock()
	globalNetworkManager = manager
	globalNetworkManagerMu.Unlock()

	logrus.Info("Network manager created")
	return manager
}

// GetGlobalNetworkManager returns the global network manager instance
func GetGlobalNetworkManager() *Manager {
	globalNetworkManagerMu.Lock()
	defer globalNetworkManagerMu.Unlock()
	return globalNetworkManager
}

// Initialize initializes the network manager components
func (nm *Manager) Initialize() error {
	nm.initMutex.Lock()
	defer nm.initMutex.Unlock()

	if nm.initialized {
		return nil
	}

	logrus.Info("Initializing network manager components")

	// Create connection pool
	poolConfig := &ConnectionPoolConfig{
		MaxIdleConns:        nm.config.MaxIdleConns,
		MaxIdleConnsPerHost: nm.config.MaxIdleConnsPerHost,
		MaxConnsPerHost:     nm.config.MaxConnsPerHost,
		IdleConnTimeout:     nm.config.IdleConnTimeout,
		DisableKeepAlives:   false,

		DialTimeout:           DefaultDialTimeout,
		ResponseHeaderTimeout: DefaultResponseTimeout,
		ExpectContinueTimeout: 1 * time.Second,

		EnableDNSOptimization: nm.config.EnableDNSOptimization,
		DNSCacheTimeout:       nm.config.DNSCacheTimeout,
	}
	nm.connectionPool = NewConnectionPool(poolConfig)

	// Create registry client
	registryConfig := &RegistryClientConfig{
		MaxConcurrency: nm.config.MaxConcurrency,
		RequestTimeout: nm.config.RequestTimeout,
		RetryAttempts:  nm.config.RetryAttempts,
		RetryDelay:     nm.config.RetryDelay,

		EnableParallelPull: nm.config.EnableParallelPull,
		EnableCompression:  nm.config.EnableCompression,
		UserAgent:          nm.config.UserAgent,

		EnableManifestCache:  nm.config.EnableManifestCache,
		ManifestCacheTimeout: nm.config.ManifestCacheTimeout,
	}
	nm.registryClient = NewRegistryClient(registryConfig, nm.connectionPool)

	nm.initialized = true
	logrus.Info("Network manager initialized successfully")
	return nil
}

// PullImage pulls an image using optimized network operations
func (nm *Manager) PullImage(ctx context.Context, ref name.Reference,
	options ...remote.Option) (v1.Image, error) {
	if err := nm.ensureInitialized(); err != nil {
		return nil, err
	}

	start := time.Now()
	image, err := nm.registryClient.PullImage(ctx, ref, options...)

	// Update statistics
	nm.updateStats(time.Since(start), 0, err == nil)

	return image, err
}

// PullImageParallel pulls multiple images in parallel
func (nm *Manager) PullImageParallel(ctx context.Context, refs []name.Reference,
	options ...remote.Option) ([]v1.Image, error) {
	if err := nm.ensureInitialized(); err != nil {
		return nil, err
	}

	start := time.Now()
	images, err := nm.registryClient.PullImageParallel(ctx, refs, options...)

	// Update statistics
	nm.updateStats(time.Since(start), 0, err == nil)

	return images, err
}

// PushImage pushes an image using optimized network operations
func (nm *Manager) PushImage(ctx context.Context, ref name.Reference, image v1.Image,
	options ...remote.Option) error {
	if err := nm.ensureInitialized(); err != nil {
		return err
	}

	start := time.Now()
	err := nm.registryClient.PushImage(ctx, ref, image, options...)

	// Update statistics
	nm.updateStats(time.Since(start), 0, err == nil)

	return err
}

// GetConnectionPool returns the connection pool
func (nm *Manager) GetConnectionPool() *ConnectionPool {
	return nm.connectionPool
}

// GetRegistryClient returns the registry client
func (nm *Manager) GetRegistryClient() *RegistryClient {
	return nm.registryClient
}

// ensureInitialized ensures the network manager is initialized
func (nm *Manager) ensureInitialized() error {
	if !nm.initialized {
		return nm.Initialize()
	}
	return nil
}

// updateStats updates network manager statistics
func (nm *Manager) updateStats(latency time.Duration, bytes int64, success bool) {
	nm.statsMutex.Lock()
	defer nm.statsMutex.Unlock()

	nm.stats.TotalRequests++
	nm.stats.TotalBytes += bytes

	if success {
		nm.stats.SuccessfulRequests++
	} else {
		nm.stats.FailedRequests++
	}

	// Update average latency using exponential moving average
	if nm.stats.AverageLatency == 0 {
		nm.stats.AverageLatency = latency
	} else {
		nm.stats.AverageLatency = (nm.stats.AverageLatency + latency) / averageDivisor
	}
}

// GetStats returns network manager statistics
func (nm *Manager) GetStats() *ManagerStats {
	nm.statsMutex.RLock()
	defer nm.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := *nm.stats
	return &stats
}

// LogStats logs comprehensive network statistics
func (nm *Manager) LogStats() {
	stats := nm.GetStats()

	logrus.Infof("Network Manager Statistics:")
	logrus.Infof("   Total Requests: %d", stats.TotalRequests)
	logrus.Infof("   Successful: %d, Failed: %d", stats.SuccessfulRequests, stats.FailedRequests)
	logrus.Infof("   Average Latency: %v", stats.AverageLatency)
	logrus.Infof("   Total Bytes: %d", stats.TotalBytes)

	if stats.TotalRequests > 0 {
		successRate := float64(stats.SuccessfulRequests) / float64(stats.TotalRequests) * percentageBase
		logrus.Infof("   Success Rate: %.2f%%", successRate)
	}

	// Log component statistics
	if nm.connectionPool != nil {
		nm.connectionPool.LogStats()
	}
	if nm.registryClient != nil {
		nm.registryClient.LogStats()
	}
}

// Close closes the network manager and cleans up resources
func (nm *Manager) Close() error {
	logrus.Info("Closing network manager")

	// Close registry client
	if nm.registryClient != nil {
		if err := nm.registryClient.Close(); err != nil {
			logrus.Warnf("Failed to close registry client: %v", err)
		}
	}

	// Close connection pool
	if nm.connectionPool != nil {
		if err := nm.connectionPool.Close(); err != nil {
			logrus.Warnf("Failed to close connection pool: %v", err)
		}
	}

	logrus.Info("Network manager closed successfully")
	return nil
}
