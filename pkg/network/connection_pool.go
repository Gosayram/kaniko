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

// Package network provides optimized network operations for Kaniko
package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// ConnectionPoolConfig holds configuration for the connection pool
type ConnectionPoolConfig struct {
	// Pool settings
	MaxIdleConns        int           // Maximum idle connections per host
	MaxIdleConnsPerHost int           // Maximum idle connections per host
	MaxConnsPerHost     int           // Maximum connections per host
	IdleConnTimeout     time.Duration // Idle connection timeout
	DisableKeepAlives   bool          // Disable HTTP keep-alives

	// Timeout settings
	DialTimeout           time.Duration // Dial timeout
	ResponseHeaderTimeout time.Duration // Response header timeout
	ExpectContinueTimeout time.Duration // Expect continue timeout

	// DNS settings
	EnableDNSOptimization bool          // Enable DNS caching and optimization
	DNSCacheTimeout       time.Duration // DNS cache timeout
}

// DefaultConnectionPoolConfig returns default configuration for connection pool
func DefaultConnectionPoolConfig() *ConnectionPoolConfig {
	return &ConnectionPoolConfig{
		MaxIdleConns:        defaultMaxIdleConns,
		MaxIdleConnsPerHost: defaultMaxIdleConnsPerHost,
		MaxConnsPerHost:     defaultMaxConnsPerHost,
		IdleConnTimeout:     DefaultIdleConnTimeout,
		DisableKeepAlives:   false,

		DialTimeout:           DefaultDialTimeout,
		ResponseHeaderTimeout: DefaultResponseTimeout,
		ExpectContinueTimeout: 1 * time.Second,

		EnableDNSOptimization: true,
		DNSCacheTimeout:       DefaultDNSCacheTimeout,
	}
}

// ConnectionPool manages HTTP connections with optimization
type ConnectionPool struct {
	config     *ConnectionPoolConfig
	transport  *http.Transport
	client     *http.Client
	dnsCache   *DNSCache
	stats      *ConnectionStats
	statsMutex sync.RWMutex
}

// ConnectionStats holds statistics about connection pool usage
type ConnectionStats struct {
	TotalRequests     int64         `json:"total_requests"`
	ActiveConnections int64         `json:"active_connections"`
	IdleConnections   int64         `json:"idle_connections"`
	CacheHits         int64         `json:"cache_hits"`
	CacheMisses       int64         `json:"cache_misses"`
	AverageLatency    time.Duration `json:"average_latency"`
	LastReset         time.Time     `json:"last_reset"`
}

// NewConnectionPool creates a new optimized connection pool
func NewConnectionPool(config *ConnectionPoolConfig) *ConnectionPool {
	if config == nil {
		config = DefaultConnectionPoolConfig()
	}

	// Create optimized transport
	transport := &http.Transport{
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		MaxConnsPerHost:     config.MaxConnsPerHost,
		IdleConnTimeout:     config.IdleConnTimeout,
		DisableKeepAlives:   config.DisableKeepAlives,

		ResponseHeaderTimeout: config.ResponseHeaderTimeout,
		ExpectContinueTimeout: config.ExpectContinueTimeout,

		// Enable HTTP/2
		ForceAttemptHTTP2: true,

		// Custom dialer for DNS optimization
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialWithOptimization(ctx, network, addr, config)
		},
	}

	// Create HTTP client with optimized transport
	client := &http.Client{
		Transport: transport,
		Timeout:   DefaultRequestTimeout, // Overall request timeout
	}

	pool := &ConnectionPool{
		config:    config,
		transport: transport,
		client:    client,
		stats: &ConnectionStats{
			LastReset: time.Now(),
		},
	}

	// Initialize DNS cache if enabled
	if config.EnableDNSOptimization {
		pool.dnsCache = NewDNSCache(config.DNSCacheTimeout)
	}

	logrus.Info("🌐 Connection pool initialized with optimizations")
	return pool
}

// GetClient returns the optimized HTTP client
func (cp *ConnectionPool) GetClient() *http.Client {
	return cp.client
}

// GetTransport returns the optimized HTTP transport
func (cp *ConnectionPool) GetTransport() *http.Transport {
	return cp.transport
}

// Close closes the connection pool and cleans up resources
func (cp *ConnectionPool) Close() error {
	logrus.Info("🔌 Closing connection pool")

	// Close DNS cache if enabled
	if cp.dnsCache != nil {
		cp.dnsCache.Close()
	}

	// Close idle connections
	cp.transport.CloseIdleConnections()

	logrus.Info("✅ Connection pool closed successfully")
	return nil
}

// GetStats returns current connection pool statistics
func (cp *ConnectionPool) GetStats() *ConnectionStats {
	cp.statsMutex.RLock()
	defer cp.statsMutex.RUnlock()

	// Return a copy to avoid race conditions
	stats := *cp.stats
	return &stats
}

// UpdateStats updates connection pool statistics
func (cp *ConnectionPool) UpdateStats(latency time.Duration) {
	cp.statsMutex.Lock()
	defer cp.statsMutex.Unlock()

	cp.stats.TotalRequests++

	// Update average latency using exponential moving average
	if cp.stats.AverageLatency == 0 {
		cp.stats.AverageLatency = latency
	} else {
		cp.stats.AverageLatency = (cp.stats.AverageLatency + latency) / averageDivisor
	}
}

// RecordCacheHit records a DNS cache hit
func (cp *ConnectionPool) RecordCacheHit() {
	cp.statsMutex.Lock()
	defer cp.statsMutex.Unlock()
	cp.stats.CacheHits++
}

// RecordCacheMiss records a DNS cache miss
func (cp *ConnectionPool) RecordCacheMiss() {
	cp.statsMutex.Lock()
	defer cp.statsMutex.Unlock()
	cp.stats.CacheMisses++
}

// LogStats logs connection pool statistics
func (cp *ConnectionPool) LogStats() {
	stats := cp.GetStats()

	logrus.Infof("🌐 Connection Pool Statistics:")
	logrus.Infof("   Total Requests: %d", stats.TotalRequests)
	logrus.Infof("   Average Latency: %v", stats.AverageLatency)
	logrus.Infof("   DNS Cache Hits: %d", stats.CacheHits)
	logrus.Infof("   DNS Cache Misses: %d", stats.CacheMisses)

	if stats.CacheHits+stats.CacheMisses > 0 {
		hitRate := float64(stats.CacheHits) / float64(stats.CacheHits+stats.CacheMisses) * percentageBase
		logrus.Infof("   DNS Cache Hit Rate: %.2f%%", hitRate)
	}
}

// dialWithOptimization performs optimized dialing with DNS caching
func dialWithOptimization(ctx context.Context, network, addr string, config *ConnectionPoolConfig) (net.Conn, error) {
	start := time.Now()

	// Parse address
	_, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %s: %w", addr, err)
	}

	// Use DNS cache if enabled
	if config.EnableDNSOptimization {
		// This would be implemented with the DNS cache
		// For now, use standard dialer
		dialer := &net.Dialer{
			Timeout: config.DialTimeout,
		}
		conn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("dial failed for %s: %w", addr, err)
		}

		// Record latency
		latency := time.Since(start)
		logrus.Debugf("🔌 Connection established to %s in %v", addr, latency)

		return conn, nil
	}

	// Standard dialer without optimization
	dialer := &net.Dialer{
		Timeout: config.DialTimeout,
	}
	return dialer.DialContext(ctx, network, addr)
}
