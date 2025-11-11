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

import "time"

// Network operation constants
const (
	// Connection pool defaults
	defaultMaxIdleConns        = 100
	defaultMaxIdleConnsPerHost = 10
	defaultMaxConnsPerHost     = 50
	defaultIdleConnTimeout     = 90
	defaultDialTimeout         = 30
	defaultResponseTimeout     = 30
	defaultRequestTimeout      = 60

	// Parallel client defaults
	// Conservative default: 5-8 instead of 10 to avoid excessive CPU usage with multiple parallel builds
	defaultMaxConcurrency = 5
	defaultRetryAttempts  = 3
	defaultRetryDelay     = 1

	// Registry client defaults
	defaultRegistryMaxConcurrency = 5
	defaultRegistryRequestTimeout = 60
	defaultRegistryRetryAttempts  = 3
	defaultRegistryRetryDelay     = 2
	defaultManifestCacheTimeout   = 10

	// Cache defaults
	defaultDNSCacheTimeout = 5
	cleanupIntervalMinutes = 5

	// Mathematical constants
	percentageBase = 100
	averageDivisor = 2
)

// Default timeouts
var (
	DefaultIdleConnTimeout      = defaultIdleConnTimeout * time.Second
	DefaultDialTimeout          = defaultDialTimeout * time.Second
	DefaultResponseTimeout      = defaultResponseTimeout * time.Second
	DefaultRequestTimeout       = defaultRequestTimeout * time.Second
	DefaultDNSCacheTimeout      = defaultDNSCacheTimeout * time.Minute
	DefaultManifestCacheTimeout = defaultManifestCacheTimeout * time.Minute
	DefaultCleanupInterval      = cleanupIntervalMinutes * time.Minute
)
