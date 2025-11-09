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

// Package plugin provides a modular plugin architecture for Kaniko
// Inspired by BuildKit's pluggable architecture
package plugin

import (
	"fmt"
	"sync"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/cache"
	"github.com/Gosayram/kaniko/pkg/config"
)

// ExecutorFactory creates an executor instance
// Returns interface{} to allow different executor types
type ExecutorFactory func(opts *config.KanikoOptions) (interface{}, error)

// CacheFactory creates a cache instance
type CacheFactory func(opts *config.KanikoOptions) (cache.LayerCache, error)

// SnapshotterFactory creates a snapshotter instance
// Returns interface{} to allow different snapshotter types
type SnapshotterFactory func(opts *config.KanikoOptions) (interface{}, error)

// Registry manages plugin registration and creation
type Registry struct {
	executors map[string]ExecutorFactory
	caches    map[string]CacheFactory
	snapshots map[string]SnapshotterFactory
	mu        sync.RWMutex
}

// NewRegistry creates a new plugin registry
func NewRegistry() *Registry {
	return &Registry{
		executors: make(map[string]ExecutorFactory),
		caches:    make(map[string]CacheFactory),
		snapshots: make(map[string]SnapshotterFactory),
	}
}

// RegisterExecutor registers an executor factory
func (r *Registry) RegisterExecutor(name string, factory ExecutorFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.executors[name]; exists {
		logrus.Warnf("Executor %s already registered, overwriting", name)
	}
	r.executors[name] = factory
	logrus.Debugf("Registered executor: %s", name)
}

// RegisterCache registers a cache factory
func (r *Registry) RegisterCache(name string, factory CacheFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.caches[name]; exists {
		logrus.Warnf("Cache %s already registered, overwriting", name)
	}
	r.caches[name] = factory
	logrus.Debugf("Registered cache: %s", name)
}

// RegisterSnapshotter registers a snapshotter factory
func (r *Registry) RegisterSnapshotter(name string, factory SnapshotterFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.snapshots[name]; exists {
		logrus.Warnf("Snapshotter %s already registered, overwriting", name)
	}
	r.snapshots[name] = factory
	logrus.Debugf("Registered snapshotter: %s", name)
}

// CreateExecutor creates an executor instance by name
func (r *Registry) CreateExecutor(name string, opts *config.KanikoOptions) (interface{}, error) {
	r.mu.RLock()
	factory, ok := r.executors[name]
	r.mu.RUnlock()

	if !ok {
		return nil, errors.Errorf("unknown executor: %s", name)
	}

	exec, err := factory(opts)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create executor %s", name)
	}

	return exec, nil
}

// CreateCache creates a cache instance by name
func (r *Registry) CreateCache(name string, opts *config.KanikoOptions) (cache.LayerCache, error) {
	r.mu.RLock()
	factory, ok := r.caches[name]
	r.mu.RUnlock()

	if !ok {
		return nil, errors.Errorf("unknown cache: %s", name)
	}

	c, err := factory(opts)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create cache %s", name)
	}

	return c, nil
}

// CreateSnapshotter creates a snapshotter instance by name
func (r *Registry) CreateSnapshotter(name string, opts *config.KanikoOptions) (interface{}, error) {
	r.mu.RLock()
	factory, ok := r.snapshots[name]
	r.mu.RUnlock()

	if !ok {
		return nil, errors.Errorf("unknown snapshotter: %s", name)
	}

	s, err := factory(opts)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create snapshotter %s", name)
	}

	return s, nil
}

// ListExecutors returns a list of registered executor names
func (r *Registry) ListExecutors() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.executors))
	for name := range r.executors {
		names = append(names, name)
	}
	return names
}

// ListCaches returns a list of registered cache names
func (r *Registry) ListCaches() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.caches))
	for name := range r.caches {
		names = append(names, name)
	}
	return names
}

// ListSnapshots returns a list of registered snapshotter names
func (r *Registry) ListSnapshots() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.snapshots))
	for name := range r.snapshots {
		names = append(names, name)
	}
	return names
}

// GetStats returns registry statistics
func (r *Registry) GetStats() map[string]interface{} {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return map[string]interface{}{
		"executors": len(r.executors),
		"caches":    len(r.caches),
		"snapshots": len(r.snapshots),
	}
}

// String returns a string representation of the registry
func (r *Registry) String() string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return fmt.Sprintf("Registry(executors=%d, caches=%d, snapshots=%d)",
		len(r.executors), len(r.caches), len(r.snapshots))
}

// Global registry instance
var globalRegistry *Registry
var globalRegistryOnce sync.Once

// GetGlobalRegistry returns the global plugin registry
func GetGlobalRegistry() *Registry {
	globalRegistryOnce.Do(func() {
		globalRegistry = NewRegistry()
	})
	return globalRegistry
}

// ErrUnknownExecutor is returned when executor is not found
var ErrUnknownExecutor = errors.New("unknown executor")

// ErrUnknownCache is returned when cache is not found
var ErrUnknownCache = errors.New("unknown cache")

// ErrUnknownSnapshotter is returned when snapshotter is not found
var ErrUnknownSnapshotter = errors.New("unknown snapshotter")
