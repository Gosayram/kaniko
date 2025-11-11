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

// Package cache provides interfaces and implementations for caching container image layers.
package cache

import (
	"fmt"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/http2"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/creds"
	"github.com/Gosayram/kaniko/pkg/util"
)

const (
	defaultIdleConnTimeout     = 90 * time.Second
	defaultCacheRequestTimeout = 30 * time.Second
	defaultCacheResultTTL      = 5 * time.Minute
)

// LayerCache is the layer cache
type LayerCache interface {
	RetrieveLayer(string) (v1.Image, error)
	// RetrieveLayersBatch retrieves multiple layers in parallel
	// Returns a map of cache key to image (or error if not found)
	// This allows parallel downloading/verification while maintaining order of application
	RetrieveLayersBatch(keys []string) map[string]LayerResult
}

// LayerResult represents the result of retrieving a layer
type LayerResult struct {
	Image v1.Image
	Error error
}

// RegistryCache is the registry cache with connection pooling support
type RegistryCache struct {
	Opts        *config.KanikoOptions
	client      *http.Client
	mu          sync.Mutex   // Protects client initialization
	resultCache *ResultCache // In-memory cache for results
}

// initClient initializes the HTTP client with connection pooling if not already initialized
func (rc *RegistryCache) initClient(registryName string) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Double-check pattern: client might have been initialized while we were waiting
	if rc.client != nil {
		return nil
	}

	// Get base transport with TLS configuration
	baseTransport, err := util.MakeTransport(&rc.Opts.RegistryOptions, registryName)
	if err != nil {
		return errors.Wrapf(err, "making base transport for registry %q", registryName)
	}

	// Clone and configure transport for connection pooling
	transport := baseTransport.(*http.Transport).Clone()

	// Set connection pooling parameters
	maxConns := rc.Opts.CacheMaxConns
	if maxConns <= 0 {
		maxConns = 10 // Default
	}
	maxConnsPerHost := rc.Opts.CacheMaxConnsPerHost
	if maxConnsPerHost <= 0 {
		maxConnsPerHost = 5 // Default
	}

	transport.MaxIdleConns = maxConns
	transport.MaxIdleConnsPerHost = maxConnsPerHost
	transport.IdleConnTimeout = defaultIdleConnTimeout
	transport.DisableKeepAlives = false

	// Configure HTTP/2 with fallback to HTTP/1.1
	if !rc.Opts.CacheDisableHTTP2 {
		// Try to enable HTTP/2
		if err := http2.ConfigureTransport(transport); err != nil {
			logrus.Warnf("Failed to configure HTTP/2 for cache transport, falling back to HTTP/1.1: %v", err)
			// HTTP/1.1 will be used automatically
		} else {
			logrus.Debugf("HTTP/2 enabled for cache transport")
		}
	} else {
		logrus.Debugf("HTTP/2 disabled for cache transport (using HTTP/1.1)")
		// Explicitly disable HTTP/2
		transport.ForceAttemptHTTP2 = false
	}

	// Set request timeout
	requestTimeout := rc.Opts.CacheRequestTimeout
	if requestTimeout <= 0 {
		requestTimeout = defaultCacheRequestTimeout
	}

	// Create HTTP client with connection pooling
	rc.client = &http.Client{
		Transport: transport,
		Timeout:   requestTimeout,
	}

	logrus.Debugf("Initialized cache HTTP client with connection pooling (maxConns=%d, maxConnsPerHost=%d, timeout=%v)",
		maxConns, maxConnsPerHost, requestTimeout)

	return nil
}

// initResultCache initializes the result cache if not already done
func (rc *RegistryCache) initResultCache() {
	rc.mu.Lock()
	defer rc.mu.Unlock()

	if rc.resultCache != nil {
		return
	}

	// Get configuration values
	ttl := rc.Opts.CacheResultTTL
	if ttl <= 0 {
		ttl = defaultCacheResultTTL
	}
	maxEntries := rc.Opts.CacheResultMaxEntries
	if maxEntries <= 0 {
		maxEntries = 1000 // Default
	}
	maxMemoryMB := rc.Opts.CacheResultMaxMemoryMB
	if maxMemoryMB <= 0 {
		maxMemoryMB = 100 // Default
	}

	rc.resultCache = NewResultCache(maxEntries, maxMemoryMB, ttl)
	logrus.Debugf("Initialized result cache (maxEntries=%d, maxMemoryMB=%d, ttl=%v)",
		maxEntries, maxMemoryMB, ttl)
}

// RetrieveLayer retrieves a layer from the cache given the cache key ck.
func (rc *RegistryCache) RetrieveLayer(ck string) (v1.Image, error) {
	// Initialize result cache if not already done
	if rc.resultCache == nil {
		rc.initResultCache()
	}

	// Check result cache first
	if cachedResult, found := rc.resultCache.Get(ck); found {
		logrus.Debugf("Cache result cache hit for key: %s", ck)
		if cachedResult.Error != nil {
			return nil, cachedResult.Error
		}
		return cachedResult.Image, nil
	}

	// Cache miss - perform actual lookup
	cache, err := Destination(rc.Opts, ck)
	if err != nil {
		return nil, errors.Wrap(err, "getting cache destination")
	}
	logrus.Infof("Checking for cached layer %s...", cache)

	cacheRef, err := name.NewTag(cache, name.WeakValidation)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("getting reference for %s", cache))
	}

	registryName := cacheRef.Context().Registry.Name()
	if rc.Opts.Insecure || rc.Opts.InsecureRegistries.Contains(registryName) {
		cacheRef, err = name.NewTag(cache, name.WeakValidation, name.Insecure)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("getting insecure reference for %s", cache))
		}
	}

	// Initialize client with connection pooling if not already done
	if rc.client == nil {
		if initErr := rc.initClient(registryName); initErr != nil {
			return nil, initErr
		}
	}

	// Get transport from the pooled client
	transport := rc.client.Transport

	// Use the pooled client's transport for the request
	keychain := creds.GetKeychain(&rc.Opts.RegistryOptions)
	img, err := remote.Image(
		cacheRef,
		remote.WithTransport(transport),
		remote.WithAuthFromKeychain(keychain),
	)
	if err != nil {
		// Cache the error result
		rc.resultCache.Set(ck, nil, err)
		return nil, err
	}

	if err := verifyImage(img, rc.Opts.CacheTTL, cache); err != nil {
		// Cache the error result
		rc.resultCache.Set(ck, nil, err)
		return nil, err
	}

	// Cache the successful result
	rc.resultCache.Set(ck, img, nil)
	return img, nil
}

// retrieveLayersBatchHelper is a helper function to retrieve multiple layers in parallel
func retrieveLayersBatchHelper(
	keys []string,
	retrieveFunc func(string) (v1.Image, error),
	opts *config.KanikoOptions,
) map[string]LayerResult {
	results := make(map[string]LayerResult)
	if len(keys) == 0 {
		return results
	}

	// Get max concurrent from options
	maxConcurrent := opts.LayerLoadMaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 3 // Default
	}

	// Use semaphore to limit concurrent requests
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, key := range keys {
		wg.Add(1)
		go func(ck string) {
			defer wg.Done()

			// Acquire semaphore
			sem <- struct{}{}
			defer func() { <-sem }()

			// Retrieve layer (uses result cache internally)
			img, err := retrieveFunc(ck)

			// Store result
			mu.Lock()
			results[ck] = LayerResult{
				Image: img,
				Error: err,
			}
			mu.Unlock()
		}(key)
	}

	wg.Wait()
	return results
}

// RetrieveLayersBatch retrieves multiple layers in parallel
// This allows parallel downloading/verification while maintaining order of application
func (rc *RegistryCache) RetrieveLayersBatch(keys []string) map[string]LayerResult {
	return retrieveLayersBatchHelper(keys, rc.RetrieveLayer, rc.Opts)
}

func verifyImage(img v1.Image, cacheTTL time.Duration, cache string) error {
	cf, err := img.ConfigFile()
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("retrieving config file for %s", cache))
	}

	expiry := cf.Created.Add(cacheTTL)
	// Layer is stale, rebuild it.
	if expiry.Before(time.Now()) {
		logrus.Infof("Cache entry expired: %s", cache)
		return fmt.Errorf("cache entry expired: %s", cache)
	}

	// Force the manifest to be populated
	if _, err := img.RawManifest(); err != nil {
		return err
	}
	return nil
}

// LayoutCache is the OCI image layout cache
type LayoutCache struct {
	Opts        *config.KanikoOptions
	resultCache *ResultCache // In-memory cache for results
	mu          sync.Mutex   // Protects result cache initialization
}

// initResultCache initializes the result cache if not already done
func (lc *LayoutCache) initResultCache() {
	lc.mu.Lock()
	defer lc.mu.Unlock()

	if lc.resultCache != nil {
		return
	}

	// Get configuration values
	ttl := lc.Opts.CacheResultTTL
	if ttl <= 0 {
		ttl = defaultCacheResultTTL
	}
	maxEntries := lc.Opts.CacheResultMaxEntries
	if maxEntries <= 0 {
		maxEntries = 1000 // Default
	}
	maxMemoryMB := lc.Opts.CacheResultMaxMemoryMB
	if maxMemoryMB <= 0 {
		maxMemoryMB = 100 // Default
	}

	lc.resultCache = NewResultCache(maxEntries, maxMemoryMB, ttl)
	logrus.Debugf("Initialized result cache for layout cache (maxEntries=%d, maxMemoryMB=%d, ttl=%v)",
		maxEntries, maxMemoryMB, ttl)
}

// RetrieveLayer retrieves a layer from the OCI layout cache given the cache key ck.
func (lc *LayoutCache) RetrieveLayer(ck string) (v1.Image, error) {
	// Initialize result cache if not already done
	if lc.resultCache == nil {
		lc.initResultCache()
	}

	// Check result cache first
	if cachedResult, found := lc.resultCache.Get(ck); found {
		logrus.Debugf("Cache result cache hit for key: %s", ck)
		if cachedResult.Error != nil {
			return nil, cachedResult.Error
		}
		return cachedResult.Image, nil
	}

	// Cache miss - perform actual lookup
	cache, err := Destination(lc.Opts, ck)
	if err != nil {
		return nil, errors.Wrap(err, "getting cache destination")
	}
	logrus.Infof("Checking for cached layer %s...", cache)

	var img v1.Image
	if img, err = locateImage(strings.TrimPrefix(cache, "oci:")); err != nil {
		// Cache the error result
		lc.resultCache.Set(ck, nil, err)
		return nil, errors.Wrap(err, "locating cache image")
	}

	if err := verifyImage(img, lc.Opts.CacheTTL, cache); err != nil {
		// Cache the error result
		lc.resultCache.Set(ck, nil, err)
		return nil, err
	}

	// Cache the successful result
	lc.resultCache.Set(ck, img, nil)
	return img, nil
}

// RetrieveLayersBatch retrieves multiple layers in parallel
// This allows parallel downloading/verification while maintaining order of application
func (lc *LayoutCache) RetrieveLayersBatch(keys []string) map[string]LayerResult {
	return retrieveLayersBatchHelper(keys, lc.RetrieveLayer, lc.Opts)
}

func locateImage(imagePath string) (v1.Image, error) {
	var img v1.Image
	layoutPath, err := layout.FromPath(imagePath)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("constructing layout path from %s", imagePath))
	}
	index, err := layoutPath.ImageIndex()
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("retrieving index file for %s", layoutPath))
	}
	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("retrieving manifest file for %s", layoutPath))
	}
	for i := range manifest.Manifests {
		m := &manifest.Manifests[i]
		// assume there is only one image
		img, err = layoutPath.Image(m.Digest)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("initializing image with digest %s", m.Digest.String()))
		}
	}
	if img == nil {
		return nil, fmt.Errorf("path contains no images")
	}
	return img, nil
}

// Destination returns the repo where the layer should be stored
// If no cache is specified, one is inferred from the destination provided
func Destination(opts *config.KanikoOptions, cacheKey string) (string, error) {
	cache := opts.CacheRepo
	if cache == "" {
		destination := opts.Destinations[0]
		destRef, err := name.NewTag(destination, name.WeakValidation)
		if err != nil {
			return "", errors.Wrap(err, "getting tag for destination")
		}
		return fmt.Sprintf("%s/cache:%s", destRef.Context(), cacheKey), nil
	}
	return fmt.Sprintf("%s:%s", cache, cacheKey), nil
}

// LocalSource retrieves a source image from a local cache given cacheKey
func LocalSource(opts *config.CacheOptions, cacheKey string) (v1.Image, error) {
	cache := opts.CacheDir
	if cache == "" {
		return nil, nil
	}

	cachePath := path.Join(cache, cacheKey)

	fi, err := os.Stat(cachePath)
	if err != nil {
		msg := fmt.Sprintf("No file found for cache key %v %v", cacheKey, err)
		logrus.Debug(msg)
		return nil, NotFoundErr{msg: msg}
	}

	// A stale cache is a bad cache
	expiry := fi.ModTime().Add(opts.CacheTTL)
	if expiry.Before(time.Now()) {
		msg := fmt.Sprintf("Cached image is too old: %v", fi.ModTime())
		logrus.Debug(msg)
		return nil, ExpiredErr{msg: msg}
	}

	logrus.Infof("Found %s in local cache", cacheKey)
	return cachedImageFromPath(cachePath)
}

// cachedImage represents a v1.Tarball that is cached locally in a CAS.
// Computing the digest for a v1.Tarball is very expensive. If the tarball
// is named with the digest we can store this and return it directly rather
// than recompute it.
type cachedImage struct {
	digest string
	v1.Image
	mfst *v1.Manifest
}

func (c *cachedImage) Digest() (v1.Hash, error) {
	return v1.NewHash(c.digest)
}

func (c *cachedImage) Manifest() (*v1.Manifest, error) {
	if c.mfst == nil {
		return c.Image.Manifest()
	}
	return c.mfst, nil
}

func mfstFromPath(p string) (*v1.Manifest, error) {
	// Validate the file path to prevent directory traversal
	cleanPath := filepath.Clean(p)
	if strings.Contains(cleanPath, "..") || strings.HasPrefix(cleanPath, "/") {
		return nil, fmt.Errorf("invalid file path: potential directory traversal detected")
	}
	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return v1.ParseManifest(f)
}

func cachedImageFromPath(p string) (v1.Image, error) {
	imgTar, err := tarball.ImageFromPath(p, nil)
	if err != nil {
		return nil, errors.Wrap(err, "getting image from path")
	}

	// Manifests may be present next to the tar, named with a ".json" suffix
	mfstPath := p + ".json"

	var mfst *v1.Manifest
	if _, err := os.Stat(mfstPath); err != nil {
		logrus.Debugf("Manifest does not exist at file: %s", mfstPath)
	} else {
		mfst, err = mfstFromPath(mfstPath)
		if err != nil {
			logrus.Debugf("Error parsing manifest from file: %s", mfstPath)
		} else {
			logrus.Infof("Found manifest at %s", mfstPath)
		}
	}

	return &cachedImage{
		digest: filepath.Base(p),
		Image:  imgTar,
		mfst:   mfst,
	}, nil
}
