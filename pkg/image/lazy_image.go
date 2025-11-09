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

package image

import (
	"context"
	"encoding/json"
	"sync"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// LayerProvider provides layers on demand, supporting remote providers
// This allows for lazy loading from various sources (registry, S3, etc.)
type LayerProvider interface {
	// Load loads a layer by descriptor
	Load(ctx context.Context, desc v1.Descriptor) (v1.Layer, error)
	// Probe checks if a layer exists without loading it
	Probe(ctx context.Context, desc v1.Descriptor) (bool, error)
}

// LazyImage wraps a v1.Image and loads layers only when needed
// This provides memory efficiency by avoiding loading all layers at once
// Inspired by BuildKit's lazy loading approach
type LazyImage struct {
	image        v1.Image
	manifest     *v1.Manifest
	config       *v1.ConfigFile
	layers       []LazyLayer
	loadedLayers map[int]v1.Layer
	providers    map[string]LayerProvider // Provider for each layer digest
	mutex        sync.RWMutex
}

// LazyLayer represents a layer that can be loaded on demand
type LazyLayer struct {
	Descriptor v1.Descriptor
	Loader     func() (v1.Layer, error)
	Provider   LayerProvider // Optional remote provider
	loaded     bool          // Whether layer has been loaded
}

// NewLazyImage creates a new LazyImage from a v1.Image
func NewLazyImage(img v1.Image) (*LazyImage, error) {
	manifest, err := img.RawManifest()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get manifest")
	}

	var parsedManifest v1.Manifest
	if unmarshalErr := json.Unmarshal(manifest, &parsedManifest); unmarshalErr != nil {
		return nil, errors.Wrap(unmarshalErr, "failed to parse manifest")
	}

	config, err := img.ConfigFile()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get config file")
	}

	// Create lazy layers from manifest
	layers := make([]LazyLayer, len(parsedManifest.Layers))
	for i := range parsedManifest.Layers {
		layerIndex := i
		layerDesc := &parsedManifest.Layers[i]
		layers[i] = LazyLayer{
			Descriptor: *layerDesc,
			Loader: func() (v1.Layer, error) {
				// Load layer from image on demand
				allLayers, err := img.Layers()
				if err != nil {
					return nil, errors.Wrapf(err, "failed to get layers for lazy loading")
				}
				if layerIndex >= len(allLayers) {
					return nil, errors.Errorf("layer index %d out of range", layerIndex)
				}
				logrus.Debugf("Lazy loading layer %d (digest: %s)", layerIndex, layerDesc.Digest.String())
				return allLayers[layerIndex], nil
			},
		}
	}

	return &LazyImage{
		image:        img,
		manifest:     &parsedManifest,
		config:       config,
		layers:       layers,
		loadedLayers: make(map[int]v1.Layer),
		providers:    make(map[string]LayerProvider),
	}, nil
}

// Layers returns all layers, loading them on demand
func (li *LazyImage) Layers() ([]v1.Layer, error) {
	li.mutex.Lock()
	defer li.mutex.Unlock()

	layers := make([]v1.Layer, len(li.layers))
	for i := range li.layers {
		if loaded, exists := li.loadedLayers[i]; exists {
			layers[i] = loaded
		} else {
			loaded, err := li.layers[i].Loader()
			if err != nil {
				return nil, errors.Wrapf(err, "failed to load layer %d", i)
			}
			li.loadedLayers[i] = loaded
			layers[i] = loaded
		}
	}
	return layers, nil
}

// LayerByIndex returns a specific layer by index, loading it if necessary
func (li *LazyImage) LayerByIndex(index int) (v1.Layer, error) {
	return li.LayerByIndexWithContext(context.Background(), index)
}

// LayerByIndexWithContext returns a specific layer by index, loading it if necessary
func (li *LazyImage) LayerByIndexWithContext(ctx context.Context, index int) (v1.Layer, error) {
	li.mutex.RLock()
	if loaded, exists := li.loadedLayers[index]; exists {
		li.mutex.RUnlock()
		return loaded, nil
	}
	li.mutex.RUnlock()

	// Need to load the layer
	li.mutex.Lock()
	defer li.mutex.Unlock()

	// Double-check after acquiring write lock
	if loaded, exists := li.loadedLayers[index]; exists {
		return loaded, nil
	}

	if index >= len(li.layers) {
		return nil, errors.Errorf("layer index %d out of range", index)
	}

	layer := li.layers[index]
	var loaded v1.Layer
	var err error

	// Try provider first if available
	if layer.Provider != nil {
		loaded, err = layer.Provider.Load(ctx, layer.Descriptor)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load layer %d from provider", index)
		}
	} else if loader := layer.Loader; loader != nil {
		loaded, err = loader()
		if err != nil {
			return nil, errors.Wrapf(err, "failed to load layer %d", index)
		}
	} else {
		return nil, errors.Errorf("no loader or provider for layer %d", index)
	}

	li.loadedLayers[index] = loaded
	li.layers[index].loaded = true
	return loaded, nil
}

// Digest returns the image digest
func (li *LazyImage) Digest() (v1.Hash, error) {
	return li.image.Digest()
}

// Manifest returns the manifest
func (li *LazyImage) Manifest() (*v1.Manifest, error) {
	return li.manifest, nil
}

// RawManifest returns the raw manifest bytes
func (li *LazyImage) RawManifest() ([]byte, error) {
	return li.image.RawManifest()
}

// ConfigName returns the config name
func (li *LazyImage) ConfigName() (v1.Hash, error) {
	return li.image.ConfigName()
}

// ConfigFile returns the config file
func (li *LazyImage) ConfigFile() (*v1.ConfigFile, error) {
	return li.config, nil
}

// RawConfigFile returns the raw config file bytes
func (li *LazyImage) RawConfigFile() ([]byte, error) {
	return li.image.RawConfigFile()
}

// MediaType returns the media type
func (li *LazyImage) MediaType() (types.MediaType, error) {
	return li.image.MediaType()
}

// Size returns the size of the image
func (li *LazyImage) Size() (int64, error) {
	return li.image.Size()
}

// LayerByDigest returns a layer by digest (compressed hash)
func (li *LazyImage) LayerByDigest(h v1.Hash) (v1.Layer, error) {
	// Find layer by digest
	for i := range li.layers {
		if li.layers[i].Descriptor.Digest == h {
			return li.LayerByIndex(i)
		}
	}
	return li.image.LayerByDigest(h)
}

// LayerByDiffID returns a layer by diff ID (uncompressed hash)
func (li *LazyImage) LayerByDiffID(h v1.Hash) (v1.Layer, error) {
	// For lazy loading, we need to check config file for diff IDs
	config, err := li.ConfigFile()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get config file")
	}

	// Find layer by diff ID in config
	for i, diffID := range config.RootFS.DiffIDs {
		if diffID == h {
			return li.LayerByIndex(i)
		}
	}
	return li.image.LayerByDiffID(h)
}

// GetLoadedLayersCount returns the number of currently loaded layers
func (li *LazyImage) GetLoadedLayersCount() int {
	li.mutex.RLock()
	defer li.mutex.RUnlock()
	return len(li.loadedLayers)
}

// GetTotalLayersCount returns the total number of layers
func (li *LazyImage) GetTotalLayersCount() int {
	return len(li.layers)
}

// ClearLoadedLayers clears the loaded layers cache (useful for memory management)
func (li *LazyImage) ClearLoadedLayers() {
	li.mutex.Lock()
	defer li.mutex.Unlock()
	li.loadedLayers = make(map[int]v1.Layer)
	// Reset loaded flags
	for i := range li.layers {
		li.layers[i].loaded = false
	}
	logrus.Debugf("Cleared loaded layers cache")
}

// SetLayerProvider sets a provider for a specific layer
func (li *LazyImage) SetLayerProvider(digest string, provider LayerProvider) {
	li.mutex.Lock()
	defer li.mutex.Unlock()
	li.providers[digest] = provider
}

// Mount loads layers only when mounting (BuildKit-style)
func (li *LazyImage) Mount(ctx context.Context, path string) error {
	li.mutex.Lock()
	defer li.mutex.Unlock()

	// Load layers only when mounting
	for i, layer := range li.layers {
		if !layer.loaded {
			var loaded v1.Layer
			var err error

			// Try provider first if available
			if layer.Provider != nil {
				loaded, err = layer.Provider.Load(ctx, layer.Descriptor)
				if err != nil {
					return errors.Wrapf(err, "failed to load layer %d from provider", i)
				}
			} else if loader := layer.Loader; loader != nil {
				loaded, err = loader()
				if err != nil {
					return errors.Wrapf(err, "failed to load layer %d", i)
				}
			} else {
				return errors.Errorf("no loader or provider for layer %d", i)
			}

			li.loadedLayers[i] = loaded
			li.layers[i].loaded = true
			logrus.Debugf("Mounted layer %d (digest: %s)", i, layer.Descriptor.Digest.String())
		}
	}

	return nil
}

// NewLazyImageWithProviders creates a new LazyImage with remote providers
func NewLazyImageWithProviders(img v1.Image, providers map[string]LayerProvider) (*LazyImage, error) {
	lazyImg, err := NewLazyImage(img)
	if err != nil {
		return nil, err
	}

	// Set providers
	for digest, provider := range providers {
		lazyImg.SetLayerProvider(digest, provider)
	}

	return lazyImg, nil
}

// Ensure v1.Image interface is implemented
var _ v1.Image = (*LazyImage)(nil)
