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

package cache

import (
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
)

// LocalFileCache implements LayerCache interface for local filesystem cache
// This allows UnifiedCache to use local filesystem as an additional cache source
type LocalFileCache struct {
	Opts *config.CacheOptions
}

// NewLocalFileCache creates a new local file cache
func NewLocalFileCache(opts *config.CacheOptions) *LocalFileCache {
	return &LocalFileCache{
		Opts: opts,
	}
}

// RetrieveLayer retrieves a layer from the local filesystem cache
func (lfc *LocalFileCache) RetrieveLayer(cacheKey string) (v1.Image, error) {
	if lfc.Opts == nil || lfc.Opts.CacheDir == "" {
		return nil, ErrCacheMiss
	}

	img, err := LocalSource(lfc.Opts, cacheKey)
	if err != nil {
		// LocalSource returns NotFoundErr or ExpiredErr, which we should treat as cache miss
		if _, ok := err.(NotFoundErr); ok {
			logrus.Debugf("Cache miss in local file cache for key: %s", cacheKey)
			return nil, ErrCacheMiss
		}
		if _, ok := err.(ExpiredErr); ok {
			logrus.Debugf("Cache expired in local file cache for key: %s", cacheKey)
			return nil, ErrCacheMiss
		}
		return nil, err
	}

	logrus.Debugf("Cache hit in local file cache for key: %s", cacheKey)
	return img, nil
}

// LayerCache interface implementation
var _ LayerCache = (*LocalFileCache)(nil)
