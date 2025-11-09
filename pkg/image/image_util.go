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

// Package image provides utilities for working with container images,
// including retrieval from remote registries and local cache.
package image

import (
	"fmt"
	"path/filepath"
	"strconv"

	"github.com/Gosayram/kaniko/pkg/cache"
	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/constants"
	"github.com/Gosayram/kaniko/pkg/image/remote"
	"github.com/Gosayram/kaniko/pkg/timing"
	"github.com/Gosayram/kaniko/pkg/util"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var (
	// RetrieveRemoteImage downloads an image from a remote location
	RetrieveRemoteImage = remote.RetrieveRemoteImage
	retrieveTarImage    = tarballImage
)

// RetrieveSourceImage returns the base image of the stage at index
func RetrieveSourceImage(stage *config.KanikoStage, opts *config.KanikoOptions) (v1.Image, error) {
	t := timing.Start("Retrieving Source Image")
	defer timing.DefaultRun.Stop(t)

	buildArgs := buildArgsFromStage(stage, opts)
	currentBaseName, err := resolveBaseName(stage.BaseName, buildArgs)
	if err != nil {
		return nil, err
	}

	if img := checkScratchImage(currentBaseName); img != nil {
		return img, nil
	}

	if img, err := checkStoredImage(stage); err != nil {
		return nil, err
	} else if img != nil {
		return img, nil
	}

	if img := checkCachedImage(opts, currentBaseName); img != nil {
		return img, nil
	}

	if err := validateSourcePolicy(opts, currentBaseName); err != nil {
		return nil, err
	}

	return retrieveRemoteImage(currentBaseName, opts)
}

func buildArgsFromStage(stage *config.KanikoStage, opts *config.KanikoOptions) []string {
	var buildArgs []string
	for _, marg := range stage.MetaArgs {
		for _, arg := range marg.Args {
			buildArgs = append(buildArgs, fmt.Sprintf("%s=%s", arg.Key, arg.ValueString()))
		}
	}
	return append(buildArgs, opts.BuildArgs...)
}

func resolveBaseName(baseName string, buildArgs []string) (string, error) {
	return util.ResolveEnvironmentReplacement(baseName, buildArgs, false)
}

func checkScratchImage(currentBaseName string) v1.Image {
	if currentBaseName == constants.NoBaseImage {
		logrus.Info("No base image, nothing to extract")
		return empty.Image
	}
	return nil
}

func checkStoredImage(stage *config.KanikoStage) (v1.Image, error) {
	if stage.BaseImageStoredLocally {
		return retrieveTarImage(stage.BaseImageIndex)
	}
	return nil, nil
}

func checkCachedImage(opts *config.KanikoOptions, currentBaseName string) v1.Image {
	if !opts.Cache || opts.CacheDir == "" {
		return nil
	}

	cachedImg, cacheErr := cachedImage(opts, currentBaseName)
	if cacheErr != nil {
		handleCacheError(cacheErr, currentBaseName)
		return nil
	}
	return cachedImg
}

func handleCacheError(cacheErr error, currentBaseName string) {
	switch {
	case cache.IsNotFound(cacheErr):
		logrus.Debugf("Image %v not found in cache", currentBaseName)
	case cache.IsExpired(cacheErr):
		logrus.Debugf("Image %v found in cache but was expired", currentBaseName)
	default:
		logrus.Errorf("Error while retrieving image from cache: %v %v", currentBaseName, cacheErr)
	}
}

func validateSourcePolicy(opts *config.KanikoOptions, currentBaseName string) error {
	if opts.SourcePolicy == nil {
		return nil
	}

	type SourcePolicyValidator interface {
		Validate(ref name.Reference) error
	}
	policy, ok := opts.SourcePolicy.(SourcePolicyValidator)
	if !ok {
		return nil
	}

	ref, parseErr := name.ParseReference(currentBaseName, name.WeakValidation)
	if parseErr != nil {
		return errors.Wrapf(parseErr, "failed to parse image reference: %s", currentBaseName)
	}

	if validateErr := policy.Validate(ref); validateErr != nil {
		return errors.Wrapf(validateErr, "source policy validation failed for %s", currentBaseName)
	}

	logrus.Debugf("Source policy validation passed for %s", currentBaseName)
	return nil
}

func retrieveRemoteImage(currentBaseName string, opts *config.KanikoOptions) (v1.Image, error) {
	image, err := RetrieveRemoteImage(currentBaseName, &opts.RegistryOptions, opts.CustomPlatform)
	if err != nil {
		logrus.Warnf("Failed to retrieve image %s: %v", currentBaseName, err)
		logrus.Warnf("This might be due to registry unavailability.")
		return nil, err
	}

	// Optionally wrap with LazyImage for memory optimization
	if opts.EnableLazyImageLoading {
		lazyImg, lazyErr := NewLazyImage(image)
		if lazyErr != nil {
			logrus.Warnf("Failed to create lazy image wrapper: %v, using original image", lazyErr)
			return image, nil
		}
		logrus.Debugf("Using lazy image loading for %s (memory optimization)", currentBaseName)
		return lazyImg, nil
	}

	return image, nil
}

func tarballImage(index int) (v1.Image, error) {
	tarPath := filepath.Join(config.KanikoIntermediateStagesDir, strconv.Itoa(index))
	logrus.Infof("Base image from previous stage %d found, using saved tar at path %s", index, tarPath)
	return tarball.ImageFromPath(tarPath, nil)
}

func cachedImage(opts *config.KanikoOptions, image string) (v1.Image, error) {
	ref, err := name.ParseReference(image, name.WeakValidation)
	if err != nil {
		return nil, err
	}

	var cacheKey string
	if d, ok := ref.(name.Digest); ok {
		cacheKey = d.DigestStr()
	} else {
		image, err := remote.RetrieveRemoteImage(image, &opts.RegistryOptions, opts.CustomPlatform)
		if err != nil {
			return nil, err
		}

		d, err := image.Digest()
		if err != nil {
			return nil, err
		}
		cacheKey = d.String()
	}
	return cache.LocalSource(&opts.CacheOptions, cacheKey)
}
