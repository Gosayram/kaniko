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

// Package remote provides functionality for retrieving remote container images.
package remote

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/creds"
	"github.com/Gosayram/kaniko/pkg/retry"
	"github.com/Gosayram/kaniko/pkg/util"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultImageRetryMaxDelay is the default maximum delay for image download retry operations
	DefaultImageRetryMaxDelay = 30 * time.Second
	// DefaultImageRetryBackoff is the default exponential backoff multiplier for image downloads
	DefaultImageRetryBackoff = 2.0
)

var (
	manifestCache   = make(map[string]v1.Image)
	remoteImageFunc = remote.Image
)

// RetrieveRemoteImage retrieves the manifest for the specified image from the specified registry
func RetrieveRemoteImage(image string, opts *config.RegistryOptions, customPlatform string) (v1.Image, error) {
	logrus.Infof("Retrieving image manifest %s", image)

	cachedRemoteImage := manifestCache[image]
	if cachedRemoteImage != nil {
		logrus.Infof("Returning cached image manifest")
		return cachedRemoteImage, nil
	}

	ref, err := name.ParseReference(image, name.WeakValidation)
	if err != nil {
		return nil, err
	}

	if newRegURLs, found := opts.RegistryMaps[ref.Context().RegistryStr()]; found {
		for _, registryMapping := range newRegURLs {
			regToMapTo, repositoryPrefix := parseRegistryMapping(registryMapping)

			insecurePull := opts.InsecurePull || opts.InsecureRegistries.Contains(regToMapTo)

			remappedRepository, remapErr := remapRepository(ref.Context(), regToMapTo, repositoryPrefix, insecurePull)
			if err != nil {
				return nil, remapErr
			}

			remappedRef := setNewRepository(ref, remappedRepository)

			logrus.Infof("Retrieving image %s from mapped registry %s", remappedRef, regToMapTo)
			retryFunc := func() (v1.Image, error) {
				return remoteImageFunc(remappedRef, remoteOptions(regToMapTo, opts, customPlatform)...)
			}

			// Use new retry mechanism with exponential backoff
			retryConfig := retry.NewRetryConfigBuilder().
				WithMaxAttempts(opts.ImageDownloadRetry + 1). // +1 because first attempt is not a retry
				WithInitialDelay(1 * time.Second).
				WithMaxDelay(DefaultImageRetryMaxDelay).
				WithBackoff(DefaultImageRetryBackoff).
				WithRetryableErrors(retry.IsRetryableError).
				Build()

			var remoteImage v1.Image
			if remoteImage, err = retry.RetryWithResult(context.Background(), retryConfig, retryFunc); err != nil {
				logrus.Warnf("Failed to retrieve image %s from remapped registry %s: %s. "+
					"Will try with the next registry, or fallback to the original registry.",
					remappedRef, regToMapTo, err)
				continue
			}

			manifestCache[image] = remoteImage

			return remoteImage, nil
		}

		if len(newRegURLs) > 0 && opts.SkipDefaultRegistryFallback {
			return nil, fmt.Errorf("image not found on any configured mapped registries for %s", ref)
		}
	}

	registryName := ref.Context().RegistryStr()
	if opts.InsecurePull || opts.InsecureRegistries.Contains(registryName) {
		newReg, regErr := name.NewRegistry(registryName, name.WeakValidation, name.Insecure)
		if err != nil {
			return nil, regErr
		}
		ref = setNewRegistry(ref, newReg)
	}

	logrus.Infof("Retrieving image %s from registry %s", ref, registryName)

	retryFunc := func() (v1.Image, error) {
		return remoteImageFunc(ref, remoteOptions(registryName, opts, customPlatform)...)
	}

	// Use new retry mechanism with exponential backoff
	retryConfig := retry.NewRetryConfigBuilder().
		WithMaxAttempts(opts.ImageDownloadRetry + 1). // +1 because first attempt is not a retry
		WithInitialDelay(1 * time.Second).
		WithMaxDelay(DefaultImageRetryMaxDelay).
		WithBackoff(DefaultImageRetryBackoff).
		WithRetryableErrors(retry.IsRetryableError).
		Build()

	var remoteImage v1.Image
	if remoteImage, err = retry.RetryWithResult(context.Background(), retryConfig, retryFunc); remoteImage != nil {
		manifestCache[image] = remoteImage
	}

	// Handle registry errors gracefully
	handleRegistryError(err, ref, registryName)

	return remoteImage, err
}

// remapRepository adds the {repositoryPrefix}/ to the original repo,
// and normalizes with an additional library/ if necessary
func remapRepository(repo name.Repository, regToMapTo, repositoryPrefix string,
	insecurePull bool) (name.Repository, error) {
	if insecurePull {
		return name.NewRepository(repositoryPrefix+repo.RepositoryStr(),
			name.WithDefaultRegistry(regToMapTo), name.WeakValidation, name.Insecure)
	}
	return name.NewRepository(repositoryPrefix+repo.RepositoryStr(),
		name.WithDefaultRegistry(regToMapTo), name.WeakValidation)
}

func setNewRepository(ref name.Reference, newRepo name.Repository) name.Reference {
	switch r := ref.(type) {
	case name.Tag:
		r.Repository = newRepo
		return r
	case name.Digest:
		r.Repository = newRepo
		return r
	default:
		return ref
	}
}

func setNewRegistry(ref name.Reference, newReg name.Registry) name.Reference {
	switch r := ref.(type) {
	case name.Tag:
		r.Registry = newReg
		return r
	case name.Digest:
		r.Registry = newReg
		return r
	default:
		return ref
	}
}

func remoteOptions(registryName string, opts *config.RegistryOptions, customPlatform string) []remote.Option {
	tr, err := util.MakeTransport(opts, registryName)

	// The MakeTransport function will only return errors if there was a problem
	// with registry certificates (Verification or mTLS)
	if err != nil {
		logrus.Fatalf("Unable to setup transport for registry %q: %v", customPlatform, err)
	}

	// The platform value has previously been validated.
	platform, err := v1.ParsePlatform(customPlatform)
	if err != nil {
		logrus.Fatalf("Invalid platform %q: %v", customPlatform, err)
	}

	return []remote.Option{
		remote.WithTransport(tr),
		remote.WithAuthFromKeychain(creds.GetKeychain()),
		remote.WithPlatform(*platform),
	}
}

// Parse the registry mapping
// example: regMapping = "registry.example.com/subdir1/subdir2" will return registry.example.com and subdir1/subdir2/
func parseRegistryMapping(regMapping string) (regURL, repositoryPrefix string) {
	// Split the registry mapping by first slash
	regURL, repositoryPrefix, _ = strings.Cut(regMapping, "/")

	// Normalize with a trailing slash if not empty
	if repositoryPrefix != "" && !strings.HasSuffix(repositoryPrefix, "/") {
		repositoryPrefix += "/"
	}

	return regURL, repositoryPrefix
}

// handleRegistryError handles registry errors gracefully with appropriate logging
func handleRegistryError(err error, ref name.Reference, registryName string) {
	if err == nil {
		return
	}

	logrus.Warnf("Failed to retrieve image %s from registry %s: %v", ref, registryName, err)
	logrus.Warnf("This might be due to registry unavailability (e.g., Docker Hub 503). " +
		"Consider using registry mirrors or cached images.")

	// Check if this is a network/registry issue that might be resolved by GitLab Runner's mirrors
	if strings.Contains(err.Error(), "503 Service Unavailable") ||
		strings.Contains(err.Error(), "unable to complete operation") {
		logrus.Warnf("Registry appears to be unavailable. GitLab Runner should handle this with its own mirrors.")
	}
}
