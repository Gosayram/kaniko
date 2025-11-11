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
	"os"
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
	// DefaultImageRetrieveTimeout is the default timeout for image retrieval operations
	DefaultImageRetrieveTimeout = 15 * time.Minute
)

var (
	manifestCache   = make(map[string]v1.Image)
	remoteImageFunc = remote.Image
)

// createImageRetrieveContext creates a context with timeout for image retrieval
func createImageRetrieveContext() (context.Context, context.CancelFunc, time.Duration) {
	timeoutStr := os.Getenv("IMAGE_RETRIEVE_TIMEOUT")
	if timeoutStr == "" {
		timeoutStr = DefaultImageRetrieveTimeout.String()
	}
	timeout, parseErr := time.ParseDuration(timeoutStr)
	if parseErr != nil {
		logrus.Warnf("Invalid IMAGE_RETRIEVE_TIMEOUT value '%s', using default %v", timeoutStr, DefaultImageRetrieveTimeout)
		timeout = DefaultImageRetrieveTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	return ctx, cancel, timeout
}

// buildRetryConfig creates a retry configuration for image downloads
func buildRetryConfig(opts *config.RegistryOptions) retry.RetryConfig {
	return retry.NewRetryConfigBuilder().
		WithMaxAttempts(opts.ImageDownloadRetry + 1). // +1 because first attempt is not a retry
		WithInitialDelay(1 * time.Second).
		WithMaxDelay(DefaultImageRetryMaxDelay).
		WithBackoff(DefaultImageRetryBackoff).
		WithRetryableErrors(retry.IsRetryableError).
		Build()
}

// tryRetrieveFromMappedRegistry attempts to retrieve image from a mapped registry
func tryRetrieveFromMappedRegistry(
	ctx context.Context,
	ref name.Reference,
	registryMapping string,
	opts *config.RegistryOptions,
	customPlatform string,
	timeout time.Duration,
) (v1.Image, error) {
	regToMapTo, repositoryPrefix := parseRegistryMapping(registryMapping)
	insecurePull := opts.InsecurePull || opts.InsecureRegistries.Contains(regToMapTo)

	remappedRepository, remapErr := remapRepository(ref.Context(), regToMapTo, repositoryPrefix, insecurePull)
	if remapErr != nil {
		return nil, remapErr
	}

	remappedRef := setNewRepository(ref, remappedRepository)
	logrus.Infof("Retrieving image %s from mapped registry %s", remappedRef, regToMapTo)

	retryFunc := func() (v1.Image, error) {
		return remoteImageFunc(remappedRef, remoteOptions(regToMapTo, opts, customPlatform)...)
	}

	retryConfig := buildRetryConfig(opts)
	remoteImage, err := retry.RetryWithResult(ctx, retryConfig, retryFunc)

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			logrus.Warnf("Timeout retrieving image %s from remapped registry %s after %v. "+
				"Will try with the next registry, or fallback to the original registry.",
				remappedRef, regToMapTo, timeout)
		} else {
			logrus.Warnf("Failed to retrieve image %s from remapped registry %s: %s. "+
				"Will try with the next registry, or fallback to the original registry.",
				remappedRef, regToMapTo, err)
		}
		return nil, err
	}

	return remoteImage, nil
}

// retrieveFromMappedRegistries tries to retrieve image from mapped registries
func retrieveFromMappedRegistries(
	ref name.Reference,
	newRegURLs []string,
	opts *config.RegistryOptions,
	customPlatform string,
	image string,
) (v1.Image, error) {
	ctx, cancel, timeout := createImageRetrieveContext()
	defer cancel()

	for _, registryMapping := range newRegURLs {
		remoteImage, err := tryRetrieveFromMappedRegistry(ctx, ref, registryMapping, opts, customPlatform, timeout)
		if err != nil {
			continue
		}

		manifestCache[image] = remoteImage
		return remoteImage, nil
	}

	return nil, nil
}

// prepareRegistryReference prepares the reference for registry operations
func prepareRegistryReference(ref name.Reference, opts *config.RegistryOptions) (name.Reference, error) {
	registryName := ref.Context().RegistryStr()
	if !opts.InsecurePull && !opts.InsecureRegistries.Contains(registryName) {
		return ref, nil
	}

	newReg, regErr := name.NewRegistry(registryName, name.WeakValidation, name.Insecure)
	if regErr != nil {
		return nil, regErr
	}
	return setNewRegistry(ref, newReg), nil
}

// retrieveFromDefaultRegistry retrieves image from the default registry
func retrieveFromDefaultRegistry(
	ref name.Reference,
	opts *config.RegistryOptions,
	customPlatform string,
	image string,
) (v1.Image, error) {
	registryName := ref.Context().RegistryStr()
	logrus.Infof("Retrieving image %s from registry %s", ref, registryName)

	retryFunc := func() (v1.Image, error) {
		return remoteImageFunc(ref, remoteOptions(registryName, opts, customPlatform)...)
	}

	retryConfig := buildRetryConfig(opts)
	ctx, cancel, timeout := createImageRetrieveContext()
	defer cancel()

	remoteImage, err := retry.RetryWithResult(ctx, retryConfig, retryFunc)
	if remoteImage != nil {
		manifestCache[image] = remoteImage
	}

	if err != nil && ctx.Err() == context.DeadlineExceeded {
		err = fmt.Errorf("timeout retrieving image %s after %v: %w", ref.String(), timeout, err)
	}
	handleRegistryError(err, ref, registryName)

	return remoteImage, err
}

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
		var remoteImage v1.Image
		remoteImage, err = retrieveFromMappedRegistries(ref, newRegURLs, opts, customPlatform, image)
		if err == nil && remoteImage != nil {
			return remoteImage, nil
		}

		if len(newRegURLs) > 0 && opts.SkipDefaultRegistryFallback {
			return nil, fmt.Errorf("image not found on any configured mapped registries for %s", ref)
		}
	}

	ref, err = prepareRegistryReference(ref, opts)
	if err != nil {
		return nil, err
	}

	return retrieveFromDefaultRegistry(ref, opts, customPlatform, image)
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
		remote.WithAuthFromKeychain(creds.GetKeychain(opts)),
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
