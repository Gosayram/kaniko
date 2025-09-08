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

package multiplatform

import (
	"context"
	"fmt"
	"runtime"
	"strings"

	"github.com/Gosayram/kaniko/pkg/config"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// LocalDriver handles single-architecture builds on the local host
type LocalDriver struct {
	opts *config.KanikoOptions
}

// NewLocalDriver creates a new local driver instance
func NewLocalDriver(opts *config.KanikoOptions) *LocalDriver {
	return &LocalDriver{opts: opts}
}

// ValidatePlatforms validates that the requested platforms are compatible with local execution
func (d *LocalDriver) ValidatePlatforms(platforms []string) error {
	currentPlatform := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

	for _, platform := range platforms {
		if platform != currentPlatform {
			if d.opts.RequireNativeNodes {
				return fmt.Errorf("platform %s is not native to this host (%s). Use --require-native-nodes=false to allow emulation", platform, currentPlatform)
			}
			logrus.Warnf("Platform %s is not native to this host (%s). Build may fail or require emulation", platform, currentPlatform)
		}
	}
	return nil
}

// ExecuteBuilds performs builds for the specified platforms on the local host
func (d *LocalDriver) ExecuteBuilds(ctx context.Context, platforms []string) (map[string]string, error) {
	digests := make(map[string]string)
	currentPlatform := fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)

	for _, platform := range platforms {
		// For local driver, we can only build for the host architecture
		if platform != currentPlatform && d.opts.RequireNativeNodes {
			logrus.Warnf("Skipping non-native platform %s (host is %s)", platform, currentPlatform)
			continue
		}

		logrus.Infof("Building for platform: %s", platform)

		// Create a modified options struct for this platform
		platformOpts := *d.opts
		platformOpts.CustomPlatform = platform

		// Execute the build using the existing kaniko executor
		image, err := executeBuild(&platformOpts)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to build for platform %s", platform)
		}

		// Get the digest of the built image
		digest, err := image.Digest()
		if err != nil {
			return nil, errors.Wrapf(err, "failed to get digest for platform %s", platform)
		}

		digests[platform] = digest.String()
		logrus.Infof("Successfully built image for platform %s: %s", platform, digest.String())
	}

	return digests, nil
}

// Cleanup performs cleanup operations for local driver
func (d *LocalDriver) Cleanup() error {
	// Local driver typically doesn't require cleanup
	return nil
}

// executeBuild uses the configured build function to execute the build
func executeBuild(opts *config.KanikoOptions) (v1.Image, error) {
	return BuildImage(opts)
}

// isPlatformNative checks if the platform matches the current host
func isPlatformNative(platform string) bool {
	parts := strings.Split(platform, "/")
	if len(parts) != 2 {
		return false
	}
	return parts[0] == runtime.GOOS && parts[1] == runtime.GOARCH
}
