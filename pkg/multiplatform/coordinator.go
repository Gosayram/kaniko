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
	"strings"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/pkg/oci"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Coordinator manages multi-platform builds across different drivers
type Coordinator struct {
	opts    *config.KanikoOptions
	driver  Driver
	digests map[string]string // platform -> digest
}

// Driver interface defines the contract for multi-platform execution
type Driver interface {
	// ValidatePlatforms checks if the requested platforms are supported
	ValidatePlatforms(platforms []string) error
	
	// ExecuteBuilds performs builds for the specified platforms
	ExecuteBuilds(ctx context.Context, platforms []string) (map[string]string, error)
	
	// Cleanup performs any necessary cleanup after builds
	Cleanup() error
}

// NewCoordinator creates a new multi-platform coordinator
func NewCoordinator(opts *config.KanikoOptions) (*Coordinator, error) {
	driver, err := getDriver(opts)
	if err != nil {
		return nil, err
	}

	return &Coordinator{
		opts:    opts,
		driver:  driver,
		digests: make(map[string]string),
	}, nil
}

// Execute performs multi-platform build coordination
func (c *Coordinator) Execute(ctx context.Context) (v1.ImageIndex, error) {
	platforms := c.opts.MultiPlatform
	if len(platforms) == 0 {
		return nil, errors.New("no platforms specified for multi-platform build")
	}

	// Validate platforms
	if err := c.driver.ValidatePlatforms(platforms); err != nil {
		return nil, errors.Wrap(err, "platform validation failed")
	}

	// Execute builds
	digests, err := c.driver.ExecuteBuilds(ctx, platforms)
	if err != nil {
		return nil, errors.Wrap(err, "failed to execute multi-platform builds")
	}
	c.digests = digests

	// Create OCI Image Index or Docker Manifest List
	if c.opts.PublishIndex {
		index, err := oci.BuildIndex(c.digests, c.opts)
		if err != nil {
			return nil, errors.Wrap(err, "failed to create image index")
		}
		return index, nil
	}

	return nil, nil
}

// Cleanup performs cleanup operations
func (c *Coordinator) Cleanup() error {
	return c.driver.Cleanup()
}

// getDriver returns the appropriate driver based on configuration
func getDriver(opts *config.KanikoOptions) (Driver, error) {
	switch opts.Driver {
	case "local":
		return NewLocalDriver(opts), nil
	case "k8s":
		return NewKubernetesDriver(opts), nil
	case "ci":
		return NewCIDriver(opts), nil
	default:
		return nil, fmt.Errorf("unsupported driver: %s", opts.Driver)
	}
}

// parsePlatforms parses comma-separated platform strings into a slice
func parsePlatforms(platformStr string) []string {
	if platformStr == "" {
		return nil
	}
	return strings.Split(platformStr, ",")
}

// GetDigests returns the collected digests from builds
func (c *Coordinator) GetDigests() map[string]string {
	return c.digests
}

// LogMultiPlatformConfig logs the multi-platform configuration
func (c *Coordinator) LogMultiPlatformConfig() {
	logrus.Infof("Multi-platform build configuration:")
	logrus.Infof("  Driver: %s", c.opts.Driver)
	logrus.Infof("  Platforms: %v", c.opts.MultiPlatform)
	logrus.Infof("  Publish Index: %t", c.opts.PublishIndex)
	logrus.Infof("  Legacy Manifest List: %t", c.opts.LegacyManifestList)
	logrus.Infof("  Require Native Nodes: %t", c.opts.RequireNativeNodes)
	logrus.Infof("  OCI Mode: %s", c.opts.OCIMode)
	
	if len(c.opts.IndexAnnotations) > 0 {
		logrus.Infof("  Index Annotations: %v", c.opts.IndexAnnotations)
	}
}