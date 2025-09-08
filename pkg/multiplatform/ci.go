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
	"os"
	"path/filepath"
	"strings"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// CIDriver implements the Driver interface for CI/CD system integration
// This driver aggregates digests from existing per-architecture builds
type CIDriver struct {
	opts *config.KanikoOptions
}

// NewCIDriver creates a new CI driver instance
func NewCIDriver(opts *config.KanikoOptions) (*CIDriver, error) {
	return &CIDriver{
		opts: opts,
	}, nil
}

// ValidatePlatforms validates that digest files are available for requested platforms
func (d *CIDriver) ValidatePlatforms(platforms []string) error {
	if d.opts.DigestsFrom == "" {
		return errors.New("CI driver requires --digests-from path to read digest files")
	}

	// Check if digest directory exists
	if _, err := os.Stat(d.opts.DigestsFrom); os.IsNotExist(err) {
		return errors.Errorf("digests directory %s does not exist", d.opts.DigestsFrom)
	}

	return nil
}

// ExecuteBuilds reads digest files from the specified directory and returns them
func (d *CIDriver) ExecuteBuilds(ctx context.Context, platforms []string) (map[string]string, error) {
	digests := make(map[string]string)

	logrus.Infof("Reading digests from directory: %s", d.opts.DigestsFrom)

	for _, platform := range platforms {
		digest, err := d.readDigestForPlatform(platform)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read digest for platform %s", platform)
		}
		digests[platform] = digest
		logrus.Infof("Platform %s: %s", platform, digest)
	}

	return digests, nil
}

// readDigestForPlatform reads the digest file for a specific platform
func (d *CIDriver) readDigestForPlatform(platform string) (string, error) {
	// Convert platform to filesystem-safe name
	safePlatform := strings.ReplaceAll(platform, "/", "-")
	digestFile := filepath.Join(d.opts.DigestsFrom, safePlatform+".digest")

	data, err := os.ReadFile(digestFile)
	if err != nil {
		return "", errors.Wrapf(err, "failed to read digest file %s", digestFile)
	}

	digest := strings.TrimSpace(string(data))
	if digest == "" {
		return "", errors.Errorf("empty digest in file %s", digestFile)
	}

	// Validate digest format (basic check)
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		logrus.Warnf("Digest %s from file %s may not be in expected format", digest, digestFile)
	}

	return digest, nil
}

// Cleanup performs cleanup operations for CI driver
func (d *CIDriver) Cleanup() error {
	// No cleanup needed for CI driver
	logrus.Info("CI driver cleanup completed")
	return nil
}

// ExpectedDigestFileFormat returns the expected format for digest files
func (d *CIDriver) ExpectedDigestFileFormat() string {
	return `
Expected digest file format for CI driver:

1. Create a directory for digest files (specified with --digests-from)
2. For each platform, create a file named <platform>.digest
   Example: 
     - linux-amd64.digest
     - linux-arm64.digest

3. Each file should contain exactly one line with the image digest:
   Example content: sha256:abc123def456...

4. The digest files should be created by your CI system's per-architecture build jobs
`
}