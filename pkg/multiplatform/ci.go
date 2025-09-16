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
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
)

// CIDriver implements the Driver interface for CI/CD system integration
// This driver aggregates digests from existing per-architecture builds
type CIDriver struct {
	opts *config.KanikoOptions
}

// NewCIDriver creates a new CI driver instance
func NewCIDriver(opts *config.KanikoOptions) (*CIDriver, error) {
	// Auto-detect DigestsFrom if not set
	if opts.DigestsFrom == "" {
		if workspace := os.Getenv("GITHUB_WORKSPACE"); workspace != "" {
			opts.DigestsFrom = filepath.Join(workspace, "digests")
			logrus.Infof("Detected GitHub Actions; using %s for digests", opts.DigestsFrom)
		} else if ciDir := os.Getenv("CI_DIGESTS_DIR"); ciDir != "" {
			opts.DigestsFrom = ciDir
			logrus.Infof("Using CI_DIGESTS_DIR %s for digests", opts.DigestsFrom)
		} else {
			// Fallback to temp dir for local CI-like runs
			opts.DigestsFrom = filepath.Join(os.TempDir(), "kaniko-digests")
			logrus.Infof("No CI env detected; using %s for digests", opts.DigestsFrom)
		}
		// Ensure dir exists
		if err := os.MkdirAll(opts.DigestsFrom, 0755); err != nil {
			return nil, fmt.Errorf("failed to create digests dir %s: %w", opts.DigestsFrom, err)
		}
	}
	return &CIDriver{
		opts: opts,
	}, nil
}

// ValidatePlatforms validates that digest files are available for requested platforms
func (d *CIDriver) ValidatePlatforms(platforms []string) error {
	if _, err := os.Stat(d.opts.DigestsFrom); os.IsNotExist(err) {
		return fmt.Errorf("digests directory does not exist: %s", d.opts.DigestsFrom)
	}
	if len(platforms) == 0 {
		// Auto mode: check has at least one .digest
		entries, err := os.ReadDir(d.opts.DigestsFrom)
		if err != nil {
			return fmt.Errorf("failed to read digests dir: %w", err)
		}
		hasDigest := false
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".digest") {
				hasDigest = true
				break
			}
		}
		if !hasDigest {
			return errors.New("no .digest files found in " + d.opts.DigestsFrom + " for auto-collection")
		}
	} else {
		// Specific platforms: check each file exists
		for _, platform := range platforms {
			filename := d.getDigestFilename(platform)
			path := filepath.Join(d.opts.DigestsFrom, filename)
			if _, err := os.Stat(path); os.IsNotExist(err) {
				return fmt.Errorf("digest file missing for %s: %s", platform, path)
			}
		}
	}
	return nil
}

// ExecuteBuilds reads digest files from the specified directory and returns them
func (d *CIDriver) ExecuteBuilds(_ context.Context, platforms []string) (map[string]string, error) {
	digests := make(map[string]string)

	logrus.Infof("Reading digests from directory: %s", d.opts.DigestsFrom)

	if len(platforms) == 0 {
		// Auto-collect all .digest files (matrix mode)
		entries, err := os.ReadDir(d.opts.DigestsFrom)
		if err != nil {
			return nil, fmt.Errorf("failed to read digests dir: %w", err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			filename := entry.Name()
			if !strings.HasSuffix(filename, ".digest") {
				continue
			}
			platform := strings.TrimSuffix(filename, ".digest")
			platform = strings.ReplaceAll(platform, "-", "/") // Restore os/arch
			path := filepath.Join(d.opts.DigestsFrom, filename)
			digest, err := d.readDigestFromFile(path)
			if err != nil {
				logrus.Warnf("Skipping %s: %v", filename, err)
				continue
			}
			digests[platform] = digest
			logrus.Infof("Auto-collected %s: %s", platform, digest)
		}
		if len(digests) == 0 {
			return nil, errors.New("no valid .digest files found for auto-collection")
		}
	} else {
		// Specific platforms
		for _, platform := range platforms {
			digest, err := d.readDigestForPlatform(platform)
			if err != nil {
				return nil, err
			}
			digests[platform] = digest
			logrus.Infof("Platform %s: %s", platform, digest)
		}
	}

	return digests, nil
}

// readDigestForPlatform reads the digest file for a specific platform
func (d *CIDriver) readDigestForPlatform(platform string) (string, error) {
	// Convert platform to filesystem-safe name
	safePlatform := strings.ReplaceAll(platform, "/", "-")
	digestFile := filepath.Join(d.opts.DigestsFrom, safePlatform+".digest")

	// Validate the file path to prevent directory traversal
	cleanDigestFile := filepath.Clean(digestFile)
	if !strings.HasPrefix(cleanDigestFile, d.opts.DigestsFrom) {
		return "", errors.Errorf("invalid file path: potential directory traversal detected")
	}
	data, err := os.ReadFile(cleanDigestFile)
	if err != nil {
		return "", errors.Wrapf(err, "failed to read digest file %s", cleanDigestFile)
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

// readDigestFromFile reads digest from file for a specific platform
func (d *CIDriver) readDigestFromFile(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return "", err
	}
	digest := strings.TrimSpace(string(data))
	if digest == "" {
		return "", fmt.Errorf("empty digest file: %s", filename)
	}
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != 71 {
		return "", fmt.Errorf("invalid digest format in %s: %s (expected sha256:64hex)", filename, digest)
	}
	return digest, nil
}

// getDigestFilename returns the expected filename for a platform's digest
func (d *CIDriver) getDigestFilename(platform string) string {
	return strings.ReplaceAll(platform, "/", "-") + ".digest"
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
