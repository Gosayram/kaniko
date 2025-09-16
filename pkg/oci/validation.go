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

package oci

import (
	"fmt"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
)

// Validator provides OCI compliance validation functionality
type Validator struct {
	opts *config.KanikoOptions
}

// NewValidator creates a new OCI compliance validator
func NewValidator(opts *config.KanikoOptions) *Validator {
	return &Validator{opts: opts}
}

// ValidateImageIndex validates an OCI Image Index for compliance
func (v *Validator) ValidateImageIndex(index v1.ImageIndex) error {
	logrus.Info("Validating OCI Image Index compliance")

	// Get index manifest
	manifest, err := index.IndexManifest()
	if err != nil {
		return errors.Wrap(err, "failed to get index manifest for validation")
	}

	// Validate media type
	if err := v.validateMediaType(manifest.MediaType); err != nil {
		return err
	}

	// Validate schema version
	if err := v.validateSchemaVersion(int(manifest.SchemaVersion)); err != nil {
		return err
	}

	// Validate manifests
	if err := v.validateManifests(manifest.Manifests); err != nil {
		return err
	}

	// Validate annotations
	if err := v.validateAnnotations(manifest.Annotations); err != nil {
		return err
	}

	logrus.Info("OCI Image Index validation passed successfully")
	return nil
}

// ValidateImageManifest validates an OCI Image Manifest for compliance
func (v *Validator) ValidateImageManifest(manifest *v1.Manifest) error {
	logrus.Info("Validating OCI Image Manifest compliance")

	// Validate media type
	if err := v.validateMediaType(manifest.MediaType); err != nil {
		return err
	}

	// Validate schema version
	if err := v.validateSchemaVersion(int(manifest.SchemaVersion)); err != nil {
		return err
	}

	// Validate config
	if err := v.validateConfig(&manifest.Config); err != nil {
		return err
	}

	// Validate layers
	if err := v.validateLayers(manifest.Layers); err != nil {
		return err
	}

	// Validate annotations
	if err := v.validateAnnotations(manifest.Annotations); err != nil {
		return err
	}

	logrus.Info("OCI Image Manifest validation passed successfully")
	return nil
}

// validateMediaType validates OCI media type compliance
func (v *Validator) validateMediaType(mediaType types.MediaType) error {
	expectedMediaTypes := []types.MediaType{
		"application/vnd.oci.image.index.v1+json",
		"application/vnd.oci.image.manifest.v1+json",
		"application/vnd.oci.image.config.v1+json",
		"application/vnd.oci.image.layer.v1.tar",
		"application/vnd.docker.distribution.manifest.list.v2+json",
		"application/vnd.docker.distribution.manifest.v2+json",
	}

	for _, expected := range expectedMediaTypes {
		if mediaType == expected {
			return nil
		}
	}

	return fmt.Errorf("unsupported media type: %s. Expected one of: %v",
		mediaType, expectedMediaTypes)
}

// validateSchemaVersion validates schema version compliance
func (v *Validator) validateSchemaVersion(version int) error {
	const expectedSchemaVersion = 2
	if version != expectedSchemaVersion {
		return fmt.Errorf("unsupported schema version: %d. Expected: %d", version, expectedSchemaVersion)
	}
	return nil
}

// validateManifests validates manifest descriptors in an index
func (v *Validator) validateManifests(manifests []v1.Descriptor) error {
	if len(manifests) == 0 {
		return errors.New("index contains no manifests")
	}

	for i := range manifests {
		if err := v.validateDescriptor(&manifests[i], fmt.Sprintf("manifest[%d]", i)); err != nil {
			return err
		}

		// Validate platform information for multi-platform images
		if manifests[i].Platform != nil {
			if err := v.validatePlatform(manifests[i].Platform); err != nil {
				return errors.Wrapf(err, "invalid platform in manifest %d", i)
			}
		}
	}

	return nil
}

// validateDescriptor validates a descriptor object
func (v *Validator) validateDescriptor(desc *v1.Descriptor, context string) error {
	if desc.Digest.Hex == "" {
		return fmt.Errorf("%s: empty digest", context)
	}

	if desc.Size == 0 {
		return fmt.Errorf("%s: zero size", context)
	}

	if err := v.validateMediaType(desc.MediaType); err != nil {
		return errors.Wrapf(err, "%s: invalid media type", context)
	}

	return nil
}

// validateConfig validates the image configuration descriptor
func (v *Validator) validateConfig(cfg *v1.Descriptor) error {
	if err := v.validateDescriptor(cfg, "config"); err != nil {
		return err
	}

	// OCI config must have specific media type
	if cfg.MediaType != "application/vnd.oci.image.config.v1+json" {
		return fmt.Errorf("config media type must be %s, got %s",
			"application/vnd.oci.image.config.v1+json", cfg.MediaType)
	}

	return nil
}

// validateLayers validates layer descriptors
func (v *Validator) validateLayers(layers []v1.Descriptor) error {
	if len(layers) == 0 {
		return errors.New("no layers in manifest")
	}

	for i := range layers {
		if err := v.validateDescriptor(&layers[i], fmt.Sprintf("layer[%d]", i)); err != nil {
			return err
		}

		// Validate layer media types
		if !v.isValidLayerMediaType(layers[i].MediaType) {
			return fmt.Errorf("layer[%d]: invalid media type: %s", i, layers[i].MediaType)
		}
	}

	return nil
}

// isValidLayerMediaType checks if a media type is valid for layers
func (v *Validator) isValidLayerMediaType(mediaType types.MediaType) bool {
	validLayerTypes := []types.MediaType{
		"application/vnd.oci.image.layer.v1.tar",
		"application/vnd.docker.image.rootfs.diff.tar",
		"application/vnd.oci.image.layer.v1.tar+zstd",
		"application/vnd.docker.image.rootfs.foreign.diff.tar",
	}

	for _, validType := range validLayerTypes {
		if mediaType == validType {
			return true
		}
	}

	return false
}

// validatePlatform validates platform specification
func (v *Validator) validatePlatform(platform *v1.Platform) error {
	if platform.OS == "" {
		return errors.New("platform OS cannot be empty")
	}

	if platform.Architecture == "" {
		return errors.New("platform architecture cannot be empty")
	}

	// Validate OS values
	validOS := []string{"linux", "windows", "freebsd", "openbsd", "solaris", "darwin"}
	if !v.contains(validOS, platform.OS) {
		return fmt.Errorf("invalid OS: %s. Valid values: %v", platform.OS, validOS)
	}

	// Validate architecture values
	validArch := []string{
		"amd64", "arm64", "ppc64le", "s390x", "386", "arm",
		"mips64", "mips64le", "mips", "mipsle", "riscv64",
	}
	if !v.contains(validArch, platform.Architecture) {
		return fmt.Errorf("invalid architecture: %s. Valid values: %v", platform.Architecture, validArch)
	}

	// Validate variant if present
	if platform.Variant != "" {
		validVariants := map[string][]string{
			"arm":     {"v6", "v7", "v8"},
			"arm64":   {"v8"},
			"ppc64le": {"power8", "power9"},
		}

		if variants, exists := validVariants[platform.Architecture]; exists {
			if !v.contains(variants, platform.Variant) {
				return fmt.Errorf("invalid variant for %s: %s. Valid values: %v",
					platform.Architecture, platform.Variant, variants)
			}
		}
	}

	return nil
}

// validateAnnotations validates OCI annotations
func (v *Validator) validateAnnotations(annotations map[string]string) error {
	for key, value := range annotations {
		// Validate annotation keys
		if err := v.validateAnnotationKey(key); err != nil {
			return errors.Wrapf(err, "invalid annotation key: %s", key)
		}

		// Validate annotation values
		if err := v.validateAnnotationValue(key, value); err != nil {
			return errors.Wrapf(err, "invalid annotation value for key %s", key)
		}
	}

	return nil
}

// validateAnnotationKey validates OCI annotation keys
func (v *Validator) validateAnnotationKey(key string) error {
	// OCI annotation keys should follow reverse domain name notation
	if strings.Contains(key, "..") {
		return errors.New("annotation key contains consecutive dots")
	}

	if strings.HasPrefix(key, ".") || strings.HasSuffix(key, ".") {
		return errors.New("annotation key cannot start or end with a dot")
	}

	// Check for reserved namespaces
	reservedPrefixes := []string{
		"io.cncf.",
		"io.openshift.",
		"com.docker.",
		"com.github.",
		"org.opencontainers.",
	}

	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(key, prefix) {
			return nil // Reserved namespace is valid
		}
	}

	// For custom annotations, require reverse domain notation
	parts := strings.Split(key, ".")
	const minPartsCount = 2
	if len(parts) < minPartsCount {
		return errors.New("custom annotation keys must use reverse domain notation (e.g., com.example.key)")
	}

	return nil
}

// validateAnnotationValue validates OCI annotation values
func (v *Validator) validateAnnotationValue(key, value string) error {
	if value == "" {
		return errors.New("annotation value cannot be empty")
	}

	// Validate specific well-known annotations
	switch key {
	case "org.opencontainers.image.created":
		if !v.isValidRFC3339Date(value) {
			return errors.New("invalid RFC3339 date format")
		}
	case "org.opencontainers.image.authors":
		// Basic validation for authors
		if value == "" {
			return errors.New("authors cannot be empty")
		}
	case "org.opencontainers.image.url":
		if !v.isValidURL(value) {
			return errors.New("invalid URL format")
		}
	}

	return nil
}

// isValidRFC3339Date checks if a string is a valid RFC3339 date
func (v *Validator) isValidRFC3339Date(date string) bool {
	// Simple validation - in production you might use time.Parse()
	return strings.Contains(date, "T") && strings.Contains(date, "Z")
}

// isValidURL checks if a string is a valid URL
func (v *Validator) isValidURL(url string) bool {
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

// contains checks if a slice contains a value
func (v *Validator) contains(slice []string, value string) bool {
	for _, item := range slice {
		if item == value {
			return true
		}
	}
	return false
}

// ValidateCompression validates compression algorithm compliance
func (v *Validator) ValidateCompression(compression config.Compression) error {
	switch compression {
	case config.GZip, config.ZStd:
		return nil
	default:
		return fmt.Errorf("unsupported compression algorithm: %s", compression)
	}
}

// ValidateOCIMode validates OCI mode configuration
func (v *Validator) ValidateOCIMode(ociMode string) error {
	validModes := []string{"oci", "docker", "auto"}
	if !v.contains(validModes, ociMode) {
		return fmt.Errorf("invalid OCI mode: %s. Valid values: %v", ociMode, validModes)
	}
	return nil
}

// GetValidationReport generates a comprehensive validation report
func (v *Validator) GetValidationReport(index v1.ImageIndex) (map[string]interface{}, error) {
	report := make(map[string]interface{})

	manifest, err := index.IndexManifest()
	if err != nil {
		return nil, err
	}

	report["mediaType"] = manifest.MediaType
	report["schemaVersion"] = manifest.SchemaVersion
	report["manifestCount"] = len(manifest.Manifests)
	report["annotationCount"] = len(manifest.Annotations)

	// Platform distribution
	platforms := make(map[string]int)
	for i := range manifest.Manifests {
		if manifest.Manifests[i].Platform != nil {
			platformKey := fmt.Sprintf("%s/%s", manifest.Manifests[i].Platform.OS, manifest.Manifests[i].Platform.Architecture)
			if manifest.Manifests[i].Platform.Variant != "" {
				platformKey += "/" + manifest.Manifests[i].Platform.Variant
			}
			platforms[platformKey]++
		}
	}
	report["platforms"] = platforms

	// Validation status
	report["valid"] = true
	if err := v.ValidateImageIndex(index); err != nil {
		report["valid"] = false
		report["validationError"] = err.Error()
	}

	return report, nil
}
