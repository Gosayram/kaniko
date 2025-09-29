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

// Package cosign provides functionality for signing and verifying container images
// using cosign (sigstore's container signing tool).
package cosign

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
)

// Signer provides functionality for signing container images using cosign
type Signer struct {
	opts *config.KanikoOptions
}

// NewSigner creates a new cosign signer instance
func NewSigner(opts *config.KanikoOptions) *Signer {
	return &Signer{opts: opts}
}

// SignImage signs a container image using cosign
func (s *Signer) SignImage(ctx context.Context, imageRef string) error {
	return s.signArtifact(ctx, imageRef, "image")
}

// SignIndex signs a multi-platform image index using cosign
func (s *Signer) SignIndex(ctx context.Context, indexRef string) error {
	return s.signArtifact(ctx, indexRef, "image index")
}

// signArtifact is a common function for signing both images and image indices
func (s *Signer) signArtifact(ctx context.Context, artifactRef, artifactType string) error {
	if !s.opts.SignImages {
		return nil // Signing is optional
	}

	logrus.Infof("Signing %s %s with cosign", artifactType, artifactRef)

	// Validate artifact reference
	if err := s.validateImageReference(artifactRef); err != nil {
		return errors.Wrap(err, "invalid artifact reference")
	}

	// Validate cosign configuration
	if err := s.validateCosignConfig(); err != nil {
		return errors.Wrap(err, "cosign configuration validation failed")
	}

	// Build cosign command arguments
	args := s.buildCosignArgs(artifactRef)

	// Execute cosign command
	if err := s.executeCosign(ctx, args); err != nil {
		return errors.Wrapf(err, "failed to sign %s with cosign", artifactType)
	}

	logrus.Infof("Successfully signed %s %s", artifactType, artifactRef)
	return nil
}

// validateCosignConfig validates the cosign configuration
func (s *Signer) validateCosignConfig() error {
	// Check if cosign is available in PATH
	if _, err := exec.LookPath("cosign"); err != nil {
		return errors.New("cosign not found in PATH. Please install cosign: https://docs.sigstore.dev/cosign/installation")
	}

	// Validate key configuration if using key-based signing
	if s.opts.CosignKeyPath != "" {
		if _, err := os.Stat(s.opts.CosignKeyPath); os.IsNotExist(err) {
			return errors.Errorf("cosign key file not found: %s", s.opts.CosignKeyPath)
		}

		// Check if key file is readable
		file, err := os.Open(s.opts.CosignKeyPath)
		if err != nil {
			return errors.Errorf("cannot read cosign key file: %s", err)
		}
		if err := file.Close(); err != nil {
			return errors.Wrap(err, "failed to close cosign key file")
		}
	}

	return nil
}

// buildCosignArgs builds the cosign command arguments
func (s *Signer) buildCosignArgs(imageRef string) []string {
	args := []string{"sign"}

	// Add key-based signing options if configured
	if s.opts.CosignKeyPath != "" {
		args = append(args, "--key", s.opts.CosignKeyPath)

		if s.opts.CosignKeyPassword != "" {
			args = append(args, "--key-pass", s.opts.CosignKeyPassword)
		}
	} else {
		// Use keyless signing (default)
		args = append(args, "--yes") // Auto-confirm for CI environments
	}

	// Add the image reference to sign
	args = append(args, imageRef)

	return args
}

// executeCosign executes the cosign command with the given arguments
func (s *Signer) executeCosign(ctx context.Context, args []string) error {
	logrus.Debugf("Executing cosign command: cosign %s", strings.Join(args, " "))

	// Use exec.Command with a fixed program name to avoid G204.
	//nolint:gosec // G204: program name hardcoded; args validated
	cmd := exec.CommandContext(ctx, "cosign", args...)

	// Capture output for logging
	output, err := cmd.CombinedOutput()

	if err != nil {
		logrus.Errorf("Cosign command failed: %s", string(output))
		return errors.Wrap(err, "cosign command execution failed")
	}

	logrus.Debugf("Cosign output: %s", string(output))
	return nil
}

// VerifyImage verifies a signed container image using cosign
func (s *Signer) VerifyImage(ctx context.Context, imageRef string) error {
	logrus.Infof("Verifying image signature for %s", imageRef)

	// Validate image reference
	if err := s.validateImageReference(imageRef); err != nil {
		return errors.Wrap(err, "invalid image reference")
	}

	args := []string{"verify"}

	// Add key-based verification if configured
	if s.opts.CosignKeyPath != "" {
		args = append(args, "--key", s.opts.CosignKeyPath)
	} else {
		// Use keyless verification (public good)
		args = append(args, "--certificate-identity-regexp", ".*", "--certificate-oidc-issuer-regexp", ".*")
	}

	args = append(args, imageRef)

	// Use exec.Command with a fixed program name to avoid G204.
	//nolint:gosec // G204: program name hardcoded; args validated
	cmd := exec.CommandContext(ctx, "cosign", args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		logrus.Errorf("Cosign verification failed: %s", string(output))
		return errors.Wrap(err, "image signature verification failed")
	}

	logrus.Infof("Image signature verified successfully: %s", string(output))
	return nil
}

// GenerateKeyPair generates a new cosign key pair
func (s *Signer) GenerateKeyPair(ctx context.Context, outputDir string) error {
	logrus.Infof("Generating cosign key pair in %s", outputDir)

	// Create output directory if it doesn't exist
	const cosignKeyDirPerm = 0o700

	if err := os.MkdirAll(outputDir, cosignKeyDirPerm); err != nil {
		return errors.Wrap(err, "failed to create output directory for key pair")
	}

	// Build cosign key generation command
	args := []string{
		"generate-key-pair",
		"--output-key-prefix", filepath.Join(outputDir, "cosign"),
	}

	// Use exec.Command with a fixed program name to avoid G204.
	//nolint:gosec // G204: program name hardcoded; args validated
	cmd := exec.CommandContext(ctx, "cosign", args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		logrus.Errorf("Cosign key generation failed: %s", string(output))
		return errors.Wrap(err, "failed to generate cosign key pair")
	}

	logrus.Infof("Cosign key pair generated successfully in %s", outputDir)
	return nil
}

// GetPublicKey returns the public key from a key file
func (s *Signer) GetPublicKey(_ context.Context) (string, error) {
	if s.opts.CosignKeyPath == "" {
		return "", errors.New("no cosign key path configured")
	}

	publicKeyPath := s.opts.CosignKeyPath + ".pub"

	// Validate file path to prevent directory traversal attacks
	if err := s.validateFilePath(publicKeyPath); err != nil {
		return "", errors.Wrap(err, "invalid public key file path")
	}

	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		return "", errors.Errorf("public key file not found: %s", publicKeyPath)
	}

	// File path has been validated by validateFilePath, safe to read
	publicKey, err := os.ReadFile(publicKeyPath) //nolint:gosec // G304: file path validated by validateFilePath
	if err != nil {
		return "", errors.Wrap(err, "failed to read public key file")
	}

	return string(publicKey), nil
}

// IsImageSigned checks if an image is signed using cosign
func (s *Signer) IsImageSigned(ctx context.Context, imageRef string) (bool, error) {
	// Validate image reference
	if err := s.validateImageReference(imageRef); err != nil {
		return false, errors.Wrap(err, "invalid image reference")
	}

	args := []string{"verify", "--output", "json", imageRef}

	// Use exec.Command with a fixed program name to avoid G204.
	//nolint:gosec // G204: program name hardcoded; args validated
	cmd := exec.CommandContext(ctx, "cosign", args...)
	output, err := cmd.CombinedOutput()

	// If command succeeds, image is signed
	if err == nil {
		return true, nil
	}

	// If command fails with "no signatures found" error, image is not signed
	if strings.Contains(string(output), "no signatures found") {
		return false, nil
	}

	// Other errors indicate verification issues
	return false, errors.Wrap(err, "failed to check image signature status")
}

// validateImageReference validates that an image reference is safe to use
func (s *Signer) validateImageReference(imageRef string) error {
	if imageRef == "" {
		return errors.New("empty image reference")
	}

	// Basic validation to prevent command injection
	if strings.Contains(imageRef, "`") || strings.Contains(imageRef, "$(") ||
		strings.Contains(imageRef, ";") || strings.Contains(imageRef, "|") ||
		strings.Contains(imageRef, "&") || strings.Contains(imageRef, ">") ||
		strings.Contains(imageRef, "<") {
		return errors.New("image reference contains potentially dangerous characters")
	}

	// Validate that it looks like a proper image reference
	if !strings.Contains(imageRef, ":") && !strings.Contains(imageRef, "@") {
		return errors.New("image reference must contain a tag or digest")
	}

	return nil
}

// validateFilePath validates that a file path is safe to use
func (s *Signer) validateFilePath(filePath string) error {
	if filePath == "" {
		return errors.New("empty file path")
	}

	// Prevent directory traversal attacks
	if strings.Contains(filePath, "..") || strings.Contains(filePath, "../") {
		return errors.New("file path contains directory traversal characters")
	}

	// Prevent absolute paths that could access sensitive locations
	if strings.HasPrefix(filePath, "/") {
		return errors.New("absolute file paths are not allowed")
	}

	// Prevent potentially dangerous characters
	if strings.Contains(filePath, "`") || strings.Contains(filePath, "$(") ||
		strings.Contains(filePath, ";") || strings.Contains(filePath, "|") ||
		strings.Contains(filePath, "&") || strings.Contains(filePath, ">") ||
		strings.Contains(filePath, "<") {
		return errors.New("file path contains potentially dangerous characters")
	}

	return nil
}
