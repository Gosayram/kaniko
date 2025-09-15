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
	if !s.opts.SignImages {
		return nil // Signing is optional
	}

	logrus.Infof("Signing image %s with cosign", imageRef)

	// Validate cosign configuration
	if err := s.validateCosignConfig(); err != nil {
		return errors.Wrap(err, "cosign configuration validation failed")
	}

	// Build cosign command arguments
	args := s.buildCosignArgs(imageRef)

	// Execute cosign command
	if err := s.executeCosign(ctx, args); err != nil {
		return errors.Wrap(err, "failed to sign image with cosign")
	}

	logrus.Infof("Successfully signed image %s", imageRef)
	return nil
}

// SignIndex signs a multi-platform image index using cosign
func (s *Signer) SignIndex(ctx context.Context, indexRef string) error {
	if !s.opts.SignImages {
		return nil // Signing is optional
	}

	logrus.Infof("Signing image index %s with cosign", indexRef)

	// Validate cosign configuration
	if err := s.validateCosignConfig(); err != nil {
		return errors.Wrap(err, "cosign configuration validation failed")
	}

	// Build cosign command arguments for index
	args := s.buildCosignArgs(indexRef)

	// Execute cosign command
	if err := s.executeCosign(ctx, args); err != nil {
		return errors.Wrap(err, "failed to sign image index with cosign")
	}

	logrus.Infof("Successfully signed image index %s", indexRef)
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
		if file, err := os.Open(s.opts.CosignKeyPath); err != nil {
			return errors.Errorf("cannot read cosign key file: %s", err)
		} else {
			file.Close()
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

	args := []string{"verify"}

	// Add key-based verification if configured
	if s.opts.CosignKeyPath != "" {
		args = append(args, "--key", s.opts.CosignKeyPath)
	} else {
		// Use keyless verification (public good)
		args = append(args, "--certificate-identity-regexp", ".*", "--certificate-oidc-issuer-regexp", ".*")
	}

	args = append(args, imageRef)

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
	if err := os.MkdirAll(outputDir, 0o700); err != nil {
		return errors.Wrap(err, "failed to create output directory for key pair")
	}

	// Build cosign key generation command
	args := []string{
		"generate-key-pair",
		"--output-key-prefix", filepath.Join(outputDir, "cosign"),
	}

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
func (s *Signer) GetPublicKey(ctx context.Context) (string, error) {
	if s.opts.CosignKeyPath == "" {
		return "", errors.New("no cosign key path configured")
	}

	publicKeyPath := s.opts.CosignKeyPath + ".pub"
	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		return "", errors.Errorf("public key file not found: %s", publicKeyPath)
	}

	publicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return "", errors.Wrap(err, "failed to read public key file")
	}

	return string(publicKey), nil
}

// IsImageSigned checks if an image is signed using cosign
func (s *Signer) IsImageSigned(ctx context.Context, imageRef string) (bool, error) {
	args := []string{"verify", "--output", "json", imageRef}

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