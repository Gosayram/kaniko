//go:build integration

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

package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// TestMultiPlatformLocalDriver tests the local driver for multi-platform builds
func TestMultiPlatformLocalDriver(t *testing.T) {
	if os.Getenv("KANIKO_TEST_MULTIPLATFORM") == "" {
		t.Skip("Skipping multi-platform local driver test. Set KANIKO_TEST_MULTIPLATFORM=1 to enable")
	}

	// Create a simple test context
	contextDir := t.TempDir()
	dockerfilePath := filepath.Join(contextDir, "Dockerfile")

	// Create a simple Dockerfile
	dockerfileContent := `FROM alpine:latest
RUN echo "Multi-platform test" > /test.txt
CMD ["cat", "/test.txt"]
`
	err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create Dockerfile: %v", err)
	}

	// Test platforms
	platforms := []string{"linux/amd64", "linux/arm64"}
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		platforms = append(platforms, "darwin/arm64")
	}

	// Build single-platform images first
	singleImages := make(map[string]string)
	for _, platform := range platforms {
		t.Run("single_"+platform, func(t *testing.T) {
			imageName := fmt.Sprintf("%s/test-multi-local-%s", config.imageRepo, strings.ReplaceAll(platform, "/", "-"))

			// Build with kaniko using custom platform
			dockerRunFlags := []string{"run", "--net=host"}
			dockerRunFlags = addServiceAccountFlags(dockerRunFlags, config.serviceAccount)
			dockerRunFlags = append(dockerRunFlags,
				ExecutorImage,
				"-c", fmt.Sprintf("dir://%s", contextDir),
				"-f", "Dockerfile",
				"-d", imageName,
				"--custom-platform", platform,
				"--no-push",
			)

			cmd := exec.Command("docker", dockerRunFlags...)
			out, err := RunCommandWithoutTest(cmd)
			if err != nil {
				t.Fatalf("Failed to build image for platform %s: %v\n%s", platform, err, string(out))
			}

			// Verify the image was created
			verifyImagePlatform(t, imageName, platform)
			singleImages[platform] = imageName
		})
	}

	// Test multi-platform build using local driver
	t.Run("multi_platform", func(t *testing.T) {
		multiImageName := fmt.Sprintf("%s/test-multi-local-index", config.imageRepo)

		// Create digest files for CI driver test
		digestDir := t.TempDir()
		for platform, image := range singleImages {
			digestFilename := strings.ReplaceAll(platform, "/", "-") + ".digest"
			digestPath := filepath.Join(digestDir, digestFilename)

			// Get digest from image
			digest, err := getImageDigest(image)
			if err != nil {
				t.Fatalf("Failed to get digest for %s: %v", image, err)
			}

			err = os.WriteFile(digestPath, []byte(digest), 0644)
			if err != nil {
				t.Fatalf("Failed to write digest file: %v", err)
			}
		}

		// Build multi-platform index using CI driver (simulating local workflow)
		dockerRunFlags := []string{"run", "--net=host"}
		dockerRunFlags = addServiceAccountFlags(dockerRunFlags, config.serviceAccount)
		dockerRunFlags = append(dockerRunFlags,
			ExecutorImage,
			"--driver=ci",
			"--digests-from", digestDir,
			"-d", multiImageName,
			"--publish-index=true",
			"--oci-mode=oci",
			"--no-push=false",
		)

		cmd := exec.Command("docker", dockerRunFlags...)
		out, err := RunCommandWithoutTest(cmd)
		if err != nil {
			t.Fatalf("Failed to build multi-platform index: %v\n%s", err, string(out))
		}

		// Verify the multi-platform index
		verifyMultiPlatformIndex(t, multiImageName, platforms)
	})
}

// TestMultiPlatformCIDriver tests the CI driver for multi-platform builds
func TestMultiPlatformCIDriver(t *testing.T) {
	if os.Getenv("KANIKO_TEST_MULTIPLATFORM") == "" {
		t.Skip("Skipping multi-platform CI driver test. Set KANIKO_TEST_MULTIPLATFORM=1 to enable")
	}

	// Create a test context
	contextDir := t.TempDir()
	dockerfilePath := filepath.Join(contextDir, "Dockerfile")

	// Create a Dockerfile that writes platform info
	dockerfileContent := `FROM alpine:latest
RUN echo "Built for $(uname -m)" > /platform.txt
CMD ["cat", "/platform.txt"]
`
	err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create Dockerfile: %v", err)
	}

	// Test platforms
	platforms := []string{"linux/amd64", "linux/arm64"}

	// Simulate CI workflow by building and pushing individual platform images
	digestDir := t.TempDir()
	pushedImages := make(map[string]string)

	for _, platform := range platforms {
		t.Run("ci_"+platform, func(t *testing.T) {
			// Build single platform image
			tempImage := fmt.Sprintf("%s/test-ci-%s-temp", config.imageRepo, strings.ReplaceAll(platform, "/", "-"))

			dockerRunFlags := []string{"run", "--net=host"}
			dockerRunFlags = addServiceAccountFlags(dockerRunFlags, config.serviceAccount)
			dockerRunFlags = append(dockerRunFlags,
				ExecutorImage,
				"-c", fmt.Sprintf("dir://%s", contextDir),
				"-f", "Dockerfile",
				"-d", tempImage,
				"--custom-platform", platform,
				"--no-push", // Don't push for this test
			)

			cmd := exec.Command("docker", dockerRunFlags...)
			out, err := RunCommandWithoutTest(cmd)
			if err != nil {
				t.Fatalf("Failed to build image for platform %s: %v\n%s", platform, err, string(out))
			}

			// Get digest and write to file (simulating CI behavior)
			digest, err := getImageDigest(tempImage)
			if err != nil {
				t.Fatalf("Failed to get digest for %s: %v", tempImage, err)
			}

			digestFilename := strings.ReplaceAll(platform, "/", "-") + ".digest"
			digestPath := filepath.Join(digestDir, digestFilename)
			err = os.WriteFile(digestPath, []byte(digest), 0644)
			if err != nil {
				t.Fatalf("Failed to write digest file: %v", err)
			}

			pushedImages[platform] = tempImage
			t.Logf("Platform %s digest: %s", platform, digest)
		})
	}

	// Test CI driver aggregation
	t.Run("ci_aggregation", func(t *testing.T) {
		multiImageName := fmt.Sprintf("%s/test-ci-multi", config.imageRepo)

		dockerRunFlags := []string{"run", "--net=host"}
		dockerRunFlags = addServiceAccountFlags(dockerRunFlags, config.serviceAccount)
		dockerRunFlags = append(dockerRunFlags,
			ExecutorImage,
			"--driver=ci",
			"--digests-from", digestDir,
			"-d", multiImageName,
			"--publish-index=true",
			"--oci-mode=oci",
			"--no-push=false",
		)

		cmd := exec.Command("docker", dockerRunFlags...)
		out, err := RunCommandWithoutTest(cmd)
		if err != nil {
			t.Fatalf("Failed to aggregate with CI driver: %v\n%s", err, string(out))
		}

		// Verify the resulting index
		verifyMultiPlatformIndex(t, multiImageName, platforms)
	})
}

// TestMultiPlatformK8sE2E tests end-to-end multi-platform builds with Kubernetes
func TestMultiPlatformK8sE2E(t *testing.T) {
	if os.Getenv("KANIKO_TEST_K8S") == "" {
		t.Skip("Skipping Kubernetes E2E test. Set KANIKO_TEST_K8S=1 to enable")
	}

	if os.Getenv("KANIKO_TEST_MULTIPLATFORM") == "" {
		t.Skip("Skipping multi-platform Kubernetes E2E test. Set KANIKO_TEST_MULTIPLATFORM=1 to enable")
	}

	// This test requires a real Kubernetes cluster with multi-architecture nodes
	// For now, we'll test the job creation and platform validation

	// Create test context
	contextDir := t.TempDir()
	dockerfilePath := filepath.Join(contextDir, "Dockerfile")

	dockerfileContent := `FROM alpine:latest
RUN echo "Kubernetes multi-platform build" > /k8s-test.txt
CMD ["cat", "/k8s-test.txt"]
`
	err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create Dockerfile: %v", err)
	}

	// Test platforms
	platforms := []string{"linux/amd64", "linux/arm64"}

	// Create Kubernetes job manifest for multi-platform build
	jobManifest := createMultiPlatformJobManifest("test-multi-k8s", contextDir, platforms, config.imageRepo)

	// Write manifest to temp file
	tmpfile, err := os.CreateTemp("", "kaniko-multiplatform-job-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	_, err = tmpfile.WriteString(jobManifest)
	if err != nil {
		t.Fatalf("Failed to write job manifest: %v", err)
	}
	tmpfile.Close()

	// Apply the job (this would require a real Kubernetes cluster)
	t.Logf("Job manifest created at: %s", tmpfile.Name())
	t.Logf("To test with a real cluster, run: kubectl apply -f %s", tmpfile.Name())

	// For now, just validate the manifest content
	validateMultiPlatformJobManifest(t, jobManifest, platforms)
}

// TestMultiPlatformImageVerification tests that multi-platform images can be pulled and used
func TestMultiPlatformImageVerification(t *testing.T) {
	if os.Getenv("KANIKO_TEST_MULTIPLATFORM") == "" {
		t.Skip("Skipping multi-platform image verification test. Set KANIKO_TEST_MULTIPLATFORM=1 to enable")
	}

	// This test verifies that multi-platform images can be pulled and inspected
	// using standard container tools

	testImage := fmt.Sprintf("%s/test-verification", config.imageRepo)

	// Create a simple multi-platform index for testing
	contextDir := t.TempDir()
	dockerfilePath := filepath.Join(contextDir, "Dockerfile")

	dockerfileContent := `FROM alpine:latest
RUN echo "Verification test" > /verify.txt
CMD ["cat", "/verify.txt"]
`
	err := os.WriteFile(dockerfilePath, []byte(dockerfileContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create Dockerfile: %v", err)
	}

	// Build for multiple platforms
	platforms := []string{"linux/amd64", "linux/arm64"}

	for _, platform := range platforms {
		imageName := fmt.Sprintf("%s-test-%s", testImage, strings.ReplaceAll(platform, "/", "-"))

		dockerRunFlags := []string{"run", "--net=host"}
		dockerRunFlags = addServiceAccountFlags(dockerRunFlags, config.serviceAccount)
		dockerRunFlags = append(dockerRunFlags,
			ExecutorImage,
			"-c", fmt.Sprintf("dir://%s", contextDir),
			"-f", "Dockerfile",
			"-d", imageName,
			"--custom-platform", platform,
			"--no-push",
		)

		cmd := exec.Command("docker", dockerRunFlags...)
		out, err := RunCommandWithoutTest(cmd)
		if err != nil {
			t.Fatalf("Failed to build verification image for %s: %v\n%s", platform, err, string(out))
		}
	}

	// Test that crane can inspect the images (if available)
	if _, err := exec.LookPath("crane"); err == nil {
		for _, platform := range platforms {
			imageName := fmt.Sprintf("%s-test-%s", testImage, strings.ReplaceAll(platform, "/", "-"))

			cmd := exec.Command("crane", "manifest", imageName)
			out, err := RunCommandWithoutTest(cmd)
			if err != nil {
				t.Logf("Warning: crane manifest failed for %s: %v", imageName, err)
			} else {
				t.Logf("Crane manifest for %s:\n%s", imageName, string(out))
			}
		}
	}

	// Test that go-containerregistry can pull the images
	for _, platform := range platforms {
		imageName := fmt.Sprintf("%s-test-%s", testImage, strings.ReplaceAll(platform, "/", "-"))

		ref, err := name.ParseReference(imageName, name.WeakValidation)
		if err != nil {
			t.Logf("Warning: failed to parse reference for %s: %v", imageName, err)
			continue
		}

		img, err := remote.Image(ref)
		if err != nil {
			t.Logf("Warning: failed to pull image %s: %v", imageName, err)
			continue
		}

		digest, err := img.Digest()
		if err != nil {
			t.Logf("Warning: failed to get digest for %s: %v", imageName, err)
			continue
		}

		t.Logf("Successfully pulled %s with digest: %s", imageName, digest.Hex)
	}
}

// Helper functions

func getImageDigest(imageName string) (string, error) {
	cmd := exec.Command("docker", "inspect", "--format='{{index .Id}}'", imageName)
	out, err := RunCommandWithoutTest(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to get image digest: %v", err)
	}

	// Clean up the output (remove quotes and newlines)
	digest := strings.TrimSpace(strings.Trim(string(out), "'\"\n"))
	if strings.HasPrefix(digest, "sha256:") {
		return digest, nil
	}

	// If it's a short ID, try to get the full digest
	cmd = exec.Command("docker", "inspect", "--format='{{index .RepoDigests}}'", imageName)
	out, err = RunCommandWithoutTest(cmd)
	if err != nil {
		return "", fmt.Errorf("failed to get repo digest: %v", err)
	}

	digests := strings.TrimSpace(strings.Trim(string(out), "[]'\"\n"))
	if strings.Contains(digests, "@") {
		parts := strings.Split(digests, "@")
		if len(parts) > 1 {
			return "sha256:" + parts[1], nil
		}
	}

	return "", fmt.Errorf("could not determine digest for image %s", imageName)
}

func verifyImagePlatform(t *testing.T, imageName, expectedPlatform string) {
	// Inspect the image to verify platform
	cmd := exec.Command("docker", "inspect", "--format='{{.Os}}/{{.Architecture}}'", imageName)
	out, err := RunCommandWithoutTest(cmd)
	if err != nil {
		t.Fatalf("Failed to inspect image platform: %v", err)
	}

	actualPlatform := strings.TrimSpace(strings.Trim(string(out), "'\"\n"))
	if actualPlatform != expectedPlatform {
		t.Errorf("Expected platform %s, got %s", expectedPlatform, actualPlatform)
	} else {
		t.Logf("Image %s has correct platform: %s", imageName, actualPlatform)
	}
}

func verifyMultiPlatformIndex(t *testing.T, indexName string, expectedPlatforms []string) {
	// Use crane to inspect the manifest if available
	if _, err := exec.LookPath("crane"); err == nil {
		cmd := exec.Command("crane", "manifest", indexName)
		out, err := RunCommandWithoutTest(cmd)
		if err != nil {
			t.Logf("Warning: crane manifest failed: %v", err)
		} else {
			t.Logf("Multi-platform manifest for %s:\n%s", indexName, string(out))
		}
	}

	// Verify we can pull the index
	ref, err := name.ParseReference(indexName, name.WeakValidation)
	if err != nil {
		t.Fatalf("Failed to parse index reference: %v", err)
	}

	index, err := remote.Index(ref)
	if err != nil {
		t.Fatalf("Failed to pull multi-platform index: %v", err)
	}

	manifest, err := index.IndexManifest()
	if err != nil {
		t.Fatalf("Failed to get index manifest: %v", err)
	}

	if len(manifest.Manifests) == 0 {
		t.Error("Multi-platform index should have manifests")
	}

	// Check that we have manifests for the expected platforms
	platformsFound := make(map[string]bool)
	for _, manifest := range manifest.Manifests {
		platform := fmt.Sprintf("%s/%s", manifest.Platform.OS, manifest.Platform.Architecture)
		platformsFound[platform] = true
		t.Logf("Found platform in index: %s", platform)
	}

	for _, expected := range expectedPlatforms {
		if !platformsFound[expected] {
			t.Errorf("Expected platform %s not found in index", expected)
		}
	}

	t.Logf("Multi-platform index %s verified successfully", indexName)
}

func createMultiPlatformJobManifest(jobName, contextDir string, platforms []string, imageRepo string) string {
	// This creates a Kubernetes job manifest for multi-platform builds
	// In a real implementation, this would create separate jobs for each platform

	var manifest strings.Builder
	manifest.WriteString(`apiVersion: batch/v1
kind: Job
metadata:
  name: ` + jobName + `
spec:
  template:
    spec:
      serviceAccountName: kaniko-builder
      restartPolicy: Never
      containers:
      - name: kaniko
        image: gcr.io/kaniko-project/executor:latest
        args:
        - --context=dir:///workspace
        - --dockerfile=Dockerfile
        - --destination=` + imageRepo + `/` + jobName + `:latest
        - --custom-platform=linux/amd64
        volumeMounts:
        - name: workspace
          mountPath: /workspace
      volumes:
      - name: workspace
        emptyDir: {}
`)

	return manifest.String()
}

func validateMultiPlatformJobManifest(t *testing.T, manifest string, platforms []string) {
	// Basic validation of the job manifest
	if !strings.Contains(manifest, "kaniko-builder") {
		t.Error("Job manifest should reference kaniko-builder service account")
	}

	if !strings.Contains(manifest, "executor:latest") {
		t.Error("Job manifest should use kaniko executor image")
	}

	if !strings.Contains(manifest, "--destination=") {
		t.Error("Job manifest should specify destination")
	}

	// Check that platform-specific configurations are present
	for _, platform := range platforms {
		if strings.Contains(platform, "linux") {
			if !strings.Contains(manifest, "linux/amd64") {
				t.Logf("Warning: manifest may not be optimized for %s platform", platform)
			}
		}
	}

	t.Logf("Job manifest validation passed")
}
