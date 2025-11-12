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

package constants

import (
	"regexp"
	"strings"
	"testing"
)

func TestConstants_Values(t *testing.T) {
	// Test path constants
	if RootDir != "/" {
		t.Errorf("Expected RootDir=\"/\", got %q", RootDir)
	}

	if !strings.HasPrefix(MountInfoPath, "/proc") {
		t.Errorf("MountInfoPath should start with /proc, got %q", MountInfoPath)
	}

	if !strings.HasPrefix(DefaultKanikoPath, "/") {
		t.Errorf("DefaultKanikoPath should be an absolute path, got %q", DefaultKanikoPath)
	}
}

func TestConstants_SnapshotModes(t *testing.T) {
	// Test snapshot mode constants
	modes := []string{SnapshotModeTime, SnapshotModeFull, SnapshotModeRedo}
	for _, mode := range modes {
		if mode == "" {
			t.Errorf("Snapshot mode should not be empty")
		}
	}
}

func TestConstants_BuildContextPrefixes(t *testing.T) {
	// Test build context prefix constants
	prefixes := []string{
		GCSBuildContextPrefix,
		S3BuildContextPrefix,
		LocalDirBuildContextPrefix,
		GitBuildContextPrefix,
		HTTPSBuildContextPrefix,
	}

	for _, prefix := range prefixes {
		if prefix == "" {
			t.Errorf("Build context prefix should not be empty")
		}
		if !strings.HasSuffix(prefix, "://") {
			t.Errorf("Build context prefix should end with ://, got %q", prefix)
		}
	}
}

func TestConstants_ScratchEnvVars(t *testing.T) {
	// Test ScratchEnvVars
	if len(ScratchEnvVars) == 0 {
		t.Error("ScratchEnvVars should not be empty")
	}

	// Should contain PATH
	foundPath := false
	for _, env := range ScratchEnvVars {
		if strings.HasPrefix(env, "PATH=") {
			foundPath = true
			break
		}
	}
	if !foundPath {
		t.Error("ScratchEnvVars should contain PATH")
	}
}

func TestConstants_AzureBlobStorageHostRegEx(t *testing.T) {
	// Test Azure blob storage regex patterns
	if len(AzureBlobStorageHostRegEx) == 0 {
		t.Error("AzureBlobStorageHostRegEx should not be empty")
	}

	// Test that patterns are valid regex
	testURLs := []string{
		"https://account.blob.core.windows.net/container/blob",
		"https://account.blob.core.chinacloudapi.cn/container/blob",
		"https://account.blob.core.cloudapi.de/container/blob",
		"https://account.blob.core.usgovcloudapi.net/container/blob",
	}

	for i, pattern := range AzureBlobStorageHostRegEx {
		re, err := regexp.Compile(pattern)
		if err != nil {
			t.Errorf("Invalid regex pattern at index %d: %v", i, err)
			continue
		}

		// Test that pattern matches corresponding test URL
		if i < len(testURLs) && !re.MatchString(testURLs[i]) {
			t.Errorf("Pattern at index %d should match test URL %q", i, testURLs[i])
		}
	}
}

func TestConstants_EnvironmentVariables(t *testing.T) {
	// Test environment variable names
	if HOME == "" {
		t.Error("HOME constant should not be empty")
	}

	if DefaultHOMEValue == "" {
		t.Error("DefaultHOMEValue should not be empty")
	}

	if RootUser == "" {
		t.Error("RootUser should not be empty")
	}
}

func TestConstants_DockerfileInstructions(t *testing.T) {
	// Test Dockerfile instruction names
	if Cmd == "" {
		t.Error("Cmd constant should not be empty")
	}

	if Entrypoint == "" {
		t.Error("Entrypoint constant should not be empty")
	}
}

func TestConstants_S3Configuration(t *testing.T) {
	// Test S3 configuration environment variable names
	if S3EndpointEnv == "" {
		t.Error("S3EndpointEnv should not be empty")
	}

	if S3ForcePathStyle == "" {
		t.Error("S3ForcePathStyle should not be empty")
	}
}
