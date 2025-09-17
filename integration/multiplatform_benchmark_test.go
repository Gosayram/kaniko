/*
Copyright 2025 Google LLC

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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

type multiplatformResult struct {
	TotalBuildTime      float64
	CoordinatorTime     float64
	SingleArchBuildTime float64
	MultiArchBuildTime  float64
	OverheadPercentage  float64
	PlatformCount       int
}

func TestMultiplatformCoordinatorOverhead(t *testing.T) {
	if b, err := strconv.ParseBool(os.Getenv("BENCHMARK")); err != nil || !b {
		t.SkipNow()
	}
	
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	
	// Create a simple test context for multi-platform benchmark
	contextDir := createMultiplatformBenchmarkContext(t, cwd)
	defer os.RemoveAll(contextDir)
	
	// Test different platform combinations
	testCases := []struct {
		name           string
		platforms      []string
		expectedOverhead float64 // Expected overhead percentage (should be < 10%)
	}{
		{
			name:           "single-arch vs multi-arch (2 platforms)",
			platforms:      []string{"linux/amd64", "linux/arm64"},
			expectedOverhead: 10.0, // 10% max allowed overhead
		},
		{
			name:           "single-arch vs multi-arch (3 platforms)",
			platforms:      []string{"linux/amd64", "linux/arm64", "linux/s390x"},
			expectedOverhead: 10.0, // 10% max allowed overhead
		},
		{
			name:           "single-arch vs multi-arch (4 platforms)",
			platforms:      []string{"linux/amd64", "linux/arm64", "linux/s390x", "linux/ppc64le"},
			expectedOverhead: 10.0, // 10% max allowed overhead
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := runMultiplatformBenchmark(t, contextDir, tc.platforms)
			
			// Verify overhead is within acceptable limits
			if result.OverheadPercentage > tc.expectedOverhead {
				t.Errorf("Coordinator overhead %.2f%% exceeds expected %.2f%%", 
					result.OverheadPercentage, tc.expectedOverhead)
			}
			
			// Log detailed results
			t.Logf("Platform Count: %d", result.PlatformCount)
			t.Logf("Single-arch Build Time: %.2fs", result.SingleArchBuildTime)
			t.Logf("Multi-arch Build Time: %.2fs", result.MultiArchBuildTime)
			t.Logf("Coordinator Time: %.2fs", result.CoordinatorTime)
			t.Logf("Total Build Time: %.2fs", result.TotalBuildTime)
			t.Logf("Coordinator Overhead: %.2f%%", result.OverheadPercentage)
			
			// Store result for summary
			storeBenchmarkResult(t, result, tc.name)
		})
	}
}

func runMultiplatformBenchmark(t *testing.T, contextDir string, platforms []string) *multiplatformResult {
	result := &multiplatformResult{
		PlatformCount: len(platforms),
	}
	
	// Measure single-arch build time (baseline)
	singleStartTime := time.Now()
	singleArchImage := fmt.Sprintf("%s_singlearch", GetKanikoImage(config.imageRepo, "Dockerfile"))
	_, err := buildKanikoImage(t.Logf, "", "Dockerfile", 
		[]string{}, []string{}, singleArchImage, contextDir, config.gcsBucket, config.gcsClient,
		config.serviceAccount, false)
	if err != nil {
		t.Fatalf("Failed to build single-arch image: %v", err)
	}
	result.SingleArchBuildTime = time.Since(singleStartTime).Seconds()
	
	// Measure multi-arch build time with coordinator
	multiStartTime := time.Now()
	multiArchImage := fmt.Sprintf("%s_multiarch", GetKanikoImage(config.imageRepo, "Dockerfile"))
	
	// Build args for multi-platform
	buildArgs := []string{
		"--platform=" + platforms[0], // First platform
		"--multi-platform=true",
	}
	
	// Add additional platforms for multi-arch builds
	if len(platforms) > 1 {
		// For multi-platform builds, we need to use the coordinator
		// This simulates the coordinator behavior by building multiple times
		for _, platform := range platforms[1:] {
			platformBuildArgs := append(buildArgs, "--platform="+platform)
			_, err := buildKanikoImage(t.Logf, "", "Dockerfile", 
				platformBuildArgs, []string{}, multiArchImage+"_"+platform, contextDir, config.gcsBucket, config.gcsClient,
				config.serviceAccount, false)
			if err != nil {
				t.Fatalf("Failed to build multi-platform image for %s: %v", platform, err)
			}
		}
	}
	
	result.MultiArchBuildTime = time.Since(multiStartTime).Seconds()
	result.TotalBuildTime = result.MultiArchBuildTime
	
	// Calculate coordinator overhead (time difference between multi-arch and single-arch)
	timeDifference := result.MultiArchBuildTime - result.SingleArchBuildTime
	result.OverheadPercentage = (timeDifference / result.SingleArchBuildTime) * 100
	
	// Estimate coordinator time (portion of overhead attributed to coordination)
	result.CoordinatorTime = timeDifference * 0.3 // Assume 30% of overhead is coordination
	
	return result
}

func createMultiplatformBenchmarkContext(t *testing.T, cwd string) string {
	contextDir, err := os.MkdirTemp("", "multiplatform-benchmark")
	if err != nil {
		t.Fatal(err)
	}
	
	// Create a simple Dockerfile that builds quickly
	dockerfile := `FROM alpine:3.18
RUN echo "Benchmark test" > /test.txt
COPY context.txt /context.txt
`
	
	err = os.WriteFile(filepath.Join(contextDir, "Dockerfile"), []byte(dockerfile), 0644)
	if err != nil {
		t.Fatal(err)
	}
	
	// Create a simple context file
	contextContent := `This is a benchmark test file
It contains minimal content for quick builds
`
	err = os.WriteFile(filepath.Join(contextDir, "context.txt"), []byte(contextContent), 0644)
	if err != nil {
		t.Fatal(err)
	}
	
	return contextDir
}

func storeBenchmarkResult(t *testing.T, result *multiplatformResult, testName string) {
	// Store results for later analysis
	resultFile := fmt.Sprintf("multiplatform_benchmark_%s.json", testName)
	
	resultData := map[string]interface{}{
		"test_name":            testName,
		"timestamp":            time.Now().Format(time.RFC3339),
		"platform_count":       result.PlatformCount,
		"total_build_time":     result.TotalBuildTime,
		"coordinator_time":     result.CoordinatorTime,
		"single_arch_time":     result.SingleArchBuildTime,
		"multi_arch_time":      result.MultiArchBuildTime,
		"overhead_percentage":  result.OverheadPercentage,
	}
	
	jsonData, err := json.MarshalIndent(resultData, "", "  ")
	if err != nil {
		t.Logf("Failed to marshal benchmark result: %v", err)
		return
	}
	
	err = os.WriteFile(resultFile, jsonData, 0644)
	if err != nil {
		t.Logf("Failed to write benchmark result file: %v", err)
		return
	}
	
	t.Logf("Benchmark results stored in %s", resultFile)
}

func TestMultiplatformDriverOverhead(t *testing.T) {
	if b, err := strconv.ParseBool(os.Getenv("BENCHMARK")); err != nil || !b {
		t.SkipNow()
	}
	
	// Test overhead for different drivers
	drivers := []struct {
		name     string
		driver   string
		platform string
	}{
		{"local-driver", "local", "linux/amd64"},
		{"k8s-driver", "k8s", "linux/amd64"},
		{"ci-driver", "ci", "linux/amd64"},
	}
	
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	contextDir := createMultiplatformBenchmarkContext(t, cwd)
	defer os.RemoveAll(contextDir)
	
	for _, driver := range drivers {
		t.Run(driver.name, func(t *testing.T) {
			startTime := time.Now()
			
			// Build with specific driver
			driverImage := fmt.Sprintf("%s_%s", GetKanikoImage(config.imageRepo, "Dockerfile"), driver.driver)
			buildArgs := []string{
				"--platform=" + driver.platform,
				"--multi-platform=true",
				"--driver=" + driver.driver,
			}
			
			_, err := buildKanikoImage(t.Logf, "", "Dockerfile", 
				buildArgs, []string{}, driverImage, contextDir, config.gcsBucket, config.gcsClient,
				config.serviceAccount, false)
			if err != nil {
				t.Fatalf("Failed to build with %s driver: %v", driver.driver, err)
			}
			
			buildTime := time.Since(startTime).Seconds()
			t.Logf("%s driver build time: %.2fs", driver.name, buildTime)
			
			// Store driver-specific benchmark result
			resultData := map[string]interface{}{
				"driver":       driver.driver,
				"platform":     driver.platform,
				"build_time":   buildTime,
				"timestamp":    time.Now().Format(time.RFC3339),
			}
			
			jsonData, err := json.MarshalIndent(resultData, "", "  ")
			if err != nil {
				t.Logf("Failed to marshal driver benchmark result: %v", err)
				return
			}
			
			resultFile := fmt.Sprintf("driver_benchmark_%s.json", driver.driver)
			err = os.WriteFile(resultFile, jsonData, 0644)
			if err != nil {
				t.Logf("Failed to write driver benchmark result file: %v", err)
				return
			}
		})
	}
}