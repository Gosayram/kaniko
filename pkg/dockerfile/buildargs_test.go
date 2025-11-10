/*
Copyright 2024 Google LLC

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

package dockerfile

import (
	"reflect"
	"testing"
)

func TestBuildArgs_ReplacementEnvs_NilSafety(t *testing.T) {
	// Test that ReplacementEnvs handles nil BuildArgs gracefully
	var nilBuildArgs *BuildArgs = nil

	envs := []string{"PATH=/usr/bin", "HOME=/root"}
	result := nilBuildArgs.ReplacementEnvs(envs)

	// Should return original envs when BuildArgs is nil
	if !reflect.DeepEqual(result, envs) {
		t.Errorf("Expected %v, got %v", envs, result)
	}
}

func TestBuildArgs_ReplacementEnvs_WithBuildArgs(t *testing.T) {
	buildArgs := NewBuildArgs([]string{
		"PNPM_VERSION=10.12.3",
		"APP_TYPE=desktop",
	})

	envs := []string{"PATH=/usr/bin", "HOME=/root"}
	result := buildArgs.ReplacementEnvs(envs)

	// Should include original envs, filtered envs, and build args
	expectedCount := len(envs) + 2 // 2 build args
	if len(result) < expectedCount {
		t.Errorf("Expected at least %d envs, got %d", expectedCount, len(result))
	}

	// Check that build args are included
	foundPNPM := false
	foundAPP := false
	for _, env := range result {
		if env == "PNPM_VERSION=10.12.3" {
			foundPNPM = true
		}
		if env == "APP_TYPE=desktop" {
			foundAPP = true
		}
	}

	if !foundPNPM {
		t.Error("PNPM_VERSION build arg not found in replacement envs")
	}
	if !foundAPP {
		t.Error("APP_TYPE build arg not found in replacement envs")
	}
}

func TestBuildArgs_GetAllAllowed_NilSafety(t *testing.T) {
	// Test that GetAllAllowed handles nil BuildArgs gracefully
	var nilBuildArgs *BuildArgs = nil

	result := nilBuildArgs.GetAllAllowed()

	// Should return empty slice when BuildArgs is nil
	if result == nil {
		t.Error("Expected empty slice, got nil")
	}
	if len(result) != 0 {
		t.Errorf("Expected empty slice, got %v", result)
	}
}

func TestBuildArgs_GetAllAllowed_WithArgs(t *testing.T) {
	buildArgs := NewBuildArgs([]string{
		"PNPM_VERSION=10.12.3",
		"APP_TYPE=desktop",
		"NO_VALUE", // arg without value
	})

	// Add meta args
	value1 := "meta1"
	value2 := "meta2"
	buildArgs.AddMetaArg("META_ARG1", &value1)
	buildArgs.AddMetaArg("META_ARG2", &value2)
	buildArgs.AddMetaArg("META_ARG3", nil) // nil value

	result := buildArgs.GetAllAllowed()

	// Should include args with values and meta args with values
	// NO_VALUE and META_ARG3 should not be included (nil values)
	expectedCount := 4 // PNPM_VERSION, APP_TYPE, META_ARG1, META_ARG2
	if len(result) != expectedCount {
		t.Errorf("Expected %d args, got %d: %v", expectedCount, len(result), result)
	}

	// Verify specific args are present
	argsMap := make(map[string]bool)
	for _, arg := range result {
		argsMap[arg] = true
	}

	expectedArgs := []string{
		"PNPM_VERSION=10.12.3",
		"APP_TYPE=desktop",
		"META_ARG1=meta1",
		"META_ARG2=meta2",
	}

	for _, expected := range expectedArgs {
		if !argsMap[expected] {
			t.Errorf("Expected arg %s not found in result", expected)
		}
	}
}

func TestBuildArgs_FilterAllowed_NilSafety(t *testing.T) {
	// Test that FilterAllowed handles nil BuildArgs gracefully
	var nilBuildArgs *BuildArgs = nil

	envs := []string{"PATH=/usr/bin", "HOME=/root"}

	// This should panic if not handled, but we've added nil check
	// Let's test that it doesn't panic
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("FilterAllowed panicked with nil BuildArgs: %v", r)
		}
	}()

	result := nilBuildArgs.FilterAllowed(envs)

	// Should return empty slice when BuildArgs is nil
	if result == nil {
		t.Error("Expected empty slice, got nil")
	}
	if len(result) != 0 {
		t.Errorf("Expected empty slice, got %v", result)
	}
}

func TestBuildArgs_FilterAllowed_WithAllowedArgs(t *testing.T) {
	buildArgs := NewBuildArgs([]string{
		"PATH",
		"HOME=/root",
	})

	envs := []string{
		"PATH=/usr/bin",
		"HOME=/root",
		"USER=test",
		"PWD=/tmp",
	}

	result := buildArgs.FilterAllowed(envs)

	// Should only include PATH and HOME (allowed args)
	expectedCount := 2
	if len(result) != expectedCount {
		t.Errorf("Expected %d filtered envs, got %d: %v", expectedCount, len(result), result)
	}

	// Verify filtered results
	filteredMap := make(map[string]bool)
	for _, env := range result {
		filteredMap[env] = true
	}

	if !filteredMap["PATH=/usr/bin"] {
		t.Error("PATH should be in filtered results")
	}
	if !filteredMap["HOME=/root"] {
		t.Error("HOME should be in filtered results")
	}
	if filteredMap["USER=test"] {
		t.Error("USER should not be in filtered results")
	}
}

func TestBuildArgs_GetAllowed(t *testing.T) {
	buildArgs := NewBuildArgs([]string{
		"ARG1=value1",
		"ARG2", // no value
	})

	// Add meta arg
	metaValue := "meta_value"
	buildArgs.AddMetaArg("META_ARG", &metaValue)

	// Test getting allowed arg with value
	value, ok := buildArgs.GetAllowed("ARG1")
	if !ok {
		t.Error("Expected ARG1 to be found")
	}
	if value != "value1" {
		t.Errorf("Expected value1, got %s", value)
	}

	// Test getting allowed arg without value
	value, ok = buildArgs.GetAllowed("ARG2")
	if ok {
		t.Error("ARG2 should not be found (no value)")
	}

	// Test getting meta arg
	value, ok = buildArgs.GetAllowed("META_ARG")
	if !ok {
		t.Error("Expected META_ARG to be found")
	}
	if value != "meta_value" {
		t.Errorf("Expected meta_value, got %s", value)
	}

	// Test getting non-existent arg
	value, ok = buildArgs.GetAllowed("NON_EXISTENT")
	if ok {
		t.Error("NON_EXISTENT should not be found")
	}
}

func TestBuildArgs_Clone(t *testing.T) {
	buildArgs := NewBuildArgs([]string{
		"ARG1=value1",
		"ARG2=value2",
	})

	metaValue := "meta"
	buildArgs.AddMetaArg("META", &metaValue)

	clone := buildArgs.Clone()

	// Clone should have same values
	if len(clone.GetAllAllowed()) != len(buildArgs.GetAllAllowed()) {
		t.Error("Clone should have same number of args")
	}

	// Modifying clone should not affect original
	cloneValue := "new_value"
	clone.AddMetaArg("NEW_META", &cloneValue)

	if len(clone.GetAllAllowed()) == len(buildArgs.GetAllAllowed()) {
		t.Error("Clone modification should not affect original")
	}
}
