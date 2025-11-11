/*
Copyright 2025 Gosayram

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

package executor

import (
	"os"
	"testing"

	"github.com/Gosayram/kaniko/pkg/config"
	"github.com/Gosayram/kaniko/testutil"
)

func TestEnvBool_FF_KANIKO_OCI_STAGES(t *testing.T) {
	// Save old value
	oldValue := os.Getenv("FF_KANIKO_OCI_STAGES")
	defer func() {
		if oldValue == "" {
			os.Unsetenv("FF_KANIKO_OCI_STAGES")
		} else {
			os.Setenv("FF_KANIKO_OCI_STAGES", oldValue)
		}
	}()

	tests := []struct {
		name     string
		envValue string
		expected bool
	}{
		{"enabled via true", "true", true},
		{"enabled via 1", "1", true},
		{"enabled via yes", "yes", true},
		{"enabled via on", "on", true},
		{"disabled via false", "false", false},
		{"disabled when empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.envValue != "" {
				os.Setenv("FF_KANIKO_OCI_STAGES", tt.envValue)
			} else {
				os.Unsetenv("FF_KANIKO_OCI_STAGES")
			}

			result := config.EnvBool("FF_KANIKO_OCI_STAGES")
			testutil.CheckDeepEqual(t, tt.expected, result)
		})
	}
}

func TestKanikoOptions_Flags(t *testing.T) {
	tests := []struct {
		name             string
		opts             *config.KanikoOptions
		checkPreserve    bool
		checkMaterialize bool
		checkPreCleanup  bool
		checkUseOCI      bool
	}{
		{
			name: "all flags enabled",
			opts: &config.KanikoOptions{
				PreserveContext: true,
				Materialize:     true,
				PreCleanup:      true,
				UseOCIStages:    true,
			},
			checkPreserve:    true,
			checkMaterialize: true,
			checkPreCleanup:  true,
			checkUseOCI:      true,
		},
		{
			name: "no flags enabled",
			opts: &config.KanikoOptions{
				PreserveContext: false,
				Materialize:     false,
				PreCleanup:      false,
				UseOCIStages:    false,
			},
			checkPreserve:    false,
			checkMaterialize: false,
			checkPreCleanup:  false,
			checkUseOCI:      false,
		},
		{
			name: "only preserve context",
			opts: &config.KanikoOptions{
				PreserveContext: true,
				Materialize:     false,
				PreCleanup:      false,
				UseOCIStages:    false,
			},
			checkPreserve:    true,
			checkMaterialize: false,
			checkPreCleanup:  false,
			checkUseOCI:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testutil.CheckDeepEqual(t, tt.checkPreserve, tt.opts.PreserveContext)
			testutil.CheckDeepEqual(t, tt.checkMaterialize, tt.opts.Materialize)
			testutil.CheckDeepEqual(t, tt.checkPreCleanup, tt.opts.PreCleanup)
			testutil.CheckDeepEqual(t, tt.checkUseOCI, tt.opts.UseOCIStages)
		})
	}
}
