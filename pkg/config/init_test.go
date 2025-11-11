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

package config

import (
	"os"
	"testing"

	"github.com/Gosayram/kaniko/testutil"
)

func TestEnvBool(t *testing.T) {
	tests := []struct {
		name     string
		envValue string
		expected bool
	}{
		{"true value", "true", true},
		{"1 value", "1", true},
		{"yes value", "yes", true},
		{"on value", "on", true},
		{"false value", "false", false},
		{"empty value", "", false},
		{"other value", "other", false},
		{"0 value", "0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save old value
			oldValue := os.Getenv("TEST_ENV_BOOL")
			defer func() {
				if oldValue == "" {
					os.Unsetenv("TEST_ENV_BOOL")
				} else {
					os.Setenv("TEST_ENV_BOOL", oldValue)
				}
			}()

			// Set test value
			if tt.envValue != "" {
				os.Setenv("TEST_ENV_BOOL", tt.envValue)
			} else {
				os.Unsetenv("TEST_ENV_BOOL")
			}

			result := EnvBool("TEST_ENV_BOOL")
			testutil.CheckDeepEqual(t, tt.expected, result)
		})
	}
}
