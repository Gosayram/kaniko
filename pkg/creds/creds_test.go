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

package creds

import (
	"testing"

	"github.com/Gosayram/kaniko/pkg/config"
)

func TestGetKeychain(t *testing.T) {
	tests := []struct {
		name   string
		opts   *config.RegistryOptions
		verify func(t *testing.T, keychain interface{})
	}{
		{
			name: "nil options uses all helpers",
			opts: nil,
			verify: func(t *testing.T, keychain interface{}) {
				// Should not be nil
				if keychain == nil {
					t.Error("keychain should not be nil")
				}
			},
		},
		{
			name: "empty options uses all helpers",
			opts: &config.RegistryOptions{
				CredentialHelpers: []string{},
			},
			verify: func(t *testing.T, keychain interface{}) {
				if keychain == nil {
					t.Error("keychain should not be nil")
				}
			},
		},
		{
			name: "specific helpers",
			opts: &config.RegistryOptions{
				CredentialHelpers: []string{"env", "google"},
			},
			verify: func(t *testing.T, keychain interface{}) {
				if keychain == nil {
					t.Error("keychain should not be nil")
				}
			},
		},
		{
			name: "empty string disables all",
			opts: &config.RegistryOptions{
				CredentialHelpers: []string{""},
			},
			verify: func(t *testing.T, keychain interface{}) {
				if keychain == nil {
					t.Error("keychain should not be nil")
				}
			},
		},
		{
			name: "unknown helper is skipped",
			opts: &config.RegistryOptions{
				CredentialHelpers: []string{"unknown", "env"},
			},
			verify: func(t *testing.T, keychain interface{}) {
				if keychain == nil {
					t.Error("keychain should not be nil")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keychain := GetKeychain(tt.opts)
			tt.verify(t, keychain)
		})
	}
}
