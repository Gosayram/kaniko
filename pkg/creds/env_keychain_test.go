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
	"os"
	"testing"

	"github.com/Gosayram/kaniko/testutil"
)

func TestEnvCredentialsHelper_Get(t *testing.T) {
	tests := []struct {
		name      string
		serverURL string
		envVars   map[string]string
		wantUser  string
		wantPass  string
		wantErr   bool
	}{
		{
			name:      "full FQDN match",
			serverURL: "gcr.io",
			envVars: map[string]string{
				"KANIKO_GCR_IO_USER":     "testuser",
				"KANIKO_GCR_IO_PASSWORD": "testpass",
			},
			wantUser: "testuser",
			wantPass: "testpass",
			wantErr:  false,
		},
		{
			name:      "partial match with domain",
			serverURL: "gcr.io",
			envVars: map[string]string{
				"KANIKO_IO_USER":     "partialuser",
				"KANIKO_IO_PASSWORD": "partialpass",
			},
			wantUser: "partialuser",
			wantPass: "partialpass",
			wantErr:  false,
		},
		{
			name:      "registry with dashes",
			serverURL: "my-registry.com",
			envVars: map[string]string{
				"KANIKO_MY_REGISTRY_COM_USER":     "dashuser",
				"KANIKO_MY_REGISTRY_COM_PASSWORD": "dashpass",
			},
			wantUser: "dashuser",
			wantPass: "dashpass",
			wantErr:  false,
		},
		{
			name:      "no matching env vars",
			serverURL: "unknown.io",
			envVars:   map[string]string{},
			wantUser:  "",
			wantPass:  "",
			wantErr:   true,
		},
		{
			name:      "user found but password missing",
			serverURL: "gcr.io",
			envVars: map[string]string{
				"KANIKO_GCR_IO_USER": "testuser",
			},
			wantUser: "",
			wantPass: "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save and restore environment
			oldEnv := make(map[string]string)
			for k, v := range tt.envVars {
				oldEnv[k] = os.Getenv(k)
				os.Setenv(k, v)
			}
			defer func() {
				for k, v := range oldEnv {
					if v == "" {
						os.Unsetenv(k)
					} else {
						os.Setenv(k, v)
					}
				}
			}()

			user, pass, err := EnvCredentialsHelper.Get(tt.serverURL)

			if tt.wantErr {
				testutil.CheckError(t, true, err)
			} else {
				testutil.CheckNoError(t, err)
				testutil.CheckDeepEqual(t, tt.wantUser, user)
				testutil.CheckDeepEqual(t, tt.wantPass, pass)
			}
		})
	}
}

func TestEnvCredentialsHelper_Add(t *testing.T) {
	err := EnvCredentialsHelper.Add(nil)
	testutil.CheckError(t, true, err)
}

func TestEnvCredentialsHelper_Delete(t *testing.T) {
	err := EnvCredentialsHelper.Delete("test")
	testutil.CheckError(t, true, err)
}

func TestEnvCredentialsHelper_List(t *testing.T) {
	_, err := EnvCredentialsHelper.List()
	testutil.CheckError(t, true, err)
}
