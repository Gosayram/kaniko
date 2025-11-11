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
	"errors"
	"os"
	"strings"

	"github.com/docker/docker-credential-helpers/credentials"
)

// envCredentialsHelper is a credential helper that retrieves credentials
// from environment variables with the pattern KANIKO_<REGISTRY>_USER and
// KANIKO_<REGISTRY>_PASSWORD. Supports FQDN and partial matches.
type envCredentialsHelper struct{}

var (
	// EnvCredentialsHelper is the singleton instance of envCredentialsHelper
	EnvCredentialsHelper = &envCredentialsHelper{}
)

// Add is not supported for environment-based credentials
func (ech *envCredentialsHelper) Add(_ *credentials.Credentials) error {
	return errors.New("unsupported operation")
}

// Delete is not supported for environment-based credentials
func (ech *envCredentialsHelper) Delete(_ string) error {
	return errors.New("unsupported operation")
}

// Get retrieves credentials from environment variables.
// It looks for KANIKO_<REGISTRY>_USER and KANIKO_<REGISTRY>_PASSWORD
// where <REGISTRY> is the uppercase hostname with dashes replaced by underscores.
// Supports partial matches (e.g., GCR_IO for gcr.io).
func (ech *envCredentialsHelper) Get(serverURL string) (username, password string, err error) {
	hostname := strings.ToUpper(strings.ReplaceAll(serverURL, "-", "_"))
	fqdn := strings.Split(hostname, ".")
	for idx := range fqdn {
		_fqdn := strings.Join(fqdn[idx:], "_")
		usr, found := os.LookupEnv("KANIKO_" + _fqdn + "_USER")
		if !found {
			continue
		}
		pwd, found := os.LookupEnv("KANIKO_" + _fqdn + "_PASSWORD")
		if found {
			return usr, pwd, nil
		}
	}
	return "", "", errors.New("no matching env var set")
}

// List is not supported for environment-based credentials
func (ech *envCredentialsHelper) List() (map[string]string, error) {
	return nil, errors.New("unsupported operation")
}
