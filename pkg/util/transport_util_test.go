/*
Copyright 2020 Google LLC

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

package util

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"testing"

	"github.com/Gosayram/kaniko/pkg/config"
)

type mockedCertPool struct {
	certificatesPath []string
}

func (m *mockedCertPool) value() *x509.CertPool {
	return &x509.CertPool{}
}

func (m *mockedCertPool) append(path string) error {
	m.certificatesPath = append(m.certificatesPath, path)
	return nil
}

type mockedKeyPairLoader struct {
}

func (p *mockedKeyPairLoader) load(certFile, keyFile string) (tls.Certificate, error) {
	foo := tls.Certificate{}
	return foo, nil
}

func Test_makeTransport(t *testing.T) {
	registryName := "my.registry.name"

	tests := []struct {
		name  string
		opts  config.RegistryOptions
		check func(*tls.Config, *mockedCertPool, error)
	}{
		{
			name: "SkipTLSVerify set",
			opts: config.RegistryOptions{SkipTLSVerify: true},
			check: func(config *tls.Config, pool *mockedCertPool, err error) {
				if !config.InsecureSkipVerify {
					t.Errorf("makeTransport().TLSClientConfig.InsecureSkipVerify not set while SkipTLSVerify set")
				}
			},
		},
		{
			name: "SkipTLSVerifyRegistries set with expected registry",
			opts: config.RegistryOptions{SkipTLSVerifyRegistries: []string{registryName}},
			check: func(config *tls.Config, pool *mockedCertPool, err error) {
				if !config.InsecureSkipVerify {
					t.Errorf("makeTransport().TLSClientConfig.InsecureSkipVerify not set while SkipTLSVerifyRegistries set with registry name")
				}
			},
		},
		{
			name: "SkipTLSVerifyRegistries set with other registry",
			opts: config.RegistryOptions{SkipTLSVerifyRegistries: []string{fmt.Sprintf("other.%s", registryName)}},
			check: func(config *tls.Config, pool *mockedCertPool, err error) {
				if config.InsecureSkipVerify {
					t.Errorf("makeTransport().TLSClientConfig.InsecureSkipVerify set while SkipTLSVerifyRegistries not set with registry name")
				}
			},
		},
		{
			name: "RegistriesCertificates set for registry",
			opts: config.RegistryOptions{RegistriesCertificates: map[string]string{registryName: "/path/to/the/certificate.cert"}},
			check: func(config *tls.Config, pool *mockedCertPool, err error) {
				if len(pool.certificatesPath) != 1 || pool.certificatesPath[0] != "/path/to/the/certificate.cert" {
					t.Errorf("makeTransport().RegistriesCertificates certificate not appended to system certificates")
				}
			},
		},
		{
			name: "RegistriesCertificates set for another registry",
			opts: config.RegistryOptions{RegistriesCertificates: map[string]string{fmt.Sprintf("other.%s=", registryName): "/path/to/the/certificate.cert"}},
			check: func(config *tls.Config, pool *mockedCertPool, err error) {
				if len(pool.certificatesPath) != 0 {
					t.Errorf("makeTransport().RegistriesCertificates certificate appended to system certificates while added for other registry")
				}
			},
		},
		{
			name: "RegistriesClientCertificates set for registry",
			opts: config.RegistryOptions{RegistriesClientCertificates: map[string]string{registryName: "/path/to/client/certificate.cert,/path/to/client/key.key"}},
			check: func(config *tls.Config, pool *mockedCertPool, err error) {
				if len(config.Certificates) != 1 {
					t.Errorf("makeTransport().RegistriesClientCertificates not loaded for desired registry")
				}
			},
		},
		{
			name: "RegistriesClientCertificates set for another registry",
			opts: config.RegistryOptions{RegistriesClientCertificates: map[string]string{fmt.Sprintf("other.%s", registryName): "/path/to/client/certificate.cert,/path/to/key.key,/path/to/extra.crt"}},
			check: func(config *tls.Config, pool *mockedCertPool, err error) {
				if len(config.Certificates) != 0 {
					t.Errorf("makeTransport().RegistriesClientCertificates certificate loaded for other registry")
				}
			},
		},
		{
			name: "RegistriesClientCertificates incorrect cert format",
			opts: config.RegistryOptions{RegistriesClientCertificates: map[string]string{registryName: "/path/to/client/certificate.cert"}},
			check: func(config *tls.Config, pool *mockedCertPool, err error) {
				if config != nil {
					t.Errorf("makeTransport().RegistriesClientCertificates was incorrectly loaded without both client/key (config was not nil)")
				}
				expectedError := "failed to load client certificate/key 'my.registry.name=/path/to/client/certificate.cert', expected format: my.registry.name=/path/to/cert,/path/to/key"
				if err == nil {
					t.Errorf("makeTransport().RegistriesClientCertificates was incorrectly loaded without both client/key (expected error, got nil)")
				} else if err.Error() != expectedError {
					t.Errorf("makeTransport().RegistriesClientCertificates was incorrectly loaded without both client/key (expected: %s, got: %s)", expectedError, err.Error())
				}
			},
		},
		{
			name: "RegistriesClientCertificates incorrect cert format extra",
			opts: config.RegistryOptions{RegistriesClientCertificates: map[string]string{registryName: "/path/to/client/certificate.cert,/path/to/key.key,/path/to/extra.crt"}},
			check: func(config *tls.Config, pool *mockedCertPool, err error) {
				if config != nil {
					t.Errorf("makeTransport().RegistriesClientCertificates was incorrectly loaded with extra paths in comma split (config was not nil)")
				}
				expectedError := "failed to load client certificate/key 'my.registry.name=/path/to/client/certificate.cert,/path/to/key.key,/path/to/extra.crt', expected format: my.registry.name=/path/to/cert,/path/to/key"
				if err == nil {
					t.Errorf("makeTransport().RegistriesClientCertificates was incorrectly loaded loaded with extra paths in comma split (expected error, got nil)")
				} else if err.Error() != expectedError {
					t.Errorf("makeTransport().RegistriesClientCertificates was incorrectly loaded loaded with extra paths in comma split (expected: %s, got: %s)", expectedError, err.Error())
				}
			},
		},
	}
	savedSystemCertLoader := systemCertLoader
	savedSystemKeyPairLoader := systemKeyPairLoader
	defer func() {
		systemCertLoader = savedSystemCertLoader
		systemKeyPairLoader = savedSystemKeyPairLoader
	}()
	for _, tt := range tests {
		var certificatesPath []string
		certPool := &mockedCertPool{
			certificatesPath: certificatesPath,
		}
		systemCertLoader = certPool
		systemKeyPairLoader = &mockedKeyPairLoader{}
		t.Run(tt.name, func(t *testing.T) {
			tr, err := MakeTransport(&tt.opts, registryName)
			var tlsConfig *tls.Config
			if err == nil {
				tlsConfig = tr.(*http.Transport).TLSClientConfig
			}
			tt.check(tlsConfig, certPool, err)
		})

	}
}

func TestMakeTransport_DisableHTTP2(t *testing.T) {
	registryName := "test.registry.io"

	// Save and restore environment
	oldValue := os.Getenv("FF_KANIKO_DISABLE_HTTP2")
	defer func() {
		if oldValue == "" {
			os.Unsetenv("FF_KANIKO_DISABLE_HTTP2")
		} else {
			os.Setenv("FF_KANIKO_DISABLE_HTTP2", oldValue)
		}
	}()

	tests := []struct {
		name           string
		envValue       string
		expectDisabled bool
	}{
		{
			name:           "HTTP2 disabled via env",
			envValue:       "true",
			expectDisabled: true,
		},
		{
			name:           "HTTP2 disabled via env (1)",
			envValue:       "1",
			expectDisabled: true,
		},
		{
			name:           "HTTP2 disabled via env (yes)",
			envValue:       "yes",
			expectDisabled: true,
		},
		{
			name:           "HTTP2 disabled via env (on)",
			envValue:       "on",
			expectDisabled: true,
		},
		{
			name:           "HTTP2 enabled (false)",
			envValue:       "false",
			expectDisabled: false,
		},
		{
			name:           "HTTP2 enabled (empty)",
			envValue:       "",
			expectDisabled: false,
		},
	}

	savedSystemCertLoader := systemCertLoader
	savedSystemKeyPairLoader := systemKeyPairLoader
	defer func() {
		systemCertLoader = savedSystemCertLoader
		systemKeyPairLoader = savedSystemKeyPairLoader
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable
			if tt.envValue != "" {
				os.Setenv("FF_KANIKO_DISABLE_HTTP2", tt.envValue)
			} else {
				os.Unsetenv("FF_KANIKO_DISABLE_HTTP2")
			}

			systemCertLoader = &mockedCertPool{}
			systemKeyPairLoader = &mockedKeyPairLoader{}

			opts := &config.RegistryOptions{}
			tr, err := MakeTransport(opts, registryName)
			if err != nil {
				t.Fatalf("MakeTransport failed: %v", err)
			}

			httpTransport := tr.(*http.Transport)

			if tt.expectDisabled {
				if httpTransport.ForceAttemptHTTP2 {
					t.Error("ForceAttemptHTTP2 should be false when FF_KANIKO_DISABLE_HTTP2 is set")
				}
				if httpTransport.TLSClientConfig == nil {
					t.Error("TLSClientConfig should be initialized when disabling HTTP/2")
				} else {
					nextProtos := httpTransport.TLSClientConfig.NextProtos
					foundHTTP11 := false
					for _, proto := range nextProtos {
						if proto == "http/1.1" {
							foundHTTP11 = true
							break
						}
					}
					if !foundHTTP11 {
						t.Error("NextProtos should include 'http/1.1' when disabling HTTP/2")
					}
				}
			} else {
				// When not disabled, ForceAttemptHTTP2 should be true (default)
				if !httpTransport.ForceAttemptHTTP2 {
					t.Error("ForceAttemptHTTP2 should be true (default) when FF_KANIKO_DISABLE_HTTP2 is not set")
				}
			}
		})
	}
}
