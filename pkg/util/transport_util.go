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

package util //nolint:revive // package name 'util' is intentionally generic

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"net/http"

	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
)

// CertPool defines an interface for certificate pool operations
type CertPool interface {
	value() *x509.CertPool
	append(path string) error
}

// X509CertPool implements CertPool using x509.CertPool
type X509CertPool struct {
	inner x509.CertPool
}

func (p *X509CertPool) value() *x509.CertPool {
	return &p.inner
}

func (p *X509CertPool) append(path string) error {
	// Validate the file path to prevent directory traversal
	if err := ValidateFilePath(path); err != nil {
		return fmt.Errorf("invalid certificate path: %w", err)
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	p.inner.AppendCertsFromPEM(pem)
	return nil
}

var systemCertLoader CertPool

// KeyPairLoader defines an interface for loading TLS key pairs
type KeyPairLoader interface {
	load(string, string) (tls.Certificate, error)
}

// X509KeyPairLoader implements KeyPairLoader using tls.LoadX509KeyPair
type X509KeyPairLoader struct {
}

func (p *X509KeyPairLoader) load(certFile, keyFile string) (tls.Certificate, error) {
	return tls.LoadX509KeyPair(certFile, keyFile)
}

var systemKeyPairLoader KeyPairLoader

// Initialize initializes the transport utilities
func Initialize() {
	systemCertPool, err := x509.SystemCertPool()
	if err != nil {
		logrus.Warn("Failed to load system cert pool. Loading empty one instead.")
		systemCertPool = x509.NewCertPool()
	}
	systemCertLoader = &X509CertPool{
		inner: *systemCertPool,
	}

	systemKeyPairLoader = &X509KeyPairLoader{}
}

// MakeTransport creates an HTTP transport with TLS configuration based on registry options
func MakeTransport(opts *config.RegistryOptions, registryName string) (http.RoundTripper, error) {
	// Create a transport to set our user-agent.
	var tr http.RoundTripper = http.DefaultTransport.(*http.Transport).Clone()
	if opts.SkipTLSVerify || opts.SkipTLSVerifyRegistries.Contains(registryName) {
		// InsecureSkipVerify is intentionally set to true to allow connections to
		// registries with self-signed certificates or other TLS issues.
		// This is a user-controlled option for development/testing environments.
		tr.(*http.Transport).TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // intentionally allowing insecure connections for development/testing
		}
	} else if certificatePath := opts.RegistriesCertificates[registryName]; certificatePath != "" {
		if err := systemCertLoader.append(certificatePath); err != nil {
			return nil, fmt.Errorf("failed to load certificate %s for %s: %w", certificatePath, registryName, err)
		}
		tr.(*http.Transport).TLSClientConfig = &tls.Config{
			RootCAs:    systemCertLoader.value(),
			MinVersion: tls.VersionTLS12, // Set minimum TLS version to 1.2 for security
		}
	}

	if clientCertificatePath := opts.RegistriesClientCertificates[registryName]; clientCertificatePath != "" {
		certFiles := strings.Split(clientCertificatePath, ",")
		const expectedCertFilesCount = 2 // expected format: cert_path,key_path

		if len(certFiles) != expectedCertFilesCount {
			return nil, fmt.Errorf("failed to load client certificate/key '%s=%s', "+
				"expected format: %s=/path/to/cert,/path/to/key",
				registryName, clientCertificatePath, registryName)
		}
		cert, err := systemKeyPairLoader.load(certFiles[0], certFiles[1])
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate/key '%s' for %s: %w",
				clientCertificatePath, registryName, err)
		}
		tr.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{cert}
	}

	return tr, nil
}
