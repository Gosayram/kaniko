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

// Package attestation provides SBOM (Software Bill of Materials) generation
package attestation

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/Gosayram/kaniko/pkg/config"
)

// SBOM represents a Software Bill of Materials
// Following SPDX (Software Package Data Exchange) format
type SBOM struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      *CreationInfo  `json:"creationInfo"`
	Packages          []Package      `json:"packages,omitempty"`
	Relationships     []Relationship `json:"relationships,omitempty"`
}

// CreationInfo contains information about SBOM creation
type CreationInfo struct {
	Created            time.Time `json:"created"`
	Creators           []string  `json:"creators"`
	LicenseListVersion string    `json:"licenseListVersion,omitempty"`
}

// Package represents a software package in the SBOM
type Package struct {
	SPDXID           string        `json:"SPDXID"`
	Name             string        `json:"name"`
	VersionInfo      string        `json:"versionInfo,omitempty"`
	DownloadLocation string        `json:"downloadLocation,omitempty"`
	FilesAnalyzed    bool          `json:"filesAnalyzed"`
	LicenseConcluded string        `json:"licenseConcluded,omitempty"`
	LicenseDeclared  string        `json:"licenseDeclared,omitempty"`
	CopyrightText    string        `json:"copyrightText,omitempty"`
	ExternalRefs     []ExternalRef `json:"externalRefs,omitempty"`
	Checksums        []Checksum    `json:"checksums,omitempty"`
}

// Relationship represents a relationship between packages
type Relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

// ExternalRef represents an external reference to a package
type ExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// Checksum represents a checksum for a package
type Checksum struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"checksumValue"`
}

// SBOMGenerator generates SBOM for container images
type SBOMGenerator struct {
	opts *config.KanikoOptions
}

// NewSBOMGenerator creates a new SBOM generator
func NewSBOMGenerator(opts *config.KanikoOptions) *SBOMGenerator {
	return &SBOMGenerator{
		opts: opts,
	}
}

// Generate generates SBOM for an image
func (sg *SBOMGenerator) Generate(ctx context.Context, image v1.Image, imageName string) (*SBOM, error) {
	// Get image digest
	digest, err := image.Digest()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get image digest")
	}

	// Get config file
	configFile, err := image.ConfigFile()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get config file")
	}

	// Get layers
	layers, err := image.Layers()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get layers")
	}

	// Build packages from layers
	packages := []Package{}
	for i, layer := range layers {
		layerDigest, err := layer.Digest()
		if err != nil {
			logrus.Warnf("Failed to get digest for layer %d: %v", i, err)
			continue
		}

		layerDiffID, err := layer.DiffID()
		if err != nil {
			logrus.Warnf("Failed to get diff ID for layer %d: %v", i, err)
			continue
		}

		pkg := Package{
			SPDXID:           fmt.Sprintf("SPDXRef-Layer-%d", i),
			Name:             fmt.Sprintf("layer-%d", i),
			DownloadLocation: layerDigest.String(),
			FilesAnalyzed:    false,
			Checksums: []Checksum{
				{
					Algorithm: "SHA256",
					Value:     layerDigest.Hex,
				},
				{
					Algorithm: "SHA256",
					Value:     layerDiffID.Hex,
				},
			},
			ExternalRefs: []ExternalRef{
				{
					ReferenceCategory: "PACKAGE-MANAGER",
					ReferenceType:     "purl",
					ReferenceLocator:  fmt.Sprintf("pkg:oci/%s@%s", imageName, layerDigest.Hex),
				},
			},
		}
		packages = append(packages, pkg)
	}

	// Create main package for the image
	mainPackage := Package{
		SPDXID:           "SPDXRef-Image",
		Name:             imageName,
		VersionInfo:      digest.Hex,
		DownloadLocation: digest.String(),
		FilesAnalyzed:    false,
		Checksums: []Checksum{
			{
				Algorithm: "SHA256",
				Value:     digest.Hex,
			},
		},
		ExternalRefs: []ExternalRef{
			{
				ReferenceCategory: "PACKAGE-MANAGER",
				ReferenceType:     "purl",
				ReferenceLocator:  fmt.Sprintf("pkg:oci/%s@%s", imageName, digest.Hex),
			},
		},
	}

	// Add OS information if available
	if configFile != nil && configFile.OS != "" {
		osPackage := Package{
			SPDXID:        "SPDXRef-OS",
			Name:          configFile.OS,
			VersionInfo:   configFile.OSVersion,
			FilesAnalyzed: false,
		}
		packages = append(packages, osPackage)
	}

	// Build relationships
	relationships := []Relationship{}
	for i := range packages {
		if packages[i].SPDXID != "SPDXRef-Image" {
			relationships = append(relationships, Relationship{
				SPDXElementID:      "SPDXRef-Image",
				RelationshipType:   "CONTAINS",
				RelatedSPDXElement: packages[i].SPDXID,
			})
		}
	}

	// Build creation info
	creators := []string{
		"Tool: kaniko",
	}
	if sg.opts != nil && len(sg.opts.Destinations) > 0 {
		creators = append(creators, fmt.Sprintf("Organization: %s", sg.opts.Destinations[0]))
	}

	sbom := &SBOM{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              fmt.Sprintf("SBOM for %s", imageName),
		DocumentNamespace: fmt.Sprintf("https://kaniko.dev/sbom/%s/%s", imageName, digest.Hex),
		CreationInfo: &CreationInfo{
			Created:  time.Now(),
			Creators: creators,
		},
		Packages:      append([]Package{mainPackage}, packages...),
		Relationships: relationships,
	}

	logrus.Debugf("Generated SBOM for image: %s", digest.String())
	return sbom, nil
}

// ToJSON converts SBOM to JSON
func (s *SBOM) ToJSON() ([]byte, error) {
	return json.MarshalIndent(s, "", "  ")
}

// FromJSON parses SBOM from JSON
func SBOMFromJSON(data []byte) (*SBOM, error) {
	var s SBOM
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, errors.Wrap(err, "failed to parse SBOM JSON")
	}
	return &s, nil
}
