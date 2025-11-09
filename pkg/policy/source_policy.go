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

// Package policy provides source policy validation for security
// Inspired by BuildKit's source policy feature
package policy

import (
	"fmt"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// SourcePolicy defines policies for controlling image sources
type SourcePolicy struct {
	// AllowedRegistries is a list of allowed registry patterns
	AllowedRegistries []string

	// DeniedRegistries is a list of denied registry patterns
	DeniedRegistries []string

	// AllowedRepos is a list of allowed repository patterns
	AllowedRepos []string

	// DeniedRepos is a list of denied repository patterns
	DeniedRepos []string

	// RequireSignature requires images to be signed
	RequireSignature bool
}

// NewSourcePolicy creates a new source policy
func NewSourcePolicy() *SourcePolicy {
	return &SourcePolicy{
		AllowedRegistries: []string{},
		DeniedRegistries:  []string{},
		AllowedRepos:      []string{},
		DeniedRepos:       []string{},
		RequireSignature:  false,
	}
}

// ErrDeniedRegistry is returned when a registry is denied
var ErrDeniedRegistry = errors.New("registry is denied by policy")

// ErrNotAllowedRegistry is returned when a registry is not allowed
var ErrNotAllowedRegistry = errors.New("registry is not in allowed list")

// ErrDeniedRepo is returned when a repository is denied
var ErrDeniedRepo = errors.New("repository is denied by policy")

// ErrNotAllowedRepo is returned when a repository is not allowed
var ErrNotAllowedRepo = errors.New("repository is not in allowed list")

// ErrSignatureRequired is returned when signature is required but not present
var ErrSignatureRequired = errors.New("signature is required but not present")

// Validate validates a reference against the source policy
func (sp *SourcePolicy) Validate(ref name.Reference) error {
	registry := ref.Context().RegistryStr()
	repo := ref.Context().RepositoryStr()

	logrus.Debugf("Validating reference: registry=%s, repo=%s", registry, repo)

	// Check denied registries first (most restrictive)
	if len(sp.DeniedRegistries) > 0 {
		for _, denied := range sp.DeniedRegistries {
			if sp.matchesPattern(registry, denied) {
				logrus.Warnf("Registry %s is denied by policy (pattern: %s)", registry, denied)
				return ErrDeniedRegistry
			}
		}
	}

	// Check allowed registries
	if len(sp.AllowedRegistries) > 0 {
		allowed := false
		for _, allowedReg := range sp.AllowedRegistries {
			if sp.matchesPattern(registry, allowedReg) {
				allowed = true
				break
			}
		}
		if !allowed {
			logrus.Warnf("Registry %s is not in allowed list", registry)
			return ErrNotAllowedRegistry
		}
	}

	// Check denied repos
	if len(sp.DeniedRepos) > 0 {
		for _, denied := range sp.DeniedRepos {
			if sp.matchesPattern(repo, denied) {
				logrus.Warnf("Repository %s is denied by policy (pattern: %s)", repo, denied)
				return ErrDeniedRepo
			}
		}
	}

	// Check allowed repos
	if len(sp.AllowedRepos) > 0 {
		allowed := false
		for _, allowedRepo := range sp.AllowedRepos {
			if sp.matchesPattern(repo, allowedRepo) {
				allowed = true
				break
			}
		}
		if !allowed {
			logrus.Warnf("Repository %s is not in allowed list", repo)
			return ErrNotAllowedRepo
		}
	}

	logrus.Debugf("Reference validated successfully: %s", ref.String())
	return nil
}

// ValidateWithSignature validates a reference and checks for signature if required
func (sp *SourcePolicy) ValidateWithSignature(ref name.Reference, hasSignature bool) error {
	if err := sp.Validate(ref); err != nil {
		return err
	}

	if sp.RequireSignature && !hasSignature {
		logrus.Warnf("Signature required for %s but not present", ref.String())
		return ErrSignatureRequired
	}

	return nil
}

// matchesPattern checks if a string matches a pattern
// Supports wildcards: * matches any sequence of characters
func (sp *SourcePolicy) matchesPattern(str, pattern string) bool {
	// Exact match
	if str == pattern {
		return true
	}

	// Simple prefix/suffix wildcard matching (most common cases)
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(str, suffix)
	}

	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(str, prefix)
	}

	// Complex wildcard matching (multiple wildcards)
	if strings.Contains(pattern, "*") {
		// Convert pattern to regex-like matching
		patternParts := strings.Split(pattern, "*")
		if len(patternParts) == 1 {
			// No wildcard, exact match
			return str == pattern
		}

		// Check if string matches pattern with wildcards
		matched := true
		remaining := str

		for i, part := range patternParts {
			if part == "" {
				// Leading or trailing wildcard
				if i == 0 {
					// Leading wildcard - check if string ends with next part
					if i+1 < len(patternParts) {
						nextPart := patternParts[i+1]
						if nextPart != "" && strings.HasSuffix(remaining, nextPart) {
							remaining = strings.TrimSuffix(remaining, nextPart)
							continue
						}
					}
				}
				continue
			}

			idx := strings.Index(remaining, part)
			if idx == -1 {
				matched = false
				break
			}

			remaining = remaining[idx+len(part):]
		}

		return matched
	}

	return false
}

// SetAllowedRegistries sets the allowed registries
func (sp *SourcePolicy) SetAllowedRegistries(registries []string) {
	sp.AllowedRegistries = registries
}

// SetDeniedRegistries sets the denied registries
func (sp *SourcePolicy) SetDeniedRegistries(registries []string) {
	sp.DeniedRegistries = registries
}

// SetAllowedRepos sets the allowed repositories
func (sp *SourcePolicy) SetAllowedRepos(repos []string) {
	sp.AllowedRepos = repos
}

// SetDeniedRepos sets the denied repositories
func (sp *SourcePolicy) SetDeniedRepos(repos []string) {
	sp.DeniedRepos = repos
}

// SetRequireSignature sets whether signature is required
func (sp *SourcePolicy) SetRequireSignature(require bool) {
	sp.RequireSignature = require
}

// String returns a string representation of the policy
func (sp *SourcePolicy) String() string {
	var parts []string

	if len(sp.AllowedRegistries) > 0 {
		parts = append(parts, fmt.Sprintf("allowed-registries=%v", sp.AllowedRegistries))
	}
	if len(sp.DeniedRegistries) > 0 {
		parts = append(parts, fmt.Sprintf("denied-registries=%v", sp.DeniedRegistries))
	}
	if len(sp.AllowedRepos) > 0 {
		parts = append(parts, fmt.Sprintf("allowed-repos=%v", sp.AllowedRepos))
	}
	if len(sp.DeniedRepos) > 0 {
		parts = append(parts, fmt.Sprintf("denied-repos=%v", sp.DeniedRepos))
	}
	if sp.RequireSignature {
		parts = append(parts, "require-signature=true")
	}

	if len(parts) == 0 {
		return "SourcePolicy(empty)"
	}

	return fmt.Sprintf("SourcePolicy(%s)", strings.Join(parts, ", "))
}
