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

package policy

import (
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
)

func TestNewSourcePolicy(t *testing.T) {
	policy := NewSourcePolicy()
	if policy == nil {
		t.Fatal("Source policy is nil")
	}

	if len(policy.AllowedRegistries) != 0 {
		t.Error("Expected empty allowed registries")
	}

	if len(policy.DeniedRegistries) != 0 {
		t.Error("Expected empty denied registries")
	}

	if policy.RequireSignature {
		t.Error("Expected RequireSignature to be false by default")
	}
}

func TestSourcePolicyValidate_AllowedRegistries(t *testing.T) {
	policy := NewSourcePolicy()
	policy.SetAllowedRegistries([]string{"gcr.io", "docker.io"})

	ref, err := name.ParseReference("gcr.io/myproject/myimage:tag", name.WeakValidation)
	if err != nil {
		t.Fatalf("Failed to parse reference: %v", err)
	}

	if err := policy.Validate(ref); err != nil {
		t.Errorf("Expected validation to pass for allowed registry, got error: %v", err)
	}

	// Test denied registry
	ref2, err := name.ParseReference("untrusted.io/myimage:tag", name.WeakValidation)
	if err != nil {
		t.Fatalf("Failed to parse reference: %v", err)
	}

	if err := policy.Validate(ref2); err == nil {
		t.Error("Expected validation to fail for non-allowed registry")
	}
}

func TestSourcePolicyValidate_DeniedRegistries(t *testing.T) {
	policy := NewSourcePolicy()
	policy.SetDeniedRegistries([]string{"untrusted.io"})

	ref, err := name.ParseReference("untrusted.io/myimage:tag", name.WeakValidation)
	if err != nil {
		t.Fatalf("Failed to parse reference: %v", err)
	}

	if err := policy.Validate(ref); err == nil {
		t.Error("Expected validation to fail for denied registry")
	}

	if err != nil && err != ErrDeniedRegistry {
		t.Errorf("Expected ErrDeniedRegistry, got %v", err)
	}
}

func TestSourcePolicyValidate_AllowedRepos(t *testing.T) {
	policy := NewSourcePolicy()
	policy.SetAllowedRepos([]string{"myproject/myimage"})

	ref, err := name.ParseReference("gcr.io/myproject/myimage:tag", name.WeakValidation)
	if err != nil {
		t.Fatalf("Failed to parse reference: %v", err)
	}

	if err := policy.Validate(ref); err != nil {
		t.Errorf("Expected validation to pass for allowed repo, got error: %v", err)
	}
}

func TestSourcePolicyValidate_RequireSignature(t *testing.T) {
	policy := NewSourcePolicy()
	policy.SetRequireSignature(true)

	ref, err := name.ParseReference("gcr.io/myproject/myimage:tag", name.WeakValidation)
	if err != nil {
		t.Fatalf("Failed to parse reference: %v", err)
	}

	// Test without signature
	if err := policy.ValidateWithSignature(ref, false); err == nil {
		t.Error("Expected validation to fail when signature is required but not present")
	}

	if err != nil && err != ErrSignatureRequired {
		t.Errorf("Expected ErrSignatureRequired, got %v", err)
	}

	// Test with signature
	if err := policy.ValidateWithSignature(ref, true); err != nil {
		t.Errorf("Expected validation to pass with signature, got error: %v", err)
	}
}

func TestSourcePolicyMatchesPattern(t *testing.T) {
	policy := NewSourcePolicy()

	tests := []struct {
		str     string
		pattern string
		want    bool
	}{
		{"gcr.io/myproject/myimage", "gcr.io/*", true},
		{"docker.io/library/ubuntu", "docker.io/*", true},
		{"gcr.io/myproject/myimage", "docker.io/*", false},
		{"myproject/myimage", "myproject/*", true},
		{"myproject/myimage", "myproject/myimage", true},
		// Note: "*myimage" pattern matching is handled by HasSuffix check
		// which only works if pattern starts with "*"
		{"myimage", "*myimage", true},
		{"some/myimage", "*myimage", true},
	}

	for _, tt := range tests {
		got := policy.matchesPattern(tt.str, tt.pattern)
		if got != tt.want {
			t.Errorf("matchesPattern(%q, %q) = %v, want %v", tt.str, tt.pattern, got, tt.want)
		}
	}
}
