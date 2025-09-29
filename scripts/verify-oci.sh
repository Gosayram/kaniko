#!/bin/bash

# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

# OCI Verification Script
# This script validates OCI Image Index artifacts using oras and crane tools

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
REGISTRY="${REGISTRY:-localhost:5000}"
IMAGE_REPO="${IMAGE_REPO:-$REGISTRY/kaniko-test}"
OCI_TEST_IMAGE="${OCI_TEST_IMAGE:-$IMAGE_REPO/oci-validation-test:latest}"
OCI_MULTIARCH_IMAGE="${OCI_MULTIARCH_IMAGE:-$IMAGE_REPO/oci-multiarch-validation:latest}"

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if required tools are available
check_requirements() {
    log_info "Checking requirements..."
    
    local missing_tools=()
    
    if ! command -v crane &> /dev/null; then
        missing_tools+=("crane")
    fi
    
    if ! command -v oras &> /dev/null; then
        missing_tools+=("oras")
    fi
    
    if ! command -v jq &> /dev/null; then
        missing_tools+=("jq")
    fi
    
    if [ ${#missing_tools[@]} -ne 0 ]; then
        log_error "Missing required tools: ${missing_tools[*]}"
        log_info "Install them with:"
        log_info "  - crane: go install github.com/google/go-containerregistry/cmd/crane@latest"
        log_info "  - oras: https://oras.land/cli/"
        log_info "  - jq: brew install jq (or equivalent for your OS)"
        exit 1
    fi
    
    log_info "All required tools are available"
}

# Start local registry if needed
start_local_registry() {
    if [[ "$REGISTRY" == "localhost:5000" ]]; then
        if ! docker ps | grep -q "registry.*5000"; then
            log_info "Starting local registry on port 5000"
            docker run --name registry -d -p 5000:5000 registry:2
            sleep 2
        fi
    fi
}

# Build test images
build_test_images() {
    log_info "Building test images..."
    
    # Build single-platform test image
    docker build -t "$OCI_TEST_IMAGE" -f - <<EOF
FROM alpine:3.18
RUN echo "OCI validation test" > /test.txt
LABEL org.opencontainers.image.title="OCI Validation Test"
LABEL org.opencontainers.image.description="Test image for OCI compliance validation"
EOF
    
    # Push to registry
    docker push "$OCI_TEST_IMAGE"
    
    # Build multi-platform test image
    log_info "Building multi-platform test image..."
    
    # Create a temporary directory for multi-platform build
    local temp_dir=$(mktemp -d)
    cd "$temp_dir"
    
    # Create Dockerfile
    cat > Dockerfile <<EOF
FROM alpine:3.18
RUN echo "Multi-platform OCI validation test" > /test.txt
LABEL org.opencontainers.image.title="Multi-Platform OCI Validation Test"
LABEL org.opencontainers.image.description="Multi-platform test image for OCI compliance validation"
EOF
    
    # Build for multiple platforms
    platforms=("linux/amd64" "linux/arm64")
    
    for platform in "${platforms[@]}"; do
        platform_name=$(echo "$platform" | tr '/' '-')
        docker buildx build --platform "$platform" -t "$OCI_MULTIARCH_IMAGE-$platform_name" -o type=docker,dest=./output-$platform_name .
    done
    
    cd "$PROJECT_ROOT"
    rm -rf "$temp_dir"
    
    log_info "Test images built successfully"
}

# Validate single-platform image
validate_single_platform() {
    local image="$1"
    log_info "Validating single-platform image: $image"
    
    # Check if image exists
    if ! crane manifest "$image" &> /dev/null; then
        log_error "Image $image does not exist or is not accessible"
        return 1
    fi
    
    # Get manifest
    local manifest=$(crane manifest "$image")
    
    # Validate manifest structure
    if ! echo "$manifest" | jq -e '.schemaVersion' &> /dev/null; then
        log_error "Invalid manifest schema for $image"
        return 1
    fi
    
    # Check if it's a single-platform manifest
    local media_type=$(echo "$manifest" | jq -r '.mediaType // empty')
    if [[ "$media_type" != "application/vnd.docker.distribution.manifest.v2+json" ]]; then
        log_warn "Unexpected media type for single-platform image: $media_type"
    fi
    
    # Validate layers
    local layers=$(echo "$manifest" | jq -r '.layers[] | .mediaType')
    for layer in $layers; do
        if [[ "$layer" != application/vnd.docker.image.rootfs.diff.tar.gzip* ]]; then
            log_warn "Unexpected layer media type: $layer"
        fi
    done
    
    log_info "Single-platform image validation passed: $image"
}

# Validate multi-platform image index
validate_multi_platform_index() {
    local index="$1"
    log_info "Validating multi-platform image index: $index"
    
    # Check if index exists
    if ! crane manifest "$index" &> /dev/null; then
        log_error "Image index $index does not exist or is not accessible"
        return 1
    fi
    
    # Get index manifest
    local manifest=$(crane manifest "$index")
    
    # Validate index structure
    if ! echo "$manifest" | jq -e '.schemaVersion' &> /dev/null; then
        log_error "Invalid index schema for $index"
        return 1
    fi
    
    # Check if it's an index (OCI 1.0+)
    local media_type=$(echo "$manifest" | jq -r '.mediaType // empty')
    if [[ "$media_type" != application/vnd.oci.image.index.v1+json ]]; then
        log_error "Expected OCI image index, got: $media_type"
        return 1
    fi
    
    # Validate manifests in index
    local manifests_count=$(echo "$manifest" | jq '.manifests | length')
    log_info "Found $manifests_count manifests in index"
    
    if [[ $manifests_count -eq 0 ]]; then
        log_error "No manifests found in index"
        return 1
    fi
    
    # Check each manifest
    local platforms_found=()
    for i in $(seq 0 $((manifests_count - 1))); do
        local manifest_digest=$(echo "$manifest" | jq -r ".manifests[$i].digest")
        local platform=$(echo "$manifest" | jq -r ".manifests[$i].platform // empty")
        
        log_info "  Manifest $((i + 1)): digest=$manifest_digest, platform=$platform"
        
        # Validate platform
        if [[ -n "$platform" ]]; then
            local os=$(echo "$platform" | jq -r '.os // empty')
            local arch=$(echo "$platform" | jq -r '.architecture // empty')
            
            if [[ -z "$os" || -z "$arch" ]]; then
                log_warn "Manifest $((i + 1)) has incomplete platform information"
            else
                platforms_found+=("$os/$arch")
            fi
        else
            log_warn "Manifest $((i + 1)) missing platform information"
        fi
        
        # Validate that we can pull the manifest
        if ! crane manifest "$index@$manifest_digest" &> /dev/null; then
            log_error "Cannot pull manifest $manifest_digest from index"
            return 1
        fi
    done
    
    # Check for duplicate platforms
    local duplicates=$(printf "%s\n" "${platforms_found[@]}" | sort | uniq -d)
    if [[ -n "$duplicates" ]]; then
        log_warn "Duplicate platforms found in index: $duplicates"
    fi
    
    log_info "Multi-platform index validation passed: $index"
}

# Validate with oras
validate_with_oras() {
    local image="$1"
    log_info "Validating with oras: $image"
    
    # Check if oras can pull the image
    if ! oras pull "$image" --output-dir /tmp/oras-validation &> /dev/null; then
        log_error "oras failed to pull image: $image"
        return 1
    fi
    
    # Check if we got the expected files
    if [[ ! -f "/tmp/oras-validation/manifest.json" ]]; then
        log_error "oras did not produce manifest.json"
        return 1
    fi
    
    if [[ ! -f "/tmp/oras-validation/config.json" ]]; then
        log_error "oras did not produce config.json"
        return 1
    fi
    
    # Validate manifest with oras
    local manifest=$(cat /tmp/oras-validation/manifest.json)
    if ! echo "$manifest" | jq -e '.schemaVersion' &> /dev/null; then
        log_error "Invalid manifest in oras validation"
        return 1
    fi
    
    log_info "oras validation passed: $image"
    rm -rf /tmp/oras-validation
}

# Run comprehensive validation
run_comprehensive_validation() {
    log_info "Running comprehensive OCI validation..."
    
    local validation_passed=true
    
    # Validate single-platform image
    if ! validate_single_platform "$OCI_TEST_IMAGE"; then
        validation_passed=false
    fi
    
    # Validate multi-platform index
    if ! validate_multi_platform_index "$OCI_MULTIARCH_IMAGE"; then
        validation_passed=false
    fi
    
    # Validate with oras
    if ! validate_with_oras "$OCI_TEST_IMAGE"; then
        validation_passed=false
    fi
    
    if ! validate_with_oras "$OCI_MULTIARCH_IMAGE"; then
        validation_passed=false
    fi
    
    if [[ "$validation_passed" == true ]]; then
        log_info "✅ All OCI validations passed!"
        return 0
    else
        log_error "❌ Some OCI validations failed!"
        return 1
    fi
}

# Generate validation report
generate_report() {
    local report_file="oci-validation-report.json"
    log_info "Generating validation report: $report_file"
    
    local report=$(cat <<EOF
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "registry": "$REGISTRY",
  "images": {
    "single_platform": {
      "image": "$OCI_TEST_IMAGE",
      "validated": $(validate_single_platform "$OCI_TEST_IMAGE" &> /dev/null && echo "true" || echo "false")
    },
    "multi_platform": {
      "image": "$OCI_MULTIARCH_IMAGE",
      "validated": $(validate_multi_platform_index "$OCI_MULTIARCH_IMAGE" &> /dev/null && echo "true" || echo "false")
    }
  },
  "tools": {
    "crane": "$(crane version 2>/dev/null || echo 'unknown')",
    "oras": "$(oras version 2>/dev/null || echo 'unknown')",
    "jq": "$(jq --version 2>/dev/null || echo 'unknown')"
  }
}
EOF
)
    
    echo "$report" | jq '.' > "$report_file"
    log_info "Validation report saved to: $report_file"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."
    
    # Clean up test images
    docker rmi "$OCI_TEST_IMAGE" "$OCI_MULTIARCH_IMAGE" 2>/dev/null || true
    
    # Clean up local registry
    if [[ "$REGISTRY" == "localhost:5000" ]]; then
        docker stop registry 2>/dev/null || true
        docker rm registry 2>/dev/null || true
    fi
    
    log_info "Cleanup completed"
}

# Main function
main() {
    log_info "Starting OCI validation..."
    
    # Set up trap for cleanup
    trap cleanup EXIT
    
    # Check requirements
    check_requirements
    
    # Start local registry if needed
    start_local_registry
    
    # Build test images
    build_test_images
    
    # Run validation
    if run_comprehensive_validation; then
        log_info "OCI validation completed successfully!"
        generate_report
        exit 0
    else
        log_error "OCI validation failed!"
        exit 1
    fi
}

# Run main function
main "$@"