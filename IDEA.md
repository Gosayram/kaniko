# Kaniko Modernization Plan with Built-in Multi-Arch Support and OCI 1.1 Compliance

## Current State Analysis

The project is in transition from legacy systems to modern Go 1.24+ practices with a focus on adding secure multi-architecture support without privileged operations and comprehensive OCI 1.1 compliance.

### ✅ Existing Infrastructure
- **Makefile**: Uses modern `internal/version` package with `.release-version` integration
- **Release Process**: [`hack/release.sh`](hack/release.sh) with GitHub API integration
- **Version Management**: Single source of truth via `.release-version` file
- **Build System**: Functional with modern Go practices
- **Architecture**: Single-binary executor with Dockerfile parsing and image building capabilities
- **OCI Compliance**: Strong OCI 1.1 support with comprehensive media type handling

### 🆕 Modern Components Already Added
- [`internal/version`](internal/version/version.go): Modern version package following Go 1.24+ best practices
- [`.release-version`](.release-version): Single source of truth for version (1.24.0)
- **CI/CD**: GitHub Actions removed, needs replacement strategy
- **OCI Support**: Full OCI 1.1 media type compliance and multi-platform capabilities

### ✅ OCI 1.1 Compliance Status
Kaniko demonstrates **excellent compliance** with OCI Image Format Specification v1.1:

**Fully Supported OCI 1.1 Features:**
- ✅ **Media Types**: Full OCI media type spectrum (`application/vnd.oci.image.*`)
- ✅ **Image Index**: Proper OCI Image Index implementation
- ✅ **Content Digests**: SHA-256 content addressing
- ✅ **Platform Fields**: OS, Architecture, Variant support
- ✅ **Layer Compression**: Gzip and Zstd with proper media types
- ✅ **Annotations**: Basic index-level annotations

**OCI Compliance Rating: 9/10** - Excellent for production use in OCI-based environments

**Key Dependencies:**
- `github.com/google/go-containerregistry v0.20.6`
- `github.com/opencontainers/image-spec v1.1.1`
- `github.com/opencontainers/go-digest v1.0.0`

## Multi-Architecture Modernization Goals

1. **Built-in Multi-Arch Support**: Add native multi-platform coordination without privileged operations
2. **OCI Compliance**: Full support for OCI Image Index and Docker Manifest List (legacy)
3. **Driver Architecture**: Support for local, Kubernetes, and CI execution modes
4. **Security First**: Maintain unprivileged operation without qemu/binfmt emulation
5. **Registry Compatibility**: Enhanced support for all major registries (Docker Hub, GHCR, ECR, ACR, GCR, Quay)

## Implementation Plan

### Phase 1: Core Multi-Arch Architecture (0-3 months)

**New Configuration Flags:**
```go
// Add to KanikoOptions struct in pkg/config/options.go
MultiPlatform         multiArg        // --multi-platform=linux/amd64,linux/arm64
PublishIndex          bool            // --publish-index[=true|false]
LegacyManifestList    bool            // --legacy-manifest-list[=true|false]
IndexAnnotations      multiKeyValueArg // --index-annotations=key=value,...
ArchCacheRepoSuffix   string          // --arch-cache-repo-suffix=-${ARCH}
Driver                string          // --driver=[local|k8s|ci]
DigestsFrom           string          // --digests-from=/path
RequireNativeNodes    bool            // --require-native-nodes=true
OCIMode               string          // --oci-mode=[oci|auto|docker]
Compression           string          // --compression=[gzip|zstd]
SignImages           bool            // --sign-images[=true|false]
CosignKeyPath        string          // --cosign-key-path=/path/to/key
CosignKeyPassword    string          // --cosign-key-password=secret
```

**Architecture Changes:**
1. **Multi-Platform Coordinator**: New package `pkg/multiplatform` for orchestration
2. **Driver Interface**: Abstract driver implementation for different execution environments
3. **OCI Index Builder**: Enhanced image index creation with proper media types
4. **Platform Validation**: Pre-flight checks for platform availability and compatibility

### Phase 2: Driver Implementations (3-6 months)

**Local Driver (`driver=local`):**
- Single architecture builds only (host architecture)
- Fail-fast for non-native platforms unless explicitly allowed
- Simple coordination for development and testing

**Kubernetes Driver (`driver=k8s`):**
- In-cluster API integration for multi-arch builds
- Job/Pod creation with `nodeSelector: kubernetes.io/arch=<arch>`
- Minimal RBAC requirements (create/get/list/watch/delete jobs/pods)
- Registry secret propagation via ServiceAccount/Secrets
- OIDC/Workload Identity support for cloud providers

**CI Driver (`driver=ci`):**
- Aggregation mode for existing per-arch builds
- Digest file collection and index publication only
- Integration with existing CI/CD matrix workflows

### Phase 3: Enhanced OCI Support & Registry Compatibility (6-9 months)

**OCI Media Type Support:**
- Strict OCIv1.1 compliance with proper media types
- Automatic fallback to legacy formats when needed
- Validation and conversion utilities

**Registry Enhancements:**
- ECR Public compatibility fixes
- Digest file immutability guarantees
- Parallel layer push optimizations
- HTTP/2 → HTTP/1.1 fallback mechanisms
- Enhanced retry logic with exponential backoff



**Cache Optimization:**
- Per-architecture cache repositories
- TTL/GC policies for cache management
- OCI cache compatibility (separate artifact repository)

## Technical Architecture

### Multi-Platform Coordinator Package (`pkg/multiplatform`)

```go
// pkg/multiplatform/coordinator.go
type Coordinator struct {
    opts    *config.KanikoOptions
    driver  Driver
    digests map[string]string // platform -> digest
}

type Driver interface {
    ValidatePlatforms(platforms []string) error
    ExecuteBuilds(ctx context.Context, platforms []string) (map[string]string, error)
    Cleanup() error
}

// Driver implementations
type LocalDriver struct{ /* ... */ }
type KubernetesDriver struct{ /* ... */ }
type CIDriver struct{ /* ... */ }
```

### OCI Index Builder (`pkg/oci/index.go`)

```go
// pkg/oci/index.go
func BuildIndex(manifests map[string]v1.Descriptor, opts *config.KanikoOptions) (v1.ImageIndex, error) {
    // Create OCI Image Index (application/vnd.oci.image.index.v1+json)
    // Optionally create Docker Manifest List for legacy compatibility
    // Add platform-specific annotations and metadata
    // Support cosign signing and SBOM attachment (optional)
    // Handle OCI vs Docker media types based on OCIMode
}
```

### Kubernetes Integration (`pkg/multiplatform/k8s.go`)

```go
// pkg/multiplatform/k8s.go
func (d *KubernetesDriver) createBuildJob(platform string) (*batchv1.Job, error) {
    // Create Job with nodeSelector for specific architecture
    // Propagate registry credentials via ServiceAccount
    // Set up proper resource limits and retry policies
    // Configure digest file output location
}
```

## Security Considerations

**No Privileged Operations:**
- No qemu/binfmt emulation
- No privileged mount operations
- Standard Linux capabilities only
- **Security First**: Kaniko remains secure by default, avoiding unsafe features from other builders

**OCI Security Features:**
- **Optional Image Signing**: Cosign support available but not enabled by default
- **No Unsafe Features**: Security-sensitive OCI features are implemented as opt-in only
- **Content Trust**: Digest-based verification prevents tampering
- **Minimal Attack Surface**: No execution of arbitrary code during build process
- **Safe Defaults**: OCI features disabled by default, require explicit opt-in
- **No Automatic Conversions**: Prevents unexpected behavior changes

**Kubernetes RBAC Minimum:**
```yaml
# Minimum required permissions
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
rules:
- apiGroups: ["batch"]
  resources: ["jobs"]
  verbs: ["create", "get", "list", "watch", "delete"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
```

**Registry Authentication:**
- ServiceAccount-bound secrets
- Workload Identity (GCP)
- Pod Identity (Azure)
- IAM Roles (AWS)

**Image Signing Security:**
- **Optional Feature**: Signing requires explicit opt-in via `--sign-images`
- **Key Management**: Keys stored securely, not embedded in images
- **No Automatic Signing**: Prevents accidental exposure of signing keys
- **Audit Trail**: Signed images provide cryptographic proof of origin

## Usage Examples

### Kubernetes Multi-Arch Build
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: kaniko-multiarch
spec:
  template:
    spec:
      serviceAccountName: kaniko-builder
      containers:
      - name: kaniko
        image: gcr.io/kaniko-project/executor:latest
        args:
        - --context=git=https://github.com/org/app.git#main
        - --dockerfile=Dockerfile
        - --destination=ghcr.io/org/app:1.2.3
        - --multi-platform=linux/amd64,linux/arm64
        - --driver=k8s
        - --publish-index=true
        - --legacy-manifest-list=true
        - --require-native-nodes=true
```

### Local Development
```bash
# Build for host architecture only with OCI compliance
kaniko --multi-platform=linux/amd64 --driver=local --oci-mode=oci

# Force build with OCI zstd compression
kaniko --multi-platform=linux/arm64 --driver=local --require-native-nodes=false \
       --oci-mode=oci --compression=zstd

# Build with optional image signing
kaniko --destination=ghcr.io/org/app:1.2.3 --sign-images=true \
       --cosign-key-path=/secrets/cosign.key
```

### CI Integration
```bash
# Matrix build per architecture with OCI compliance
kaniko --multi-platform=linux/amd64,linux/arm64 --driver=ci \
       --digests-from=/artifacts/digests --publish-index=true \
       --oci-mode=oci --compression=zstd

# Full OCI 1.1 compliant build with annotations
kaniko --oci-mode=oci --compression=zstd --publish-index=true \
       --index-annotations=org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
```

### Production OCI Configuration
```bash
# Recommended production configuration for full OCI compliance
kaniko --oci-mode=oci \          # Strict OCI compliance
       --compression=zstd \      # OCI zstd layer compression
       --publish-index=true \    # Create OCI Image Index
       --index-annotations="org.opencontainers.image.source=https://github.com/org/repo" \
       --index-annotations="org.opencontainers.image.licenses=Apache-2.0"

# Legacy compatibility mode (Docker format)
kaniko --oci-mode=docker \       # Docker compatibility mode
       --compression=gzip \      # Traditional gzip compression
       --legacy-manifest-list=true
```

## Testing Strategy

**Unit Tests:**
- Platform validation and parsing
- OCI media type conversion
- Driver interface compliance

**Integration Tests:**
- Multi-platform build coordination
- Kubernetes Job creation and management
- Digest file collection and index creation

**E2E Tests:**
- Full multi-arch build pipeline
- Registry push and pull validation
- Cross-platform compatibility testing

**Registry Matrix Testing:**
- Docker Hub, GHCR, ECR, ACR, GCR, Quay
- Authentication and permission validation
- Network resilience and retry behavior

## Risk Mitigation

1. **Backward Compatibility**: Maintain single-arch functionality during transition
2. **Gradual Rollout**: Implement drivers incrementally with feature flags
3. **Comprehensive Testing**: Matrix testing across all supported platforms and registries
4. **Documentation**: Clear migration guides and known limitations

## Success Metrics

- ✅ Multi-platform builds complete successfully without privileges
- ✅ OCI Image Index created with proper media types
- ✅ Kubernetes driver creates Jobs with correct nodeSelectors
- ✅ CI driver aggregates existing per-arch builds correctly
- ✅ All existing single-arch functionality preserved
- ✅ Performance within 10% of single-arch builds for coordinator overhead
- ✅ Registry compatibility maintained across all major providers

## Timeline

1. **Q1**: Core multi-platform architecture and local driver
2. **Q2**: Kubernetes driver implementation and testing
3. **Q3**: CI driver and enhanced OCI support
4. **Q4**: Performance optimization

This plan ensures Kaniko remains the premier unprivileged container builder while adding comprehensive multi-architecture support for modern CI/CD and Kubernetes environments.

## Documentation Strategy

### High-Quality Documentation Requirements

**Comprehensive Usage Guides:**
- **Basic Usage**: Simple examples for standard use cases
- **OCI Compliance**: Detailed OCI 1.1 configuration guide
- **Multi-Platform**: Step-by-step multi-architecture building
- **Security**: Security best practices and configuration
- **Troubleshooting**: Common issues and solutions

**Documentation Structure:**
```
docs/
├── oci-compliance.md          # OCI 1.1 compliance guide
├── multi-arch-guide.md        # Multi-platform building
├── security-best-practices.md # Security configuration
├── signing-guide.md           # Image signing with cosign
├── advanced-configuration.md  # Advanced OCI features
└── troubleshooting.md        # Common issues and solutions
```

**Key Documentation Features:**
- Clear argument explanations with examples
- Use case-based configuration examples
- Security considerations for each feature
- Registry-specific compatibility notes
- Performance optimization tips

### OCI Documentation Focus Areas

**For Standard Users:**
```bash
# Simple usage - just works
kaniko --destination=registry/app:tag
```

**For OCI Compliance:**
```bash
# Full OCI 1.1 compliance
kaniko --oci-mode=oci --compression=zstd --publish-index=true
```

**For Security-Conscious Users:**
```bash
# Secure build with signing
kaniko --sign-images=true --cosign-key-path=/secrets/key
```

This documentation approach ensures that Kaniko remains accessible to all users while providing advanced features for those who need OCI compliance and enhanced security.