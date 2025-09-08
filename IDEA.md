# Kaniko Modernization Plan with Built-in Multi-Arch Support

## Current State Analysis

The project is in transition from legacy systems to modern Go 1.24+ practices with a focus on adding secure multi-architecture support without privileged operations.

### ✅ Existing Infrastructure
- **Makefile**: Uses modern `internal/version` package with `.release-version` integration
- **Release Process**: [`hack/release.sh`](hack/release.sh) with GitHub API integration
- **Version Management**: Single source of truth via `.release-version` file
- **Build System**: Functional with modern Go practices
- **Architecture**: Single-binary executor with Dockerfile parsing and image building capabilities

### 🆕 Modern Components Already Added
- [`internal/version`](internal/version/version.go): Modern version package following Go 1.24+ best practices
- [`.release-version`](.release-version): Single source of truth for version (1.24.0)
- **CI/CD**: GitHub Actions removed, needs replacement strategy

## Multi-Architecture Modernization Goals

1. **Built-in Multi-Arch Support**: Add native multi-platform coordination without privileged operations
2. **OCI Compliance**: Full support for OCI Image Index and Docker Manifest List (legacy)
3. **Driver Architecture**: Support for local, Kubernetes, and CI execution modes
4. **Security First**: Maintain unprivileged operation without qemu/binfmt emulation
5. **Registry Compatibility**: Enhanced support for all major registries (Docker Hub, GHCR, ECR, ACR, GCR, Quay)
6. **Observability**: Add structured logging, metrics, and profiling capabilities

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
OCIMode               string          // --oci-mode=[oci|auto]
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

### Phase 4: Observability & Performance (9-12 months)

**Metrics & Logging:**
- Structured logging with `log/slog`
- Prometheus metrics endpoint
- pprof profiling support
- Build timing and performance metrics

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
    // Support cosign signing and SBOM attachment
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
# Build for host architecture only
kaniko --multi-platform=linux/amd64 --driver=local

# Force build (will fail for non-native platforms)
kaniko --multi-platform=linux/arm64 --driver=local --require-native-nodes=false
```

### CI Integration
```bash
# Matrix build per architecture, then aggregate
kaniko --multi-platform=linux/amd64,linux/arm64 --driver=ci \
       --digests-from=/artifacts/digests --publish-index=true
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
5. **Monitoring**: Enhanced observability for early issue detection

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
4. **Q4**: Observability features and performance optimization

This plan ensures Kaniko remains the premier unprivileged container builder while adding comprehensive multi-architecture support for modern CI/CD and Kubernetes environments.