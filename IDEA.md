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
- **CI/CD**:  
  - **CD** is based on scripts located in [`hack/`](hack/) (e.g., `hack/release.sh`, `hack/boilerplate.sh`, `hack/gofmt.sh`, etc.).  
  - **CI** checks and tests are implemented using the **Makefile** targets and a dedicated test script (e.g., `hack/test.sh`).  
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

---

## CI/CD Strategy

To replace the removed GitHub Actions, the project adopts a **simple and transparent CI/CD approach**:

- **Continuous Deployment (CD):**  
  Based entirely on scripts from the [`hack/`](hack/) directory:  
  - `hack/release.sh` – release automation with GitHub API integration  
  - `hack/boilerplate.sh` – boilerplate validation  
  - `hack/gofmt.sh`, `hack/linter.sh` – formatting and lint checks  
  - `hack/install_golint.sh` – local tooling setup  

- **Continuous Integration (CI):**  
  Built around the **Makefile** and a dedicated **test script**:  
  - `make lint` – run static checks and linters  
  - `make test` – run unit and integration tests  
  - `make build` – reproducible local builds  
  - `hack/test.sh` – extended integration/E2E test pipeline for CI environments  

This ensures:
- Reproducible results (local = CI consistency)  
- No hidden release mechanism — everything is scripted and visible  
- Easy portability across different CI systems  

---

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
        image: gcr.io/gosayram/kaniko:latest
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

## Suggested Improvements for Enhanced Debugging and Development

### 1. Enhanced Debug Mode Configuration
**Current State**: Basic logging configuration exists but lacks comprehensive debug controls.

**Proposed Enhancement**:
```go
// Add to pkg/config/options.go
type DebugOptions struct {
    EnableFullDebug       bool     `json:"enableFullDebug" yaml:"enableFullDebug"`
    DebugBuildSteps       bool     `json:"debugBuildSteps" yaml:"debugBuildSteps"`
    DebugMultiPlatform    bool     `json:"debugMultiPlatform" yaml:"debugMultiPlatform"`
    DebugOCIOperations    bool     `json:"debugOCIOperations" yaml:"debugOCIOperations"`
    DebugDriverOperations bool     `json:"debugDriverOperations" yaml:"debugDriverOperations"`
    DebugFilesystem       bool     `json:"debugFilesystem" yaml:"debugFilesystem"`
    DebugCacheOperations  bool     `json:"debugCacheOperations" yaml:"debugCacheOperations"`
    DebugRegistry         bool     `json:"debugRegistry" yaml:"debugRegistry"`
    DebugSigning          bool     `json:"debugSigning" yaml:"debugSigning"`
    OutputDebugFiles      bool     `json:"outputDebugFiles" yaml:"outputDebugFiles"`
    DebugLogLevel         string   `json:"debugLogLevel" yaml:"debugLogLevel"` // trace, debug, info
    DebugComponents       []string `json:"debugComponents" yaml:"debugComponents"` // specific components to debug
}

// Add to cmd/executor/cmd/root.go
func addDebugFlags() {
    RootCmd.PersistentFlags().BoolVar(&opts.Debug.EnableFullDebug, "debug-full", false, "Enable comprehensive debug logging for all components")
    RootCmd.PersistentFlags().BoolVar(&opts.Debug.DebugBuildSteps, "debug-build-steps", false, "Debug individual build steps and commands")
    RootCmd.PersistentFlags().BoolVar(&opts.Debug.DebugMultiPlatform, "debug-multi-platform", false, "Debug multi-platform build coordination")
    RootCmd.PersistentFlags().BoolVar(&opts.Debug.DebugOCIOperations, "debug-oci", false, "Debug OCI index and manifest operations")
    RootCmd.PersistentFlags().BoolVar(&opts.Debug.DebugDriverOperations, "debug-drivers", false, "Debug driver operations (local, k8s, ci)")
    RootCmd.PersistentFlags().BoolVar(&opts.Debug.DebugFilesystem, "debug-filesystem", false, "Debug filesystem operations and snapshots")
    RootCmd.PersistentFlags().BoolVar(&opts.Debug.DebugCacheOperations, "debug-cache", false, "Debug cache operations and layer management")
    RootCmd.PersistentFlags().BoolVar(&opts.Debug.DebugRegistry, "debug-registry", false, "Debug registry push/pull operations")
    RootCmd.PersistentFlags().BoolVar(&opts.Debug.DebugSigning, "debug-signing", false, "Debug image signing operations")
    RootCmd.PersistentFlags().BoolVar(&opts.Debug.OutputDebugFiles, "debug-output-files", false, "Output debug information to files")
    RootCmd.PersistentFlags().StringVar(&opts.Debug.DebugLogLevel, "debug-level", "debug", "Debug log level (trace, debug, info)")
    RootCmd.PersistentFlags().StringSliceVar(&opts.Debug.DebugComponents, "debug-components", []string{}, "Specific components to debug (comma-separated)")
}
```

### 2. Comprehensive Debug Output System
**Current State**: Basic logrus logging exists.

**Proposed Enhancement**:
```go
// Add to pkg/debug/debug.go
package debug

import (
    "os"
    "path/filepath"
    "time"
    "fmt"
    
    "github.com/sirupsen/logrus"
)

type DebugManager struct {
    opts        *config.DebugOptions
    logFile     *os.File
    componentLogs map[string]*logrus.Logger
}

func NewDebugManager(opts *config.DebugOptions) (*DebugManager, error) {
    dm := &DebugManager{
        opts:        opts,
        componentLogs: make(map[string]*logrus.Logger),
    }
    
    if opts.OutputDebugFiles {
        if err := dm.initDebugFiles(); err != nil {
            return nil, err
        }
    }
    
    return dm, nil
}

func (dm *DebugManager) initDebugFiles() error {
    debugDir := filepath.Join(config.KanikoDir, "debug")
    if err := os.MkdirAll(debugDir, 0755); err != nil {
        return err
    }
    
    timestamp := time.Now().Format("20060102-150405")
    logFile := filepath.Join(debugDir, "kaniko-debug-"+timestamp+".log")
    
    file, err := os.Create(logFile)
    if err != nil {
        return err
    }
    
    dm.logFile = file
    return nil
}

func (dm *DebugManager) LogComponent(component string, msg string, args ...interface{}) {
    if !dm.shouldLogComponent(component) {
        return
    }
    
    formattedMsg := fmt.Sprintf(msg, args...)
    logEntry := fmt.Sprintf("[%s] [%s] %s", time.Now().Format(time.RFC3339), component, formattedMsg)
    
    if dm.logFile != nil {
        fmt.Fprintln(dm.logFile, logEntry)
    }
    
    logrus.Debugf("[%s] %s", component, formattedMsg)
}

func (dm *DebugManager) shouldLogComponent(component string) bool {
    if dm.opts.EnableFullDebug {
        return true
    }
    
    if len(dm.opts.DebugComponents) == 0 {
        return false
    }
    
    for _, comp := range dm.opts.DebugComponents {
        if comp == component {
            return true
        }
    }
    
    return false
}
```

### 3. Enhanced Multi-Platform Debug Information
**Current State**: Basic logging in coordinator and drivers.

**Proposed Enhancement**:
```go
// Enhance pkg/multiplatform/coordinator.go
func (c *Coordinator) Execute(ctx context.Context) (v1.ImageIndex, error) {
    debug.LogComponent("multiplatform", "Starting multi-platform build with platforms: %v", c.opts.MultiPlatform)
    debug.LogComponent("multiplatform", "Using driver: %s", c.opts.Driver)
    
    // ... existing code ...
    
    // Enhanced debug logging
    debug.LogComponent("multiplatform", "Pre-flight checks completed for platforms: %v", platforms)
    debug.LogComponent("multiplatform", "Platform validation result: %v", err)
    
    if err := c.driver.ValidatePlatforms(platforms); err != nil {
        debug.LogComponent("multiplatform", "Platform validation failed: %v", err)
        return nil, errors.Wrap(err, "platform validation failed")
    }
    
    debug.LogComponent("multiplatform", "Executing builds for platforms: %v", platforms)
    digests, err := c.driver.ExecuteBuilds(ctx, platforms)
    if err != nil {
        debug.LogComponent("multiplatform", "Build execution failed: %v", err)
        return nil, errors.Wrap(err, "failed to execute multi-platform builds")
    }
    
    debug.LogComponent("multiplatform", "Build results: %v", digests)
    c.digests = digests
    
    // ... rest of existing code ...
}
```

### 4. Driver-Specific Debug Enhancements
**Current State**: Basic error logging in drivers.

**Proposed Enhancement**:
```go
// Enhance pkg/multiplatform/k8s.go
func (d *KubernetesDriver) ExecuteBuilds(ctx context.Context, platforms []string) (map[string]string, error) {
    debug.LogComponent("k8s-driver", "Starting Kubernetes builds for platforms: %v", platforms)
    
    for _, platform := range platforms {
        debug.LogComponent("k8s-driver", "Creating job for platform: %s", platform)
        
        job, err := d.createBuildJob(platform)
        if err != nil {
            debug.LogComponent("k8s-driver", "Failed to create job for %s: %v", platform, err)
            return nil, fmt.Errorf("failed to create job for platform %s: %w", platform, err)
        }
        
        debug.LogComponent("k8s-driver", "Created job %s for platform %s", job.Name, platform)
        
        createdJob, err := d.client.BatchV1().Jobs(d.namespace).Create(ctx, job, metav1.CreateOptions{})
        if err != nil {
            debug.LogComponent("k8s-driver", "Failed to create job in cluster: %v", err)
            return nil, fmt.Errorf("failed to create job for platform %s: %w", platform, err)
        }
        
        debug.LogComponent("k8s-driver", "Job created successfully: %s/%s", d.namespace, createdJob.Name)
        
        digest, err := d.waitForJobCompletion(ctx, createdJob.Name, platform)
        if err != nil {
            debug.LogComponent("k8s-driver", "Job completion failed for %s: %v", platform, err)
            return nil, fmt.Errorf("job failed for platform %s: %w", platform, err)
        }
        
        debug.LogComponent("k8s-driver", "Successfully retrieved digest for %s: %s", platform, digest)
        digests[platform] = digest
    }
    
    return digests, nil
}
```

### 5. OCI Operations Debug Enhancement
**Current State**: Basic logging in OCI package.

**Proposed Enhancement**:
```go
// Enhance pkg/oci/index.go
func BuildIndex(manifests map[string]string, opts *config.KanikoOptions) (v1.ImageIndex, error) {
    debug.LogComponent("oci-index", "Building image index with %d manifests", len(manifests))
    debug.LogComponent("oci-index", "OCI Mode: %s", opts.OCIMode)
    debug.LogComponent("oci-index", "Legacy Manifest List: %t", opts.LegacyManifestList)
    
    for platform, digest := range manifests {
        debug.LogComponent("oci-index", "Adding manifest for %s: %s", platform, digest)
    }
    
    // ... existing code ...
    
    if opts.LegacyManifestList {
        debug.LogComponent("oci-index", "Creating Docker Manifest List")
        index, err = buildDockerManifestList(manifests, opts)
    } else {
        debug.LogComponent("oci-index", "Creating OCI Image Index")
        index, err = buildOCIImageIndex(manifests, opts)
    }
    
    if err != nil {
        debug.LogComponent("oci-index", "Failed to build index: %v", err)
        return nil, errors.Wrap(err, "failed to build image index")
    }
    
    debug.LogComponent("oci-index", "Successfully created image index")
    return index, nil
}
```

### 6. Debug Image Build Configuration
**Current State**: Standard build process.

**Proposed Enhancement**:
```dockerfile
# Create debug-specific Dockerfile
FROM gcr.io/gosayram/kaniko:latest as debug-builder

# Install additional debug tools
RUN apt-get update && apt-get install -y \
    strace \
    ltrace \
    tcpdump \
    net-tools \
    curl \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Copy debug scripts and configuration
COPY debug-scripts/ /kaniko/debug-scripts/
COPY debug-config/ /kaniko/debug-config/

# Set debug environment variables
ENV KANIKO_DEBUG=true
ENV KANIKO_DEBUG_LEVEL=trace
ENV KANIKO_DEBUG_OUTPUT_FILES=true

# Create debug entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
echo "=== Kaniko Debug Mode ==="\n\
echo "Debug Level: ${KANIKO_DEBUG_LEVEL}"\n\
echo "Debug Components: ${KANIKO_DEBUG_COMPONENTS}"\n\
echo "Output Debug Files: ${KANIKO_DEBUG_OUTPUT_FILES}"\n\
echo "========================="\n\
exec /kaniko/executor "$@"' > /kaniko/debug-entrypoint && \
    chmod +x /kaniko/debug-entrypoint

# Final debug image
FROM gcr.io/gosayram/kaniko:latest
COPY --from=debug-builder /kaniko/debug-scripts/ /kaniko/debug-scripts/
COPY --from=debug-builder /kaniko/debug-config/ /kaniko/debug-config/
COPY --from=debug-builder /kaniko/debug-entrypoint /kaniko/debug-entrypoint
ENV PATH="/kaniko/debug-scripts:${PATH}"
```

### 7. Debug Script Collection
**Current State**: No dedicated debug scripts.

**Proposed Enhancement**:
Create `debug-scripts/` directory with:
- `analyze-build.sh` - Analyze build performance and bottlenecks
- `trace-filesystem.sh` - Trace filesystem operations during build
- `debug-oci-operations.sh` - Debug OCI index and manifest operations
- `debug-multi-platform.sh` - Debug multi-platform builds
- `collect-debug-info.sh` - Collect comprehensive debug information

### 8. Environment-Based Debug Configuration
**Current State**: Debug flags only via CLI.

**Proposed Enhancement**:
```go
// Add to cmd/executor/main.go
func configureDebugFromEnvironment() {
    // Enable debug mode if environment variable is set
    if os.Getenv("KANIKO_DEBUG") == "true" {
        opts.Debug.EnableFullDebug = true
        opts.Debug.DebugLogLevel = "trace"
        opts.Debug.OutputDebugFiles = true
        logrus.Info("Debug mode enabled via environment variable")
    }
    
    // Set debug level from environment
    if level := os.Getenv("KANIKO_DEBUG_LEVEL"); level != "" {
        opts.Debug.DebugLogLevel = level
    }
    
    // Set debug components from environment
    if components := os.Getenv("KANIKO_DEBUG_COMPONENTS"); components != "" {
        opts.Debug.DebugComponents = strings.Split(components, ",")
    }
}
```

### 9. Debug File Output Structure
**Current State**: No structured debug output.

**Proposed Enhancement**:
Create organized debug output structure:
```
/kaniko/debug/
├── kaniko-debug-<timestamp>.log          # Main debug log
├── build-steps/                          # Individual build step logs
│   ├── step-1.log
│   ├── step-2.log
│   └── ...
├── multi-platform/                       # Multi-platform debug logs
│   ├── coordinator.log
│   ├── local-driver.log
│   ├── k8s-driver.log
│   └── ci-driver.log
├── oci-operations/                       # OCI operation logs
│   ├── index-building.log
│   ├── manifest-handling.log
│   └── push-operations.log
├── filesystem/                           # Filesystem operation logs
│   ├── snapshotting.log
│   ├── layer-creation.log
│   └── file-changes.log
└── registry/                             # Registry operation logs
    ├── pull-operations.log
    ├── push-operations.log
    └── authentication.log
```

### 10. Performance and Memory Debug Enhancement
**Current State**: Basic timing information.

**Proposed Enhancement**:
```go
// Add to pkg/debug/performance.go
package debug

import (
    "runtime"
    "time"
    "sync"
)

type PerformanceTracker struct {
    mu           sync.Mutex
    startTime    time.Time
    metrics      map[string]interface{}
    memoryPoints []MemorySnapshot
}

type MemorySnapshot struct {
    Timestamp time.Time
    Alloc     uint64
    TotalAlloc uint64
    Sys       uint64
    NumGC     uint32
}

func NewPerformanceTracker() *PerformanceTracker {
    return &PerformanceTracker{
        startTime: time.Now(),
        metrics:   make(map[string]interface{}),
    }
}

func (pt *PerformanceTracker) RecordMemorySnapshot() {
    var m runtime.MemStats
    runtime.ReadMemStats(&m)
    
    pt.mu.Lock()
    defer pt.mu.Unlock()
    
    pt.memoryPoints = append(pt.memoryPoints, MemorySnapshot{
        Timestamp: time.Now(),
        Alloc:     m.Alloc,
        TotalAlloc: m.TotalAlloc,
        Sys:       m.Sys,
        NumGC:     m.NumGC,
    })
}

func (pt *PerformanceTracker) RecordMetric(name string, value interface{}) {
    pt.mu.Lock()
    defer pt.mu.Unlock()
    
    pt.metrics[name] = value
}

func (pt *PerformanceTracker) GenerateReport() string {
    pt.mu.Lock()
    defer pt.mu.Unlock()
    
    report := fmt.Sprintf("=== Performance Report ===\n")
    report += fmt.Sprintf("Total execution time: %v\n", time.Since(pt.startTime))
    report += fmt.Sprintf("Final memory allocation: %d bytes\n", pt.memoryPoints[len(pt.memoryPoints)-1].Alloc)
    report += fmt.Sprintf("Total memory allocated: %d bytes\n", pt.memoryPoints[len(pt.memoryPoints)-1].TotalAlloc)
    report += fmt.Sprintf("Number of GC cycles: %d\n", pt.memoryPoints[len(pt.memoryPoints)-1].NumGC)
    
    for name, value := range pt.metrics {
        report += fmt.Sprintf("%s: %v\n", name, value)
    }
    
    return report
}
```

## Implementation Priority for Debugging Improvements

### High Priority (Immediate Benefits)
1. **Enhanced Debug Mode Configuration** - Essential for comprehensive debugging
2. **Debug File Output Structure** - Organized debug information for easier analysis
3. **Environment-Based Debug Configuration** - Convenient debug setup

### Medium Priority (Enhanced Debugging)
4. **Comprehensive Debug Output System** - Centralized debug management
5. **Driver-Specific Debug Enhancements** - Better visibility into driver operations
6. **OCI Operations Debug Enhancement** - Detailed OCI operation logging

### Low Priority (Advanced Debugging)
7. **Enhanced Multi-Platform Debug Information** - Multi-platform build insights
8. **Performance and Memory Debug Enhancement** - Performance analysis tools
9. **Debug Script Collection** - Pre-built debugging utilities

## Usage Examples for Debugging Improvements

### Basic Debug Mode
```bash
# Enable comprehensive debug logging
kaniko --debug-full --destination=registry/app:tag

# Debug specific components
kaniko --debug-components=multiplatform,oci --destination=registry/app:tag

# Debug with file output
kaniko --debug-full --debug-output-files --destination=registry/app:tag
```

### Multi-Platform Debug
```bash
# Debug multi-platform builds
kaniko --multi-platform=linux/amd64,linux/arm64 \
       --driver=k8s \
       --debug-multi-platform \
       --debug-drivers \
       --destination=registry/app:tag
```

### Advanced Debug Configuration
```bash
# Environment-based debug configuration
export KANIKO_DEBUG=true
export KANIKO_DEBUG_LEVEL=trace
export KANIKO_DEBUG_COMPONENTS=filesystem,cache,registry

kaniko --destination=registry/app:tag
```

## Future Development Roadmap

The following enhancements represent opportunities for future development to further improve Kaniko's capabilities:

### 1. Advanced Cache Management
**Current State**: Basic per-architecture cache support exists.

**Proposed Enhancement**:
```go
// Add to pkg/cache/advanced.go
type CacheManager struct {
    opts          *config.KanikoOptions
    cachePolicies map[string]CachePolicy
    gcEnabled     bool
}

type CachePolicy struct {
    TTL           time.Duration
    MaxSize       int64
    EvictionPolicy string // LRU, FIFO, Random
    Compression    string // gzip, zstd, none
}

func (cm *CacheManager) GarbageCollect(ctx context.Context) error {
    // Implement intelligent cache garbage collection
    // Based on TTL, size limits, and usage patterns
}

func (cm *CacheManager) PrefetchLayers(ctx context.Context, platforms []string) error {
    // Prefetch commonly used layers for multi-platform builds
    // Optimize for parallel platform building
}
```

### 2. Intelligent Platform Detection
**Current State**: Manual platform specification required.

**Proposed Enhancement**:
```go
// Add to pkg/platform/detection.go
package platform

import (
    "runtime"
    "github.com/containerd/containerd/platforms"
)

func AutoDetectAvailablePlatforms() ([]string, error) {
    // Detect available build platforms in current environment
    // For Kubernetes: query nodes and their architectures
    // For CI: detect matrix capabilities
    // For local: detect emulation capabilities
}

func SuggestOptimalPlatforms(targets []string) ([]string, error) {
    // Suggest optimal platform combinations based on:
    // - Registry support
    // - Build time constraints
    // - Cache availability
    // - Popularity metrics
}
```

### 3. Advanced Registry Intelligence
**Current State**: Basic registry compatibility.

**Proposed Enhancement**:
```go
// Add to pkg/registry/intelligence.go
type RegistryIntelligence struct {
    client    *http.Client
    cache     *lru.Cache
    knownRegistries map[string]RegistryCapabilities
}

type RegistryCapabilities struct {
    SupportsMultiArch    bool
    SupportsOCI          bool
    SupportsZstd         bool
    RateLimits           RateLimitInfo
    RecommendedSettings   RecommendedConfig
}

func (ri *RegistryIntelligence) DetectCapabilities(registry string) (RegistryCapabilities, error) {
    // Auto-detect registry capabilities through:
    // - HEAD requests to manifest endpoints
    // - API version discovery
    // - Historical performance data
    // - Community knowledge base
}

func (ri *RegistryIntelligence) OptimizePushStrategy(registry string, platforms []string) PushStrategy {
    // Determine optimal push strategy:
    // - Parallel vs sequential pushes
    // - Chunk sizing
    // - Retry configuration
    // - Compression levels
}
```

### 4. Build Optimization Engine
**Current State**: Basic build execution.

**Proposed Enhancement**:
```go
// Add to pkg/optimization/engine.go
type OptimizationEngine struct {
    buildHistory   []BuildRecord
    patternDetector *PatternDetector
    recommendationEngine *RecommendationEngine
}

type BuildRecord struct {
    Duration    time.Duration
    Platform    string
    LayerCount  int
    CacheStats  CacheStatistics
    Performance PerformanceMetrics
}

func (oe *OptimizationEngine) AnalyzeBuildPatterns() BuildRecommendations {
    // Analyze historical build patterns to:
    // - Identify common layer sequences
    // - Detect optimal build order
    // - Suggest cache preheating strategies
    // - Recommend platform build sequencing
}

func (oe *OptimizationEngine) GenerateDockerfileSuggestions(dockerfile string) []Suggestion {
    // Provide Dockerfile optimization suggestions:
    // - Layer consolidation opportunities
    // - Multi-stage build improvements
    // - Platform-specific optimizations
    // - Cache-friendly restructuring
}
```

### 5. Intelligent Retry System
**Current State**: Basic retry logic with exponential backoff.

**Proposed Enhancement**:
```go
// Add to pkg/retry/intelligent.go
type IntelligentRetry struct {
    errorClassifier *ErrorClassifier
    contextAnalyzer *ContextAnalyzer
    strategySelector *StrategySelector
}

type RetryStrategy struct {
    BackoffAlgorithm string // exponential, linear, fibonacci
    MaxAttempts       int
    Jitter            bool
    ContextAware      bool
    Adaptive          bool
}

func (ir *IntelligentRetry) DetermineStrategy(ctx context.Context, operation string, err error) RetryStrategy {
    // Analyze error type and context to determine optimal retry strategy
    // Consider: network errors vs registry errors vs authentication errors
    // Use historical success rates for different strategies
}

func (ir *IntelligentRetry) ShouldRetry(ctx context.Context, attempt int, err error) bool {
    // Intelligent retry decision making:
    // - Transient vs permanent errors
    // - Rate limiting detection
    // - Resource exhaustion detection
    // - Context cancellation awareness
}
```

### 6. Documentation Automation
**Current State**: Manual documentation maintenance.

**Proposed Enhancement**:
```go
// Add to hack/docs-automation.go
package main

import (
    "go/ast"
    "go/parser"
    "go/token"
    "text/template"
)

func GenerateCLIDocs() error {
    // Parse Go source to extract:
    // - All CLI flags and their descriptions
    // - Configuration structs and their fields
    // - Usage examples from comments
    // - Default values and validation rules
}

func UpdateReadmeWithExamples() error {
    // Automatically update README with:
    // - Current flag documentation
    // - Usage examples from integration tests
    // - Performance benchmark results
    // - Compatibility matrices
}

func GenerateMigrationGuides() error {
    // Create migration guides based on:
    // - Version changes in .release-version
    // - Breaking changes from git history
    // - Deprecation notices
    // - Alternative configurations
}
```

## Implementation Priority for Future Development

### High Priority (Significant User Benefits):
- **Advanced Cache Management** - Performance improvements for all builds
- **Intelligent Retry System** - Improved reliability across all operations
- **Advanced Registry Intelligence** - Better user experience across different registries

### Medium Priority (Enhanced Functionality):
- **Intelligent Platform Detection** - Simplifies multi-platform usage
- **Build Optimization Engine** - For performance-critical environments

### Maintenance & Documentation:
- **Documentation Automation** - Maintains documentation quality and consistency

These enhancements would build upon the excellent foundation already established and provide additional value for both casual users and enterprise deployments, focusing on performance, reliability, and user experience improvements.