# Kaniko Multi-Architecture Build Guide

This document provides comprehensive guidance on using Kaniko's multi-architecture build capabilities.

## Overview

Kaniko now supports building container images for multiple architectures without requiring privileged operations. This is achieved through three different drivers:

1. **Local Driver**: Single-architecture builds on the host machine
2. **Kubernetes Driver**: Multi-architecture builds using Kubernetes Jobs
3. **CI Driver**: Aggregation of existing per-architecture builds from CI systems

## Quick Start Examples

### Local Development (Single Architecture)
```bash
# Build for host architecture only
kaniko --multi-platform=linux/amd64 --driver=local \
       --destination=ghcr.io/org/app:1.0.0

# Force build for non-native architecture (will fail if not supported)
kaniko --multi-platform=linux/arm64 --driver=local --require-native-nodes=false
```

### Kubernetes Multi-Arch Build
```yaml
# Kubernetes Job example
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

### CI Integration
```bash
# Matrix build per architecture, then aggregate
kaniko --multi-platform=linux/amd64,linux/arm64 --driver=ci \
       --digests-from=/artifacts/digests --publish-index=true
```

## Configuration Flags

### Multi-Platform Options
- `--multi-platform`: Comma-separated list of platforms (e.g., `linux/amd64,linux/arm64`)
- `--driver`: Execution driver (`local`, `k8s`, or `ci`)
- `--publish-index`: Publish OCI Image Index after builds complete
- `--legacy-manifest-list`: Create Docker Manifest List for backward compatibility
- `--index-annotations`: Annotations for the image index (key=value pairs)
- `--arch-cache-repo-suffix`: Suffix pattern for architecture-specific cache repositories

### Driver-Specific Options

#### Local Driver
- `--require-native-nodes`: Fail if non-native architecture is requested (default: true)

#### Kubernetes Driver
- `--require-native-nodes`: Require native architecture nodes in cluster (default: true)

#### CI Driver
- `--digests-from`: Path to directory containing digest files from per-arch builds

## Driver Details

### Local Driver
The local driver is designed for development and testing. It:
- Only builds for the host architecture
- Provides fast feedback during development
- Can be forced to attempt non-native builds (may fail)

### Kubernetes Driver
The Kubernetes driver orchestrates builds across a cluster:
- Creates Jobs with proper `nodeSelector` for each architecture
- Requires RBAC permissions to create/list/watch Jobs and Pods
- Supports registry authentication via ServiceAccount secrets
- Provides proper cleanup of created resources

#### Required RBAC Permissions
```yaml
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

### CI Driver
The CI driver aggregates existing builds:
- Reads digest files from a specified directory
- Expects files named `<platform>.digest` (e.g., `linux-amd64.digest`)
- Each file should contain exactly one line with the image digest
- Creates OCI Image Index from collected digests

#### Digest File Format
```
# Directory structure
/artifacts/digests/
  linux-amd64.digest
  linux-arm64.digest

# File content example (single line)
sha256:abc123def456...
```

## Cache Management

Kaniko supports architecture-specific cache repositories:
```bash
# Use architecture-specific cache
kaniko --multi-platform=linux/amd64,linux/arm64 \
       --cache=true --cache-repo=ghcr.io/org/app-cache \
       --arch-cache-repo-suffix=-${ARCH}

# Results in cache repositories:
# - ghcr.io/org/app-cache-amd64
# - ghcr.io/org/app-cache-arm64
```

## OCI Compliance

Kaniko supports both OCI Image Index and Docker Manifest List formats:

- **OCI Image Index** (`application/vnd.oci.image.index.v1+json`): Modern standard
- **Docker Manifest List** (`application/vnd.docker.distribution.manifest.list.v2+json`): Legacy compatibility

Use `--oci-mode` to control the behavior:
- `auto`: Automatic detection based on registry capabilities
- `oci`: Force OCI Image Index format
- `docker`: Force Docker Manifest List format

## Registry Compatibility

Kaniko's multi-arch support works with all major registries:

- **Docker Hub**: Full support for both formats
- **GHCR** (GitHub Container Registry): Prefers OCI format
- **ECR** (AWS): Supports both formats
- **ACR** (Azure): Supports both formats  
- **GCR** (Google Cloud): Supports both formats
- **Quay**: Prefers OCI format

## Best Practices

### 1. Platform Selection
```bash
# Good: Specific platforms
--multi-platform=linux/amd64,linux/arm64

# Avoid: Overly broad platform lists
--multi-platform=linux/amd64,linux/arm64,linux/arm/v7,linux/s390x
```

### 2. Cache Strategy
```bash
# Use architecture-specific cache for better performance
--arch-cache-repo-suffix=-${ARCH}

# Set appropriate cache TTL for multi-arch builds
--cache-ttl=168h  # 1 week
```

### 3. Resource Management
```bash
# Set appropriate resource limits for Kubernetes driver
# (Configured via Kubernetes resource limits, not Kaniko flags)
```

### 4. Security
```bash
# Use minimal RBAC permissions for Kubernetes driver
# Enable --require-native-nodes for production builds
```

## Troubleshooting

### Common Issues

**Platform validation fails:**
```bash
# Check platform format
Error: invalid platform format: linux-amd64 (expected os/arch)
Fix: Use --multi-platform=linux/amd64
```

**Kubernetes driver fails:**
```bash
# Check RBAC permissions and node availability
Error: failed to create job: permissions error
Fix: Ensure proper RBAC roles are configured
```

**CI driver missing digests:**
```bash
# Check digest file format and location
Error: failed to read digest file
Fix: Ensure digest files exist and contain valid SHA256 digests
```

### Debugging Tips

```bash
# Enable verbose logging
--verbosity=debug

# Check platform detection
--multi-platform=linux/amd64 --no-push

# Test without publishing index
--publish-index=false
```

## Migration Guide

### From Single-Arch to Multi-Arch

1. **Start with local driver:**
   ```bash
   kaniko --multi-platform=linux/amd64 --driver=local
   ```

2. **Add additional platforms:**
   ```bash
   kaniko --multi-platform=linux/amd64,linux/arm64 --driver=local
   ```

3. **Move to Kubernetes for production:**
   ```bash
   kaniko --multi-platform=linux/amd64,linux/arm64 --driver=k8s
   ```

### From Other Tools

If migrating from `docker buildx` or other multi-arch tools:

1. **Remove privileged operations**: Kaniko doesn't require `--privileged` or `binfmt_misc`
2. **Update build commands**: Replace buildx commands with Kaniko flags
3. **Verify registry compatibility**: Test with your target registry

## Performance Considerations

- **Local driver**: Fastest for development, limited to host architecture
- **Kubernetes driver**: Parallel builds across nodes, overhead from Job creation
- **CI driver**: Minimal overhead, relies on existing CI infrastructure

## Limitations

- **Kubernetes driver**: Requires Kubernetes cluster with multi-arch nodes
- **Local driver**: Limited to host architecture without emulation
- **Registry support**: Some older registries may have limited OCI support

## Support Matrix

| Feature | Local Driver | Kubernetes Driver | CI Driver |
|---------|-------------|------------------|-----------|
| Multi-platform | ❌ (Single arch) | ✅ | ✅ (Aggregation) |
| No privileges | ✅ | ✅ | ✅ |
| Parallel builds | ❌ | ✅ | N/A |
| Production ready | ⚠️ (Dev only) | ✅ | ✅ |

## Getting Help

- Check the [Kaniko GitHub Issues](https://github.com/GoogleContainerTools/kaniko/issues)
- Join the [Kaniko Slack channel](https://kubernetes.slack.com/messages/kaniko)
- Review [additional examples](https://github.com/GoogleContainerTools/kaniko/tree/main/examples)

## Contributing

We welcome contributions to improve multi-arch support! Areas of interest:

- Enhanced Kubernetes driver features
- Additional registry compatibility fixes
- Performance optimizations
- Testing infrastructure improvements