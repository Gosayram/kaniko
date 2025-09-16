# Kaniko Multi-Architecture Building Guide

Kaniko now supports native multi-architecture container building without privileged operations. This guide covers the comprehensive multi-platform capabilities added to Kaniko.

## Overview

Kaniko's multi-architecture support enables building container images for multiple platforms (e.g., `linux/amd64`, `linux/arm64`) in a single build process. Unlike other builders, Kaniko maintains its security-first approach by avoiding privileged operations and qemu emulation.

## Key Features

- **Built-in Multi-Platform Support**: Native coordination across multiple architectures
- **OCI 1.1 Compliance**: Full support for OCI Image Index and Docker Manifest List
- **Multiple Driver Support**: Local, Kubernetes, and CI execution modes
- **Security First**: No privileged operations or qemu/binfmt emulation
- **Registry Compatibility**: Enhanced support for all major registries

## Usage Examples

### Basic Multi-Platform Build

```bash
# Build for multiple platforms with OCI compliance
kaniko \
  --context=dir:///workspace \
  --dockerfile=Dockerfile \
  --destination=ghcr.io/org/app:1.2.3 \
  --multi-platform=linux/amd64,linux/arm64 \
  --driver=local \
  --publish-index=true \
  --oci-mode=oci
```

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
        image: ghcr.io/org/kaniko:latest
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

### CI Integration Mode

```bash
# Matrix build per architecture with digest aggregation
kaniko \
  --multi-platform=linux/amd64,linux/arm64 \
  --driver=ci \
  --digests-from=/artifacts/digests \
  --publish-index=true \
  --oci-mode=oci \
  --compression=zstd
```

## Configuration Options

### Multi-Platform Flags

| Flag | Description | Default |
|------|-------------|---------|
| `--multi-platform` | Comma-separated list of platforms (e.g., `linux/amd64,linux/arm64`) | - |
| `--driver` | Execution driver: `local`, `k8s`, or `ci` | `local` |
| `--publish-index` | Publish OCI Image Index or Docker Manifest List | `false` |
| `--legacy-manifest-list` | Use Docker Manifest List instead of OCI Image Index | `false` |
| `--oci-mode` | OCI compliance mode: `oci`, `docker`, or `auto` | `auto` |
| `--require-native-nodes` | Require native architecture nodes in Kubernetes | `true` |
| `--digests-from` | Path to digest files for CI driver | - |
| `--arch-cache-repo-suffix` | Cache repository suffix pattern (e.g., `-${ARCH}`) | - |
| `--index-annotations` | Key-value annotations for image index | - |

### Driver Comparison

| Driver | Use Case | Requirements |
|--------|----------|-------------|
| **local** | Development and testing | Single architecture (host) |
| **k8s** | Production Kubernetes | Kubernetes cluster with multi-arch nodes |
| **ci** | Existing CI/CD pipelines | Pre-built per-architecture images |

## OCI Compliance

Kaniko provides full OCI 1.1 compliance with proper media types:

### OCI Media Types
- **Image Index**: `application/vnd.oci.image.index.v1+json`
- **Image Manifest**: `application/vnd.oci.image.manifest.v1+json`
- **Layer Compression**: Gzip and Zstd with proper media types

### Docker Compatibility
For legacy compatibility, Kaniko can generate Docker Manifest Lists:
- **Manifest List**: `application/vnd.docker.distribution.manifest.list.v2+json`

## Security Considerations

### No Privileged Operations
- No qemu/binfmt emulation
- No privileged mount operations
- Standard Linux capabilities only

### Registry Authentication
- ServiceAccount-bound secrets
- Workload Identity (GCP)
- Pod Identity (Azure) 
- IAM Roles (AWS)

### Minimum Kubernetes RBAC
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

## Performance Optimization

### Cache Strategies
```bash
# Per-architecture cache repositories
--cache=true \
--cache-repo=registry/cache-repo \
--arch-cache-repo-suffix=-${ARCH}

# Shared cache with architecture awareness
--cache=true \
--cache-repo=registry/shared-cache
```

### Compression Options
```bash
# OCI zstd compression (recommended for OCI compliance)
--compression=zstd

# Traditional gzip compression (Docker compatibility)
--compression=gzip
```

## Troubleshooting

### Common Issues

**Platform Validation Errors**
```bash
# Invalid platform format
Error: invalid platform format: linux (expected os/arch)

# Solution: Use proper platform format
--multi-platform=linux/amd64,linux/arm64
```

**Kubernetes Driver Issues**
```bash
# No nodes available for architecture
Error: no native nodes available for architecture arm64

# Solution: Add arm64 nodes or disable requirement
--require-native-nodes=false
```

**OCI Compliance Issues**
```bash
# Registry doesn't support OCI media types
Error: registry doesn't support OCI media types

# Solution: Use Docker compatibility mode
--oci-mode=docker \
--legacy-manifest-list=true
```

### Debugging

Enable verbose logging for multi-platform operations:
```bash
--verbosity=debug
```

Check platform detection:
```bash
--multi-platform=linux/amd64 --dry-run
```

## Best Practices

1. **Use OCI Mode for New Projects**: `--oci-mode=oci --compression=zstd`
2. **Enable Index Publishing**: `--publish-index=true` for multi-arch images
3. **Use Architecture-Specific Caches**: `--arch-cache-repo-suffix=-${ARCH}`
4. **Validate Platforms Early**: Use `--dry-run` to validate platform support
5. **Monitor Build Performance**: Use `--verbosity=info` for performance insights

## Registry Compatibility

| Registry | OCI Support | Notes |
|----------|-------------|-------|
| **GHCR** | ✅ Full | Recommended for OCI compliance |
| **ECR** | ✅ Full | Requires proper IAM permissions |
| **GCR** | ✅ Full | Google Cloud Container Registry |
| **ACR** | ✅ Full | Azure Container Registry |
| **Docker Hub** | ⚠️ Partial | Prefers Docker format |
| **Quay** | ✅ Full | Red Hat Quay |

## Examples

### Production OCI Configuration
```bash
kaniko --oci-mode=oci \
       --compression=zstd \
       --publish-index=true \
       --index-annotations="org.opencontainers.image.source=https://github.com/org/repo" \
       --index-annotations="org.opencontainers.image.licenses=Apache-2.0"
```

### Legacy Docker Compatibility
```bash
kaniko --oci-mode=docker \
       --compression=gzip \
       --legacy-manifest-list=true
```

### Advanced Multi-Platform with Caching
```bash
kaniko --multi-platform=linux/amd64,linux/arm64 \
       --driver=k8s \
       --cache=true \
       --cache-repo=ghcr.io/org/cache \
       --arch-cache-repo-suffix=-${ARCH} \
       --publish-index=true \
       --oci-mode=oci
```

## Migration Guide

### From Single-Arch to Multi-Arch

1. **Add Platform Specification**
   ```bash
   # Before
   --destination=registry/app:1.0.0
   
   # After  
   --destination=registry/app:1.0.0 \
   --multi-platform=linux/amd64,linux/arm64 \
   --publish-index=true
   ```

2. **Update Cache Strategy**
   ```bash
   # Before
   --cache=true --cache-repo=registry/cache
   
   # After
   --cache=true --cache-repo=registry/cache --arch-cache-repo-suffix=-${ARCH}
   ```

3. **Verify Registry Support**
   ```bash
   # Test OCI compliance
   --oci-mode=oci --dry-run
   
   # Fallback to Docker if needed
   --oci-mode=docker --legacy-manifest-list=true
   ```

## Support Matrix

### Platform Support
| Platform | Status | Notes |
|----------|--------|-------|
| `linux/amd64` | ✅ Supported | Primary platform |
| `linux/arm64` | ✅ Supported | ARM64 architecture |
| `linux/arm/v7` | ⚠️ Experimental | ARMv7 architecture |
| `linux/s390x` | ⚠️ Experimental | IBM Z architecture |
| `linux/ppc64le` | ⚠️ Experimental | PowerPC architecture |

### Kubernetes Versions
| Version | Status |
|---------|--------|
| 1.24+ | ✅ Supported |
| 1.20-1.23 | ⚠️ Limited |
| < 1.20 | ❌ Not supported |

## Contributing

For issues and feature requests related to multi-platform support:

1. Check existing issues on GitHub
2. Provide detailed platform information
3. Include logs with `--verbosity=debug`
4. Test with `--dry-run` first

## References

- [OCI Image Format Specification](https://github.com/opencontainers/image-spec)
- [Docker Manifest List](https://docs.docker.com/registry/spec/manifest-v2-2/)
- [Kaniko Architecture](https://github.com/GoogleContainerTools/kaniko)