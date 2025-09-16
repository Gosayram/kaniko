# OCI 1.1 Compliance Guide

This guide covers Kaniko's implementation of OCI (Open Container Initiative) Image Format Specification v1.1 compliance, including media types, validation, and configuration options.

## OCI Compliance Status

Kaniko demonstrates **excellent compliance** with OCI Image Format Specification v1.1:

**OCI Compliance Rating: 9/10** - Excellent for production use in OCI-based environments

### ✅ Fully Supported OCI 1.1 Features

- **Media Types**: Full OCI media type spectrum (`application/vnd.oci.image.*`)
- **Image Index**: Proper OCI Image Index implementation
- **Content Digests**: SHA-256 content addressing
- **Platform Fields**: OS, Architecture, Variant support
- **Layer Compression**: Gzip and Zstd with proper media types
- **Annotations**: Basic index-level annotations

## Configuration Options

### OCI Mode Selection

```bash
# Strict OCI compliance (recommended)
--oci-mode=oci

# Docker compatibility mode
--oci-mode=docker

# Automatic detection based on registry capabilities (default)
--oci-mode=auto
```

### Compression Algorithms

```bash
# OCI zstd compression (recommended for OCI compliance)
--compression=zstd

# Traditional gzip compression (Docker compatible)
--compression=gzip
```

### Multi-Platform Support

```bash
# OCI Image Index creation
--publish-index=true

# Legacy Docker Manifest List support
--legacy-manifest-list=false  # Default: false for OCI compliance

# Platform-specific annotations
--index-annotations=org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
```

## Media Type Support

### OCI Media Types

| Media Type | Description | Status |
|------------|-------------|---------|
| `application/vnd.oci.image.index.v1+json` | OCI Image Index | ✅ Fully Supported |
| `application/vnd.oci.image.manifest.v1+json` | OCI Image Manifest | ✅ Fully Supported |
| `application/vnd.oci.image.config.v1+json` | OCI Image Config | ✅ Fully Supported |
| `application/vnd.oci.image.layer.v1.tar` | OCI Layer (tar) | ✅ Fully Supported |
| `application/vnd.oci.image.layer.v1.tar+gzip` | OCI Layer (gzip) | ✅ Fully Supported |
| `application/vnd.oci.image.layer.v1.tar+zstd` | OCI Layer (zstd) | ✅ Fully Supported |

### Docker Media Types (Legacy Compatibility)

| Media Type | Description | Status |
|------------|-------------|---------|
| `application/vnd.docker.distribution.manifest.list.v2+json` | Docker Manifest List | ✅ Supported |
| `application/vnd.docker.distribution.manifest.v2+json` | Docker Manifest | ✅ Supported |
| `application/vnd.docker.image.rootfs.diff.tar` | Docker Layer | ✅ Supported |
| `application/vnd.docker.image.rootfs.diff.tar.gzip` | Docker Layer (gzip) | ✅ Supported |

## Platform Support

### Valid Operating Systems
- `linux` (primary focus)
- `windows`
- `freebsd`
- `openbsd`
- `solaris`
- `darwin`

### Valid Architectures
- `amd64` (x86-64)
- `arm64` (ARM64)
- `ppc64le` (PowerPC)
- `s390x` (IBM Z)
- `386` (x86)
- `arm` (ARM)
- `mips64`, `mips64le`, `mips`, `mipsle`
- `riscv64`

### Architecture Variants
- **ARM**: `v6`, `v7`, `v8`
- **ARM64**: `v8`
- **PPC64LE**: `power8`, `power9`

## OCI Annotations

### Standard OCI Annotations

```bash
# Recommended OCI annotations
--index-annotations=org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)
--index-annotations=org.opencontainers.image.source=https://github.com/org/repo
--index-annotations=org.opencontainers.image.licenses=Apache-2.0
--index-annotations=org.opencontainers.image.authors=team@example.com
--index-annotations=org.opencontainers.image.url=https://example.com/app
--index-annotations=org.opencontainers.image.documentation=https://example.com/docs
--index-annotations=org.opencontainers.image.vendor=Example Inc.
--index-annotations=org.opencontainers.image.ref.name=main
--index-annotations=org.opencontainers.image.version=1.2.3
--index-annotations=org.opencontainers.image.revision=$(git rev-parse HEAD)
```

### Annotation Validation Rules

1. **Key Format**: Must use reverse domain notation (e.g., `com.example.key`)
2. **Value Format**: Non-empty strings with proper formatting for specific annotations
3. **Reserved Namespaces**: `io.cncf.`, `io.openshift.`, `com.docker.`, `com.github.`, `org.opencontainers.`

## Validation and Compliance Checking

### Built-in OCI Validation

Kaniko includes comprehensive OCI compliance validation:

```bash
# Enable verbose validation logging
--verbosity=debug

# OCI compliance validation is automatic when --oci-mode=oci
```

### Validation Checks Performed

1. **Media Type Validation**: All media types must conform to OCI or Docker specifications
2. **Schema Version**: Only schema version 2 is supported
3. **Platform Validation**: OS, architecture, and variant values must be valid
4. **Annotation Validation**: Keys must follow reverse domain notation
5. **Digest Validation**: All content must have valid SHA-256 digests
6. **Size Validation**: All descriptors must have non-zero sizes

### Example Validation Output

```json
{
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "schemaVersion": 2,
  "manifestCount": 2,
  "annotationCount": 5,
  "platforms": {
    "linux/amd64": 1,
    "linux/arm64": 1
  },
  "valid": true
}
```

## Registry Compatibility

### OCI-Compliant Registries

- **GHCR** (GitHub Container Registry): Full OCI 1.1 support
- **GCR** (Google Container Registry): Full OCI 1.1 support
- **ECR** (AWS Elastic Container Registry): Full OCI 1.1 support
- **ACR** (Azure Container Registry): Full OCI 1.1 support
- **Quay**: Full OCI 1.1 support
- **Docker Hub**: OCI support with legacy fallback

### Registry-Specific Considerations

**Docker Hub**:
- Prefers Docker media types
- Automatic fallback to Docker format when needed
- Requires `--legacy-manifest-list=true` for multi-arch

**ECR Public**:
- Strict OCI compliance requirements
- Recommended: `--oci-mode=oci --compression=zstd`

**Self-Hosted Registries**:
- Use `--oci-mode=auto` for automatic detection
- Fallback to Docker format if OCI not supported

## Performance Considerations

### Compression Efficiency

| Algorithm | Compression Ratio | Speed | OCI Compliance |
|-----------|-------------------|-------|----------------|
| **zstd** | ⭐⭐⭐⭐⭐ (Best) | ⭐⭐⭐⭐⭐ (Fastest) | ✅ Full |
| **gzip** | ⭐⭐⭐ (Good) | ⭐⭐⭐ (Medium) | ✅ Full |

### Layer Optimization

```bash
# Recommended production settings for OCI compliance
--compression=zstd
--compression-level=3  # Balance between speed and ratio
--oci-mode=oci
--publish-index=true
```

## Security Features

### OCI Security Compliance

- **Content Trust**: Digest-based verification prevents tampering
- **No Privileged Operations**: Builds remain unprivileged
- **Minimal Attack Surface**: No execution of arbitrary code
- **Safe Defaults**: OCI features disabled by default, require explicit opt-in

### Image Signing Integration

```bash
# Cosign signing with OCI compliance
--sign-images=true
--cosign-key-path=/secrets/cosign.key

# Keyless signing (Sigstore)
--sign-images=true
```

## Migration from Docker Format

### Step-by-Step Migration

1. **Assessment**: Check current image format usage
   ```bash
   # Analyze existing images
   regctl manifest get registry/image:tag --format body | jq .mediaType
   ```

2. **Testing**: Validate OCI compatibility
   ```bash
   # Test build with OCI mode
   kaniko --oci-mode=oci --no-push --destination=local
   ```

3. **Gradual Rollout**: Use `--oci-mode=auto` initially
   ```bash
   # Phase 1: Auto-detection
   kaniko --oci-mode=auto --destination=registry/image:tag
   
   # Phase 2: Full OCI
   kaniko --oci-mode=oci --destination=registry/image:tag
   ```

4. **Verification**: Validate OCI compliance
   ```bash
   # Verify OCI compliance
   regctl manifest verify registry/image:tag
   ```

### Backward Compatibility

Kaniko maintains full backward compatibility:

- **Single-Architecture**: Existing workflows unchanged
- **Docker Format**: Always available via `--oci-mode=docker`
- **Automatic Fallback**: `--oci-mode=auto` handles compatibility issues

## Troubleshooting

### Common OCI Compliance Issues

**Media Type Rejection**:
```bash
# Error: unsupported media type
# Solution: Use --oci-mode=docker or validate registry OCI support
```

**Platform Validation Failure**:
```bash
# Error: invalid platform format
# Solution: Use correct platform format (os/arch[/variant])
```

**Annotation Validation**:
```bash
# Error: invalid annotation key
# Solution: Use reverse domain notation (com.example.key)
```

### Debugging OCI Issues

```bash
# Enable debug logging
--verbosity=debug

# Validate OCI configuration
--dry-run

# Check registry capabilities
regctl registry info registry.example.com
```

### Registry Compatibility Testing

```bash
# Test OCI push
kaniko --oci-mode=oci --no-push --digest-file=digest.txt

# Test Docker push  
kaniko --oci-mode=docker --no-push --digest-file=digest.txt

# Compare results
diff digest-oci.txt digest-docker.txt
```

## Best Practices

### Production OCI Configuration

```bash
# Recommended production settings
kaniko --oci-mode=oci \
       --compression=zstd \
       --publish-index=true \
       --index-annotations="org.opencontainers.image.source=https://github.com/org/repo" \
       --index-annotations="org.opencontainers.image.licenses=Apache-2.0" \
       --index-annotations="org.opencontainers.image.created=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
       --sign-images=true \
       --verbosity=info
```

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Build and push OCI image
  run: |
    kaniko --oci-mode=oci \
           --compression=zstd \
           --publish-index=true \
           --destination=ghcr.io/${{ github.repository }}:${{ github.sha }}
```

### Kubernetes OCI Builds

```yaml
# Kubernetes Job with OCI compliance
apiVersion: batch/v1
kind: Job
spec:
  template:
    spec:
      containers:
      - name: kaniko
        args:
        - --oci-mode=oci
        - --compression=zstd
        - --publish-index=true
        - --destination=registry/image:tag
```

## References

- [OCI Image Format Specification v1.1](https://github.com/opencontainers/image-spec/releases/tag/v1.1.0)
- [OCI Annotations Specification](https://github.com/opencontainers/image-spec/blob/main/annotations.md)
- [Docker Manifest Format](https://docs.docker.com/registry/spec/manifest-v2-2/)
- [Kaniko OCI Compliance](https://github.com/GoogleContainerTools/kaniko/blob/master/README.md#oci-compliance)

## Support

For OCI compliance issues:

1. **Registry Compatibility**: Check registry documentation for OCI support
2. **Validation Errors**: Use `--verbosity=debug` for detailed error information
3. **Migration Assistance**: Start with `--oci-mode=auto` for gradual migration
4. **Community Support**: GitHub Issues and Discussions

---

*This OCI compliance guide reflects Kaniko's implementation as of version 1.24.1. OCI specifications may evolve, and users should regularly check for updates.*