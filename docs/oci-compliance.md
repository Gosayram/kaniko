# OCI 1.1 Compliance Guide

This document provides a comprehensive guide to OCI (Open Container Initiative) 1.1 compliance in Kaniko, including supported media types, validation, and best practices.

## Overview

Kaniko now supports full OCI 1.1 compliance for multi-platform builds, enabling you to create and push OCI Image Index artifacts that can be consumed by container runtimes and registries that support the OCI specification.

## Supported OCI 1.1 Features

### 1. OCI Image Index

Kaniko creates OCI Image Index (`application/vnd.oci.image.index.v1+json`) when building multi-platform images. The index contains platform-specific image manifests and supports:

- **Platform descriptors**: Each manifest includes `platform.os` and `platform.architecture`
- **Annotations**: Custom metadata can be attached to the index
- **Media type validation**: Automatic fallback to Docker Manifest List when needed

### 2. Supported Media Types

| Media Type | Description | Support Status |
|------------|-------------|----------------|
| `application/vnd.oci.image.index.v1+json` | OCI Image Index | ✅ Full |
| `application/vnd.oci.image.manifest.v1+json` | OCI Image Manifest | ✅ Full |
| `application/vnd.oci.image.config.v1+json` | OCI Image Configuration | ✅ Full |
| `application/vnd.oci.image.layer.v1.tar+gzip` | Gzipped OCI Layer | ✅ Full |
| `application/vnd.oci.image.layer.v1.tar+zstd` | Zstd-compressed OCI Layer | ✅ Full |
| `application/vnd.docker.distribution.manifest.list.v2+json` | Docker Manifest List | ✅ Fallback |

### 3. Compression Support

Kaniko supports multiple compression algorithms for OCI layers:

#### Gzip (Default)
```bash
# Default behavior - gzip compression
kaniko --destination=gcr.io/myrepo/myimage:latest \
       --platform=linux/amd64,linux/arm64
```

#### Zstandard (Zstd)
```bash
# Zstd compression for better compression ratios
kaniko --destination=gcr.io/myrepo/myimage:latest \
       --platform=linux/amd64,linux/arm64 \
       --compression=zstd
```

## Configuration Options

### 1. OCI Mode Selection

Kaniko provides three OCI compliance modes:

```bash
# Auto mode (default) - prefers OCI, falls back to Docker
kaniko --oci-mode=auto

# Strict OCI mode - only OCI formats, fails if not supported
kaniko --oci-mode=oci

# Docker mode - uses Docker manifest lists
kaniko --oci-mode=docker
```

### 2. Publishing Image Index

To publish the OCI Image Index to your registry:

```bash
# Enable index publishing
kaniko --destination=gcr.io/myrepo/myimage:latest \
       --platform=linux/amd64,linux/arm64 \
       --publish-index=true
```

### 3. Index Annotations

Add custom annotations to the OCI Image Index:

```bash
# Add annotations via command line
kaniko --destination=gcr.io/myrepo/myimage:latest \
       --platform=linux/amd64,linux/arm64 \
       --index-annotations="org.opencontainers.image.title=MyApp,org.opencontainers.image.version=1.0"

# Or use multiple flags
kaniko --destination=gcr.io/myrepo/myimage:latest \
       --platform=linux/amd64,linux/arm64 \
       --index-annotations="org.opencontainers.image.title=MyApp" \
       --index-annotations="org.opencontainers.image.version=1.0"
```

## Validation and Verification

### 1. Using `oras` to Validate OCI Artifacts

```bash
# Install oras
curl -L https://github.com/oras-project/oras/releases/download/v1.0.0/oras_1.0.0_linux_amd64.tar.gz | tar -xz
sudo mv oras /usr/local/bin/

# Validate OCI Image Index
oras manifest fetch gcr.io/myrepo/myimage:latest

# Validate specific platform manifest
oras manifest fetch gcr.io/myrepo/myimage:latest --platform linux/amd64
```

### 2. Using `crane` to Inspect OCI Artifacts

```bash
# Install crane
go install github.com/google/go-containerregistry/cmd/crane@latest

# Inspect image index
crane manifest gcr.io/myrepo/myimage:latest

# Get platform-specific information
crane manifest gcr.io/myrepo/myimage:latest --platform linux/arm64
```

### 3. Registry Compatibility

#### Registries with Full OCI 1.1 Support
- **Google Container Registry (GCR)**: ✅ Full support
- **GitHub Container Registry (GHCR)**: ✅ Full support
- **Amazon ECR**: ✅ Full support
- **Azure Container Registry**: ✅ Full support

#### Legacy Registry Considerations
Some older registries may not support OCI Image Index. Use these strategies:

```bash
# Force Docker manifest list for legacy registries
kaniko --destination=old-registry.com/myrepo/myimage:latest \
       --platform=linux/amd64,linux/arm64 \
       --oci-mode=docker

# Or use legacy manifest list flag
kaniko --destination=old-registry.com/myrepo/myimage:latest \
       --platform=linux/amd64,linux/arm64 \
       --legacy-manifest-list=true
```

## Best Practices

### 1. Multi-Platform Builds

```bash
# Best practice: Build for multiple platforms
kaniko --destination=gcr.io/myrepo/myimage:latest \
       --platform=linux/amd64,linux/arm64,linux/s390x \
       --publish-index=true \
       --oci-mode=auto
```

### 2. Layer Compression Optimization

```bash
# Use zstd for better compression with supported registries
kaniko --destination=gcr.io/myrepo/myimage:latest \
       --platform=linux/amd64,linux/arm64 \
       --compression=zstd \
       --compression-level=3
```

### 3. Index Management

```bash
# Add meaningful annotations
kaniko --destination=gcr.io/myrepo/myimage:latest \
       --platform=linux/amd64,linux/arm64 \
       --publish-index=true \
       --index-annotations="org.opencontainers.image.description=Multi-platform build" \
       --index-annotations="org.opencontainers.image.source=https://github.com/user/repo"
```

### 4. Error Handling

```bash
# Handle registry compatibility issues gracefully
if ! kaniko build --oci-mode=oci; then
  echo "OCI mode failed, falling back to Docker mode"
  kaniko build --oci-mode=docker
fi
```

## Troubleshooting

### 1. Common Issues

#### Registry Rejects OCI Index
```bash
# Error: "unsupported media type"
# Solution: Use Docker fallback
kaniko --destination=registry.example.com/image:tag \
       --platform=linux/amd64,linux/arm64 \
       --oci-mode=docker
```

#### Layer Compression Issues
```bash
# Error: "unsupported layer compression"
# Solution: Use gzip compression
kaniko --destination=gcr.io/myrepo/myimage:latest \
       --platform=linux/amd64,linux/arm64 \
       --compression=gzip
```

### 2. Debugging OCI Artifacts

```bash
# Enable debug logging
kaniko --destination=gcr.io/myrepo/myimage:latest \
       --platform=linux/amd64,linux/arm64 \
       --verbosity=debug

# Check generated artifact locally
docker run --rm -v /tmp:/output gcr.io/kaniko-project/executor:latest \
       --destination=local:/output/index.tar \
       --platform=linux/amd64,linux/arm64 \
       --no-push
```

## Migration from Docker Manifest Lists

### For Existing Multi-Platform Images

1. **Identify existing Docker manifest lists**:
   ```bash
   crane manifest gcr.io/myrepo/myimage:latest | jq '.manifests[].platform'
   ```

2. **Migrate to OCI format**:
   ```bash
   # Rebuild with OCI mode
   kaniko --destination=gcr.io/myrepo/myimage:latest \
          --platform=linux/amd64,linux/arm64 \
          --oci-mode=oci \
          --publish-index=true
   ```

3. **Verify migration**:
   ```bash
   # Check media type
   crane manifest gcr.io/myrepo/myimage:latest | jq '.mediaType'
   
   # Should return: "application/vnd.oci.image.index.v1+json"
   ```

### CI/CD Pipeline Updates

#### GitHub Actions Example

```yaml
name: Build and Push Multi-Platform Image

on:
  push:
    branches: [ main ]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Docker Buildx
      uses: docker/setup-buildx-action@v3
    
    - name: Build and push with Kaniko (OCI mode)
      run: |
        #!/bin/bash
        docker run --rm \
          -v ${{ github.workspace }}:/workspace \
          gcr.io/kaniko-project/executor:latest \
          --dockerfile=/workspace/Dockerfile \
          --context=/workspace \
          --destination=gcr.io/myrepo/myimage:${{ github.sha }} \
          --platform=linux/amd64,linux/arm64 \
          --oci-mode=auto \
          --publish-index=true \
          --index-annotations="org.opencontainers.image.title=MyApp" \
          --index-annotations="org.opencontainers.image.revision=${{ github.sha }}"
```

#### GitLab CI Example

```yaml
build_multiplatform:
  image: gcr.io/kaniko-project/executor:latest
  stage: build
  script:
    - |
      /kaniko/executor \
        --dockerfile=Dockerfile \
        --context=$CI_PROJECT_DIR \
        --destination=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA \
        --platform=linux/amd64,linux/arm64 \
        --oci-mode=auto \
        --publish-index=true \
        --index-annotations="org.opencontainers.image.title=MyApp" \
        --index-annotations="org.opencontainers.image.revision=$CI_COMMIT_SHA"
  only:
    - main
```

## Performance Considerations

### 1. Index Size Optimization

- **Minimize annotations**: Only include necessary metadata
- **Use appropriate compression**: Zstd for smaller sizes, gzip for wider compatibility
- **Avoid redundant platforms**: Only build for architectures you actually need

### 2. Push Optimization

- **Enable caching**: Reduces layer push times for subsequent builds
- **Use parallel pushes**: Kaniko automatically handles parallel pushes for multi-platform builds
- **Registry-specific settings**: Some registries benefit from specific retry configurations

```bash
# Optimize for performance
kaniko --destination=gcr.io/myrepo/myimage:latest \
       --platform=linux/amd64,linux/arm64 \
       --cache=true \
       --cache-repo=gcr.io/myrepo/cache \
       --push-retry=3 \
       --push-retry-initial-delay=1000 \
       --push-retry-max-delay=30000
```

## Security Considerations

### 1. Image Signing

Kaniko supports Cosign integration for OCI artifact signing:

```bash
# Build and sign OCI index
kaniko --destination=gcr.io/myrepo/myimage:latest \
       --platform=linux/amd64,linux/arm64 \
       --publish-index=true \
       --sign-images=true \
       --cosign-key=/path/to/cosign.key
```

### 2. Verification

```bash
# Verify signed OCI index
cosign verify gcr.io/myrepo/myimage:latest
```

## Conclusion

Kaniko's OCI 1.1 compliance enables modern container workflows with full multi-platform support. By following this guide, you can leverage OCI features while maintaining compatibility with existing infrastructure.

For more information about the OCI specification, see:
- [OCI Image Specification](https://github.com/opencontainers/image-spec)
- [OCI Distribution Specification](https://github.com/opencontainers/distribution-spec)