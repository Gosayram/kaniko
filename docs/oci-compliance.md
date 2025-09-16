# OCI 1.1 Compliance Guide

Kaniko provides excellent OCI 1.1 compliance (9/10 rating) out of the box, leveraging go-containerregistry and opencontainers/image-spec v1.1.1. This guide covers configuration for strict OCI compliance, media types, validation, and common use cases.

## Key OCI 1.1 Features Supported
- **Media Types**: Full support for OCI media types (`application/vnd.oci.image.*`), including Image Index (`application/vnd.oci.image.index.v1+json`), Image Manifest (`application/vnd.oci.image.manifest.v1+json`), and layer media types (e.g., `application/vnd.oci.image.layer.v1.tar+gzip`).
- **Image Index**: Multi-platform coordination creates OCI Image Index with platform descriptors.
- **Content Digests**: SHA256 content addressing for all blobs.
- **Platform Fields**: OS/Architecture in index entries.
- **Layer Compression**: Gzip (default) and Zstd (`--compression=zstd`).
- **Annotations**: Custom metadata via `--index-annotations=key=value`.
- **SBOM Attachment**: Optional via cosign integration (future).

## Configuration for OCI Compliance
To ensure full OCI 1.1 compliance, use the `--oci-mode=oci` flag. This forces OCI media types and Image Index for multi-platform builds.

### Basic Usage
```bash
kaniko --context=dir:.
  --dockerfile=Dockerfile
  --destination=registry/app:tag
  --oci-mode=oci  # Strict OCI
  --compression=zstd  # OCI-preferred compression
```

### Multi-Platform Builds
For multi-arch, `--publish-index=true` creates OCI Image Index:
```bash
kaniko --context=dir:.
  --dockerfile=Dockerfile
  --destination=registry/app:tag
  --multi-platform=linux/amd64,linux/arm64
  --driver=local  # or k8s/ci
  --publish-index=true
  --oci-mode=oci
  --compression=zstd
  --index-annotations=org.opencontainers.image.source=https://github.com/org/repo
```

### Validation
Validate generated images/indices with tools like oras or crane:
```bash
# Validate index
oras manifest fetch registry/app:tag --media-type application/vnd.oci.image.index.v1+json | jq .

# Verify media types
crane config registry/app:tag | jq .mediaType  # Should be application/vnd.oci.image.config.v1+json

# Check layers
crane layers registry/app:tag | jq '.[0].mediaType'  # application/vnd.oci.image.layer.v1.tar+zstd
```

## Media Type Handling
Kaniko automatically uses OCI media types when `--oci-mode=oci` or auto (default for multi-platform). Fallback to Docker for legacy (`--oci-mode=docker`).

- **Image Manifest**: `application/vnd.oci.image.manifest.v1+json`
- **Image Index**: `application/vnd.oci.image.index.v1+json`
- **Config**: `application/vnd.oci.image.config.v1+json`
- **Layers**: `application/vnd.oci.image.layer.v1.tar+gzip` or `application/vnd.oci.image.layer.v1.tar+zstd`

Conversion from Docker types happens in [pkg/oci/index.go](pkg/oci/index.go).

## Security Considerations
- Use `--oci-mode=oci` for production to avoid legacy Docker formats.
- Annotations for source/licenses: `--index-annotations=org.opencontainers.image.licenses=Apache-2.0`
- Signing: `--sign-images` with cosign for cryptographic verification.

## Known Limitations
- No automatic conversion from legacy manifests (opt-in only).
- Zstd requires compatible registry (e.g., GHCR, Quay support).

For advanced config, see advanced-configuration.md. Verify with `oras pull` or `crane inspect`.