# OCI Compliance Verification

This document describes the OCI compliance verification tools and processes for Kaniko, ensuring that generated container images conform to the Open Container Initiative (OCI) specification.

## Overview

The OCI verification tools validate that Kaniko-generated images comply with OCI 1.0+ specifications, including:

- **OCI Image Index Format**: Multi-platform image indices
- **OCI Manifest Format**: Single-platform image manifests
- **Media Type Validation**: Correct use of OCI-standard media types
- **Layer Validation**: Proper layer structure and media types
- **Tool Compatibility**: Verification with industry-standard tools (crane, oras)

## Verification Tools

### 1. verify-oci.sh Script

The main verification script located at `scripts/verify-oci.sh` provides comprehensive OCI compliance validation.

#### Features

- **Automatic Test Image Creation**: Builds single-platform and multi-platform test images
- **Multi-Tool Validation**: Uses crane, oras, and jq for comprehensive validation
- **Registry Support**: Works with local and remote registries
- **Detailed Reporting**: Generates JSON validation reports
- **Error Detection**: Identifies non-compliant artifacts and provides detailed error messages

#### Requirements

- **crane**: `go install github.com/google/go-containerregistry/cmd/crane@latest`
- **oras**: https://oras.land/cli/
- **jq**: `brew install jq` (or equivalent for your OS)
- **Docker**: For building and managing test images
- **Registry**: Local registry (localhost:5000) or remote registry access

#### Usage

```bash
# Basic verification (uses local registry)
make verify-oci

# Quick verification (uses existing images in gcr.io/kaniko-test)
make verify-oci-quick

# Direct script execution with custom registry
REGISTRY=my-registry:5000 ./scripts/verify-oci.sh

# Using remote registry
REGISTRY=gcr.io/my-project ./scripts/verify-oci.sh
```

#### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `REGISTRY` | `localhost:5000` | Container registry to use for testing |
| `IMAGE_REPO` | `$REGISTRY/kaniko-test` | Base repository for test images |
| `OCI_TEST_IMAGE` | `$IMAGE_REPO/oci-validation-test:latest` | Single-platform test image |
| `OCI_MULTIARCH_IMAGE` | `$IMAGE_REPO/oci-multiarch-validation:latest` | Multi-platform test image |

### 2. Integration Tests

OCI validation is also integrated into the multi-platform E2E tests:

```bash
# Run multi-platform image verification tests
make integration-test-image-verification

# Run all multi-platform tests
make integration-test-multiplatform
```

## Validation Process

### 1. Single-Platform Image Validation

The script validates single-platform images by:

1. **Manifest Schema**: Verifies `schemaVersion` field exists
2. **Media Type**: Checks for `application/vnd.docker.distribution.manifest.v2+json`
3. **Layer Validation**: Validates layer media types are correct
4. **Accessibility**: Confirms image can be pulled and inspected

### 2. Multi-Platform Index Validation

The script validates OCI Image Indices by:

1. **Index Schema**: Verifies `schemaVersion` and `mediaType` fields
2. **Media Type**: Confirms `application/vnd.oci.image.index.v1+json`
3. **Manifest Count**: Ensures at least one manifest is present
4. **Platform Information**: Validates platform descriptors for each manifest
5. **Duplicate Detection**: Identifies duplicate platform entries
6. **Manifest Accessibility**: Verifies each manifest can be pulled

### 3. Tool Compatibility Validation

**crane Validation**:
- Manifest inspection
- Digest verification
- Platform validation

**oras Validation**:
- Image pulling
- Manifest extraction
- Config validation

## Expected Results

### Successful Validation

```
[INFO] Checking requirements...
[INFO] All required tools are available
[INFO] Starting local registry on port 5000
[INFO] Building test images...
[INFO] Validating single-platform image: localhost:5000/kaniko-test/oci-validation-test:latest
[INFO] Single-platform image validation passed: localhost:5000/kaniko-test/oci-validation-test:latest
[INFO] Validating multi-platform image index: localhost:5000/kaniko-test/oci-multiarch-validation:latest
[INFO] Found 2 manifests in index
[INFO]   Manifest 1: digest=sha256:abc123, platform=linux/amd64
[INFO]   Manifest 2: digest=sha256:def456, platform=linux/arm64
[INFO] Multi-platform index validation passed: localhost:5000/kaniko-test/oci-multiarch-validation:latest
[INFO] Validating with oras: localhost:5000/kaniko-test/oci-validation-test:latest
[INFO] oras validation passed: localhost:5000/kaniko-test/oci-validation-test:latest
[INFO] Validating with oras: localhost:5000/kaniko-test/oci-multiarch-validation:latest
[INFO] oras validation passed: localhost:5000/kaniko-test/oci-multiarch-validation:latest
[INFO] ✅ All OCI validations passed!
[INFO] Generating validation report: oci-validation-report.json
```

### Validation Report

The script generates a JSON report with validation results:

```json
{
  "timestamp": "2025-01-17T12:00:00Z",
  "registry": "localhost:5000",
  "images": {
    "single_platform": {
      "image": "localhost:5000/kaniko-test/oci-validation-test:latest",
      "validated": true
    },
    "multi_platform": {
      "image": "localhost:5000/kaniko-test/oci-multiarch-validation:latest",
      "validated": true
    }
  },
  "tools": {
    "crane": "v0.18.0",
    "oras": "1.0.0",
    "jq": "1.6"
  }
}
```

## Error Scenarios

### Missing Tools

```
[ERROR] Missing required tools: crane oras jq
[INFO] Install them with:
[INFO]   - crane: go install github.com/google/go-containerregistry/cmd/crane@latest
[INFO]   - oras: https://oras.land/cli/
[INFO]   - jq: brew install jq (or equivalent for your OS)
```

### Invalid Manifest

```
[ERROR] Invalid manifest schema for localhost:5000/kaniko-test/oci-validation-test:latest
[ERROR] Multi-platform index validation failed: localhost:5000/kaniko-test/oci-multiarch-validation:latest
[ERROR] Expected OCI image index, got: application/vnd.docker.distribution.manifest.v2+json
```

### Registry Issues

```
[ERROR] Image localhost:5000/kaniko-test/oci-validation-test:latest does not exist or is not accessible
[ERROR] Cannot pull manifest sha256:abc123 from index
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Verify OCI Compliance
  run: |
    make verify-oci
  if: github.event_name == 'push'

- name: Quick OCI Check
  run: |
    make verify-oci-quick
  if: github.event_name == 'pull_request'
```

### Pre-commit Hooks

```bash
#!/bin/bash
# .git/hooks/pre-commit
make verify-oci-quick
```

## Troubleshooting

### Common Issues

1. **Registry Connection Issues**:
   - Ensure local registry is running: `docker run --name registry -d -p 5000:5000 registry:2`
   - Check network connectivity for remote registries
   - Verify authentication credentials

2. **Tool Installation Problems**:
   - Ensure Go is properly installed and in PATH
   - Check GOPATH environment variable
   - Verify tool versions are compatible

3. **Image Build Failures**:
   - Check Dockerfile syntax
   - Ensure sufficient disk space
   - Verify context file permissions

4. **Validation Failures**:
   - Check if images were built with correct Kaniko flags
   - Verify OCI mode is enabled: `--oci-mode=oci`
   - Ensure multi-platform builds use `--multi-platform=true`

### Debug Mode

For detailed debugging, run with verbose output:

```bash
# Enable verbose logging in the script
set -x
./scripts/verify-oci.sh

# Or run individual validation steps
crane manifest localhost:5000/kaniko-test/oci-validation-test:latest
oras pull localhost:5000/kaniko-test/oci-validation-test:latest --output-dir /tmp/debug
```

## Best Practices

### 1. Regular Validation

- Run OCI validation as part of your CI/CD pipeline
- Perform validation before production deployments
- Keep validation tools updated to latest versions

### 2. Performance Considerations

- Use `verify-oci-quick` for PR checks to save time
- Run full verification on main branch updates
- Cache validation results when possible

### 3. Security

- Use secure registries with proper authentication
- Validate images from untrusted sources
- Keep verification tools in isolated environments

### 4. Monitoring

- Set up alerts for validation failures
- Track validation metrics over time
- Monitor tool version updates

## Related Documentation

- [OCI Specification](https://opencontainers.org/)
- [Multi-Platform Guide](multi-arch-guide.md)
- [Benchmark Documentation](benchmark.md)
- [Kaniko Modernization Plan](../MODERNIZATION.md)