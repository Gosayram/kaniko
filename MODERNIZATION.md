# Kaniko Modernization Documentation

## Overview

This document describes the modernization of Kaniko's build and version system from legacy approaches to modern Go 1.24+ best practices.

## Changes Made

### 1. Version Management System

**Before**: Manual version variables in Makefile + `pkg/version` package
**After**: Single source of truth in `.release-version` + `internal/version` package

#### Files Modified:

- [`Makefile`](Makefile): Updated to read version from `.release-version` and inject into `internal/version`
- [`hack/release.sh`](hack/release.sh): Modified to update `.release-version` instead of Makefile variables
- [`internal/version/version.go`](internal/version/version.go): New modern version package
- [`.release-version`](.release-version): Single source of truth for version

### 2. Build System Updates

The Makefile now uses proper ldflags injection with commit hash and build date:

```makefile
GO_LDFLAGS += -X $(VERSION_PACKAGE).Version=$(VERSION)
GO_LDFLAGS += -X $(VERSION_PACKAGE).Commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
GO_LDFLAGS += -X $(VERSION_PACKAGE).Date=$(shell date -u +%Y-%m-%dT%H:%M:%SZ)
```

### 3. Backward Compatibility

The system maintains backward compatibility:
- Makefile version variables (`VERSION_MAJOR`, `VERSION_MINOR`, `VERSION_BUILD`) are still updated
- Old `pkg/version` package remains functional during transition
- Existing build scripts continue to work

## Usage

### Building Locally

```bash
# Build for Linux (production target)
GOOS=linux GOARCH=amd64 make out/executor

# Build with specific version
echo "1.24.1" > .release-version
GOOS=linux GOARCH=amd64 make out/executor
```

### Release Process

```bash
# Run release script (interactive)
./hack/release.sh

# Or provide version non-interactively
echo "v1.24.1" | ./hack/release.sh
```

The release script will:
1. Update `.release-version` with the new version
2. Update Makefile variables for backward compatibility  
3. Generate changelog using GitHub API
4. Prepend release notes to `CHANGELOG.md`

### Version Inspection

The version information is now available through the [`internal/version`](internal/version/version.go) package and can be accessed via:

```go
import "github.com/Gosayram/kaniko/internal/version"

fmt.Printf("Version: %s\n", version.Version)
fmt.Printf("Commit: %s\n", version.Commit) 
fmt.Printf("Build Date: %s\n", version.Date)
fmt.Printf("Version String: %s\n", version.String())
```

## CI/CD Integration

### Future GitHub Actions Plan

The modernization sets the stage for a future CI/CD system that:

1. **Uses `.release-version` as single source of truth**
2. **Injects version via ldflags during build**
3. **Leverages existing hack scripts for release automation**
4. **Supports multi-architecture builds**
5. **Includes security scanning and signing**

### Example CI/CD Snippet

```yaml
- name: Build with version injection
  run: |
    VERSION=$(cat .release-version)
    COMMIT=$(git rev-parse --short HEAD)
    DATE=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    
    go build -ldflags "
      -X 'github.com/Gosayram/kaniko/internal/version.Version=$VERSION'
      -X 'github.com/Gosayram/kaniko/internal/version.Commit=$COMMIT'
      -X 'github.com/Gosayram/kaniko/internal/version.Date=$DATE'
      -s -w
    " -o bin/executor ./cmd/executor
```

## Testing

### Local Testing Commands

```bash
# Test version injection
GOOS=linux GOARCH=amd64 make out/executor

# Test release script (dry run)
echo "v1.24.1" > test-version
./hack/release.sh < test-version

# Run specific test suites
make test-unit
make integration-test
```

### Verification

To verify the modernization worked:

1. **Version Injection**: Check that builds use version from `.release-version`
2. **Backward Compatibility**: Ensure existing scripts still work
3. **Release Process**: Test that `hack/release.sh` updates both systems
4. **Build Artifacts**: Verify binaries contain correct version information

## Benefits

1. **Single Source of Truth**: No more version duplication
2. **Modern Go Practices**: Follows Go 1.24+ best practices
3. **CI/CD Ready**: Prepared for automated build pipelines
4. **Backward Compatible**: No breaking changes
5. **Enhanced Metadata**: Includes commit hash and build date

## Files Summary

- [`Makefile`](Makefile): Updated build system with modern version injection
- [`hack/release.sh`](hack/release.sh): Enhanced release automation
- [`internal/version/version.go`](internal/version/version.go): Modern version package
- [`.release-version`](.release-version): Version source file
- [`MODERNIZATION.md`](MODERNIZATION.md): This documentation
- [`IDEA.md`](IDEA.md): Planning and implementation notes

## Next Steps

1. **CI/CD Implementation**: Create GitHub Actions workflows
2. **Multi-arch Support**: Enhance Docker builds for multiple architectures
3. **Security Scanning**: Integrate vulnerability scanning
4. **Documentation Update**: Update main README with new practices
5. **Community Transition**: Guide contributors to new system

This modernization provides a solid foundation for future development while maintaining all existing functionality for local testing and development.