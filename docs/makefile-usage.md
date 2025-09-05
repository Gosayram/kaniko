# Kaniko Makefile Usage Guide

This document provides comprehensive documentation for the Kaniko project's Makefile, explaining all available targets and their purposes.

## Overview

The Kaniko Makefile provides various build, test, and deployment targets for working with the Kaniko container image builder project.

## Available Targets

### Build Targets

#### `out/executor`
Builds the kaniko executor binary.
```bash
make out/executor
```

#### `out/warmer` 
Builds the kaniko warmer binary.
```bash
make out/warmer
```

**Environment Variables:**
- `GOOS`: Target operating system (default: current OS)
- `GOARCH`: Target architecture (default: current architecture)
- `VERSION`: Version string (default: from `.release-version` file)

### Test Targets

#### `test`
Runs the main test suite using `scripts/test.sh`.
```bash
make test
```

#### `test-with-coverage`
Runs tests and generates a coverage HTML report.
```bash
make test-with-coverage
```

#### `integration-test`
Runs all integration tests.
```bash
make integration-test
```

#### `integration-test-run`
Runs only the "TestRun" integration tests.
```bash
make integration-test-run
```

#### `integration-test-layers`
Runs only the "TestLayers" integration tests.
```bash
make integration-test-layers
```

#### `integration-test-k8s`
Runs only the "TestK8s" integration tests.
```bash
make integration-test-k8s
```

#### `integration-test-misc`
Runs miscellaneous integration tests.
```bash
make integration-test-misc
```

### Container Image Targets

#### `images`
Builds all Kaniko container images:
- `executor:latest` - Main executor image
- `executor:debug` - Debug version with additional tools
- `executor:slim` - Minimal version
- `warmer:latest` - Warmer component image

```bash
make images
```

**Environment Variables:**
- `BUILD_ARG`: Additional Docker build arguments
- `GOARCH`: Target architecture (default: current architecture)
- `REGISTRY`: Container registry (default: `gcr.io/kaniko-project`)

#### `push`
Pushes all built images to the container registry.
```bash
make push
```

#### `k8s-executor-build-push`
Builds and pushes only the executor image (useful for Kubernetes deployments).
```bash
make k8s-executor-build-push
```

### Setup and Utility Targets

#### `install-container-diff`
Installs the container-diff tool for comparing container images.
```bash
make install-container-diff
```

#### `k3s-setup`
Sets up a local k3s Kubernetes cluster for testing.
```bash
make k3s-setup
```

## Environment Variables

| Variable    | Description                       | Default                                |
| ----------- | --------------------------------- | -------------------------------------- |
| `VERSION`   | Project version                   | From `.release-version` or `v1.24.0`   |
| `GOOS`      | Target operating system           | Current OS (`go env GOOS`)             |
| `GOARCH`    | Target architecture               | Current architecture (`go env GOARCH`) |
| `REGISTRY`  | Container registry                | `gcr.io/kaniko-project`                |
| `BUILD_ARG` | Additional Docker build arguments | Empty                                  |
| `ORG`       | GitHub organization               | `github.com/GoogleContainerTools`      |
| `PROJECT`   | Project name                      | `kaniko`                               |

## Common Usage Examples

### Build for Specific Architecture
```bash
GOARCH=amd64 GOOS=linux make out/executor
```

### Build and Test
```bash
make out/executor && make test
```

### Build All Images and Push
```bash
make images && make push
```

### Run Specific Integration Tests
```bash
make integration-test-layers
```

### Development Workflow
```bash
# Build and test
make out/executor && make test

# Build images for testing
make images

# Run integration tests
make integration-test
```

## Script Dependencies

The Makefile relies on several scripts in the `scripts/` directory:

- `test.sh` - Main test runner
- `integration-test.sh` - Integration test runner
- `misc-integration-test.sh` - Miscellaneous test configuration
- `k3s-setup.sh` - Kubernetes cluster setup

## Version Management

The project uses a single source of truth for versioning from the `.release-version` file. The Makefile automatically extracts:
- Major version (`VERSION_MAJOR`)
- Minor version (`VERSION_MINOR`) 
- Build version (`VERSION_BUILD`)

These are injected into binaries via linker flags for proper version reporting.

## Build Flags

The Go build uses several linker flags:
- Static linking (`-extldflags "-static"`)
- Version injection from `.release-version`
- Git commit hash injection
- Build timestamp injection
- Debug symbol stripping (`-w -s`)

## Notes

- The Makefile uses Go Modules with vendor directory (`-mod=vendor`)
- All builds are statically linked with CGO disabled
- Docker BuildKit is enabled for image builds (`DOCKER_BUILDKIT=1`)
- The project follows semantic versioning conventions