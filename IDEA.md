# Kaniko Modernization Plan

## Current State Analysis

The project is in transition from legacy systems to modern Go 1.24+ practices:

### ✅ Existing Infrastructure
- **Makefile**: Uses old `pkg/version` package with manual version variables
- **Release Process**: [`hack/release.sh`](hack/release.sh) with GitHub API integration
- **Version Management**: Mixed approach - `.release-version` file exists but not fully integrated
- **Build System**: Functional but uses deprecated patterns

### 🆕 Modern Components Already Added
- [`internal/version`](internal/version/version.go): Modern version package following Go 1.24+ best practices
- [`.release-version`](.release-version): Single source of truth for version (1.24.0)
- **CI/CD**: GitHub Actions removed, needs replacement strategy

## Modernization Goals

1. **Unified Version System**: Complete transition to `internal/version` with `.release-version` as source
2. **Modern Build System**: Update Makefile to use proper ldflags injection
3. **Release Automation**: Enhance `hack/release.sh` to work with new system
4. **Local Development**: Ensure all changes work seamlessly for local testing
5. **CI/CD Integration**: Plan for future CI that leverages hack scripts

## Implementation Plan

### Phase 1: Makefile Modernization

**Current Issue**: Makefile uses `pkg/version` but should use `internal/version`

```makefile
# Current (line 35)
GO_LDFLAGS += -X $(VERSION_PACKAGE).version=$(VERSION)

# Should be (after checking module path)
GO_LDFLAGS += -X $(MODULE)/internal/version.Version=$(VERSION)
```

**Action Items**:
1. Determine correct module path: `go list -m`
2. Update Makefile VERSION_PACKAGE reference
3. Add commit hash and build date injection
4. Ensure backward compatibility

### Phase 2: Release Script Update

**Current Issue**: [`hack/release.sh`](hack/release.sh) updates Makefile variables but should update `.release-version`

**Action Items**:
1. Modify release script to update `.release-version` instead of Makefile
2. Keep Makefile version variables for backward compatibility during transition
3. Update changelog generation to use new version source

### Phase 3: Local Testing Preservation

**Critical**: Ensure all existing functionality works locally:
- `make test` - unit tests
- `make integration-test` - integration tests  
- `make images` - Docker image building
- `make out/executor` - binary compilation

### Phase 4: CI/CD Strategy

**Future Planning**: Design CI/CD that:
- Uses hack scripts for release automation
- Supports both GitHub Actions and local execution
- Maintains security signing with cosign
- Provides multi-arch builds

## Step-by-Step Execution

### Step 1: Module Path Identification
```bash
# Check current module path
go list -m
# Expected: github.com/Gosayram/kaniko
```

### Step 2: Makefile Updates
Update [`Makefile`](Makefile) lines:
- Line 21: `VERSION ?= $(shell cat .release-version)`
- Line 31: `VERSION_PACKAGE = $(REPOPATH)/internal/version`
- Add commit and date injection to ldflags

### Step 3: Release Script Modification
Update [`hack/release.sh`](hack/release.sh):
- Write version to `.release-version` instead of Makefile
- Keep Makefile update for transition period
- Update version extraction logic

### Step 4: Testing Validation
Comprehensive testing:
```bash
# Test version injection
make out/executor
./out/executor version

# Test release process
./hack/release.sh

# Test all build targets
make test
make integration-test
make images
```

## Risk Mitigation

1. **Backward Compatibility**: Keep old `pkg/version` functional during transition
2. **Gradual Rollout**: Implement changes incrementally
3. **Testing**: Comprehensive test suite before final switch
4. **Documentation**: Update all relevant docs with new approach

## Timeline

1. **Stage 1**: Makefile updates and testing
2. **Stage 2**: Release script modifications  
3. **Stage 3**: Comprehensive testing and validation
4. **Stage 4**: Documentation and cleanup
5. **Stage 5**: CI/CD planning (future phase)

## Success Metrics

- ✅ `make out/executor` produces binary with correct version from `.release-version`
- ✅ `./out/executor version` shows version from internal/package
- ✅ `./hack/release.sh` updates `.release-version` correctly
- ✅ All existing tests pass
- ✅ Docker images build successfully

This plan ensures a smooth transition to modern Go practices while maintaining all existing functionality for local development and testing.