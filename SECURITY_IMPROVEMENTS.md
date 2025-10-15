# 🔒 Kaniko Security Improvements

## 📋 Overview
This document describes critical security improvements implemented in Kaniko to prevent attacks and enhance stability.

## ✅ Implemented Improvements

### 1. **Directory Traversal Vulnerability Fixes**
- **Problem**: Unsafe file path validation
- **Solution**: Unified `validateFilePath` function
- **Files**: `pkg/util/util.go`, `pkg/util/tar_util.go`, `pkg/util/transport_util.go`
- **Status**: ✅ Completed

### 2. **File Size Validation**
- **Problem**: No file size limitations
- **Solution**: Dynamic limits with configuration options
- **Files**: `pkg/util/fs_util.go`

#### Default Settings:
- **MaxFileSize**: 500MB (single files)
- **MaxTarFileSize**: 5GB (files in tar archives)
- **MaxTotalArchiveSize**: 10GB (total archive size)

#### Command Line Arguments (Recommended):
```bash
# Configure size limits via CLI arguments (highest priority)
/kaniko/executor \
  --max-file-size="1GB" \
  --max-tar-file-size="10GB" \
  --max-total-archive-size="20GB" \
  --context=/workspace \
  --dockerfile=Dockerfile \
  --destination=my-app:latest
```

#### Environment Variables (Fallback):
```bash
# Configure single file size limit
export KANIKO_MAX_FILE_SIZE="1GB"

# Configure tar file size limit
export KANIKO_MAX_TAR_FILE_SIZE="10GB"

# Configure total archive size limit
export KANIKO_MAX_TOTAL_ARCHIVE_SIZE="20GB"
```

#### Supported Formats:
- `1024` - bytes
- `500MB` - megabytes
- `2.5GB` - gigabytes (with decimal fractions)
- `1TB` - terabytes

### 3. **Enhanced Error Handling**
- Logging of limit exceed attempts
- Detailed error messages
- Graceful fallback to default values

## 🚀 Benefits

### **Security:**
- Prevention of DoS attacks via large files
- Protection against directory traversal attacks
- Resource consumption control

### **Flexibility:**
- Limit configuration via environment variables
- Support for various size formats
- Backward compatibility

### **Performance:**
- Early detection of problematic files
- Prevention of memory exhaustion
- Archive processing optimization

## 📊 Usage Examples

### **Basic Usage:**
```bash
# Using with default settings
docker run --rm -v $(pwd):/workspace kaniko-test:latest \
  --context=/workspace \
  --dockerfile=Dockerfile \
  --destination=my-app:latest
```

### **With CLI Limit Configuration (Recommended):**
```bash
# Using CLI arguments for size limits (most secure)
docker run --rm \
  -v $(pwd):/workspace kaniko-test:latest \
  --context=/workspace \
  --dockerfile=Dockerfile \
  --destination=my-app:latest \
  --max-file-size="2GB" \
  --max-tar-file-size="20GB" \
  --max-total-archive-size="50GB"
```

### **With Environment Variable Configuration:**
```bash
# Using environment variables (fallback method)
docker run --rm \
  -e KANIKO_MAX_FILE_SIZE="2GB" \
  -e KANIKO_MAX_TAR_FILE_SIZE="20GB" \
  -e KANIKO_MAX_TOTAL_ARCHIVE_SIZE="50GB" \
  -v $(pwd):/workspace kaniko-test:latest \
  --context=/workspace \
  --dockerfile=Dockerfile \
  --destination=my-app:latest
```

### **For CI/CD Pipelines:**
```yaml
# GitLab CI example with CLI arguments (recommended)
build:
  image: kaniko-test:latest
  script:
    - /kaniko/executor \
      --context=/workspace \
      --dockerfile=Dockerfile \
      --destination=registry/app:latest \
      --max-file-size="1GB" \
      --max-tar-file-size="10GB" \
      --max-total-archive-size="20GB"

# Alternative: Using environment variables
build_with_env:
  image: kaniko-test:latest
  variables:
    KANIKO_MAX_FILE_SIZE: "1GB"
    KANIKO_MAX_TAR_FILE_SIZE: "10GB"
    KANIKO_MAX_TOTAL_ARCHIVE_SIZE: "20GB"
  script:
    - /kaniko/executor --context=/workspace --dockerfile=Dockerfile --destination=registry/app:latest
```

## 🔧 Technical Details

### **Architecture:**
- Constants for default values
- Functions for dynamic limit retrieval
- Size parser with support for various formats
- Integration into existing copy functions

### **Testing:**
- Unit tests for all new functions
- Edge case tests
- Various size format tests
- Error handling tests

## 📈 Metrics

### **Before Improvements:**
- ❌ No directory traversal validation
- ❌ No file size limitations
- ❌ Potential DoS vulnerabilities

### **After Improvements:**
- ✅ Protection against directory traversal attacks
- ✅ File size control (500MB/5GB by default)
- ✅ Configurable limits via environment variables
- ✅ Support for various size formats
- ✅ Complete test coverage

## 🎯 Next Steps

### **Planned Improvements:**
1. **Symlink handling improvement** - circular reference detection
2. **Permission checks** - enhanced file operation security
3. **Performance optimization** - buffer pooling and parallelization
4. **Metrics and monitoring** - Prometheus metrics integration

---

**Created**: $(date)
**Version**: 1.0
**Status**: In Production
