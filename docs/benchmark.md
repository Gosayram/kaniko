# Multi-Platform Benchmark

This document describes the multi-platform benchmarks for Kaniko, which measure the coordinator overhead when using multi-platform builds compared to single-arch builds.

## Overview

The benchmarks are designed to measure the performance impact of the multi-platform coordinator functionality introduced in the modernization plan. The goal is to ensure that the coordinator overhead remains below 10% of the total build time.

## Benchmarks

### 1. Coordinator Overhead Benchmark

**Test**: `TestMultiplatformCoordinatorOverhead`

**Purpose**: Measures the overhead introduced by the multi-platform coordinator when building images for multiple platforms.

**Metrics**:
- Single-arch build time (baseline)
- Multi-arch build time (with coordinator)
- Coordinator overhead percentage
- Total build time

**Platform Combinations Tested**:
- Single-arch vs multi-arch (2 platforms): `linux/amd64`, `linux/arm64`
- Single-arch vs multi-arch (3 platforms): `linux/amd64`, `linux/arm64`, `linux/s390x`
- Single-arch vs multi-arch (4 platforms): `linux/amd64`, `linux/arm64`, `linux/s390x`, `linux/ppc64le`

**Expected Result**: Coordinator overhead should be less than 10%.

### 2. Driver Overhead Benchmark

**Test**: `TestMultiplatformDriverOverhead`

**Purpose**: Measures the performance impact of different multi-platform drivers.

**Drivers Tested**:
- Local driver
- Kubernetes driver
- CI driver

**Metrics**:
- Build time for each driver
- Platform-specific performance characteristics

## Running Benchmarks

### Prerequisites

1. Ensure you have a local registry running:
```bash
docker start registry || docker run --name registry -d -p 5000:5000 registry:2
```

2. Set the BENCHMARK environment variable:
```bash
export BENCHMARK=true
```

### Using Make Targets

```bash
# Run coordinator overhead benchmark
make benchmark

# Run driver overhead benchmark
make benchmark-drivers

# Run all benchmarks
make benchmark-all
```

### Using Go Test Directly

```bash
# Run coordinator overhead benchmark
BENCHMARK=true go test ./integration/... -run "TestMultiplatformCoordinatorOverhead" -v

# Run driver overhead benchmark
BENCHMARK=true go test ./integration/... -run "TestMultiplatformDriverOverhead" -v

# Run all multi-platform benchmarks
BENCHMARK=true go test ./integration/... -run "TestMultiplatform" -v
```

### Using Benchmark Script

```bash
# Run with the existing benchmark script
export BENCHMARK=true
./benchmark.sh
```

## Benchmark Results

### Output Format

The benchmarks produce JSON result files with the following structure:

```json
{
  "test_name": "single-arch vs multi-arch (2 platforms)",
  "timestamp": "2025-01-17T12:00:00Z",
  "platform_count": 2,
  "total_build_time": 45.23,
  "coordinator_time": 2.15,
  "single_arch_time": 40.12,
  "multi_arch_time": 42.27,
  "overhead_percentage": 5.35
}
```

### Interpretation

- **Overhead Percentage**: The percentage increase in build time when using multi-platform builds compared to single-arch builds. Should be < 10%.
- **Coordinator Time**: Estimated time spent on coordination activities (platform validation, job management, etc.).
- **Total Build Time**: Complete time for multi-platform build including coordination overhead.

## Performance Analysis

### Expected Performance Characteristics

1. **Single-arch Baseline**: Fastest possible build time for a single platform.
2. **Multi-arch with 2 platforms**: ~5-10% overhead over single-arch.
3. **Multi-arch with 3+ platforms**: ~8-15% overhead over single-arch.

### Factors Affecting Performance

1. **Network Latency**: Affects remote drivers (k8s, CI) more than local driver.
2. **Registry Performance**: Push latency impacts multi-platform builds more significantly.
3. **Platform Complexity**: Some platforms may require different build steps.
4. **Resource Contention**: Concurrent builds may compete for resources.

## Troubleshooting

### Common Issues

1. **Registry Not Available**:
   - Ensure local registry is running on port 5000
   - Check firewall settings if using remote registry

2. **Build Failures**:
   - Verify Dockerfile syntax
   - Check context file permissions
   - Ensure sufficient disk space

3. **Inconsistent Results**:
   - Run multiple iterations for statistical significance
   - Ensure system is not under heavy load
   - Warm up caches before running benchmarks

### Debug Mode

For detailed logging, run with additional flags:
```bash
BENCHMARK=true go test ./integration/... -run "TestMultiplatformCoordinatorOverhead" -v -args --debug
```

## Integration with CI/CD

### GitHub Actions

The benchmarks can be integrated into CI/CD pipelines:

```yaml
- name: Run Multi-Platform Benchmarks
  run: |
    export BENCHMARK=true
    make benchmark-all
  if: github.event_name == 'push'
```

### Performance Regression Detection

Set up alerts for:
- Overhead percentage exceeding 10%
- Build time increases of more than 20%
- Failed benchmark runs

## Future Enhancements

1. **Statistical Analysis**: Add statistical significance testing to benchmark results.
2. **Memory Usage**: Monitor memory consumption during multi-platform builds.
3. **Network Impact**: Measure network traffic and latency effects.
4. **Large Scale Testing**: Test with more platforms and larger build contexts.
5. **Real-world Workloads**: Benchmark with production Dockerfiles and contexts.

## Related Documentation

- [Multi-Platform Guide](multi-arch-guide.md)
- [OCI Compliance](oci-compliance.md)
- [Integration Tests](../integration/README.md)