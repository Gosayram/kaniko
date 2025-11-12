# kaniko - Build Images In Kubernetes

> [!IMPORTANT]
> This repository is a **modern fork** of the original [Gosayram/kaniko](https://github.com/Gosayram/kaniko) project, now maintained by [Gosayram](https://github.com/Gosayram). The original Google Kaniko repository was archived on Jun 3, 2025. This fork continues development and maintenance to ensure the container image building tool remains available and functional for the community, with **modern Go 1.24+ infrastructure, full OCI 1.1 compliance, built-in multi-architecture support, secure rootless execution by default, advanced caching capabilities, enhanced logging and monitoring, and intelligent registry optimization**.

[![Go Report Card](https://goreportcard.com/badge/github.com/Gosayram/kaniko)](https://goreportcard.com/report/github.com/Gosayram/kaniko)
[![Version](https://img.shields.io/badge/Version-1.25.1-blue)](.release-version)

![kaniko logo](logo/Kaniko-Logo.png)

kaniko is a modern tool to build container images from a Dockerfile, inside a container or Kubernetes cluster, featuring **built-in multi-architecture support, full OCI 1.1 compliance, enhanced registry compatibility, and secure rootless execution by default**.

kaniko doesn't depend on a Docker daemon and executes each command within a Dockerfile completely in userspace. This enables building container images in environments that can't easily or securely run a Docker daemon, such as a standard Kubernetes cluster. The modern implementation includes **native multi-platform coordination without privileged operations**, **excellent OCI compliance**, and **automatic rootless security mode** for enhanced safety.

kaniko is meant to be run as an image: `ghcr.io/gosayram/kaniko`. We do **not** recommend running the kaniko executor binary in another image, as it might not work as you expect - see [Known Issues](#known-issues).

## 🚀 Quick Start

### Basic Usage

```bash
docker run -v $(pwd):/workspace \
  ghcr.io/gosayram/kaniko:latest \
  --dockerfile=/workspace/Dockerfile \
  --destination=<your-registry/your-image:tag> \
  --context=dir:///workspace
```

### Using Default User

⚠️ **SECURITY WARNING**: Only use this for development or legacy builds. **NEVER use `--default-user=root` in production!**

For Dockerfiles that need root privileges but don't specify a USER instruction:

```bash
docker run -v $(pwd):/workspace \
  ghcr.io/gosayram/kaniko:latest \
  --dockerfile=/workspace/Dockerfile \
  --destination=<your-registry/your-image:tag> \
  --context=dir:///workspace \
  --default-user=root
```

**Recommended approach**: Always specify a non-root user in your Dockerfile:
```dockerfile
FROM node:18-alpine
# ... your build steps ...
USER node
CMD ["node", "app.js"]
```

### Using Source Policy (Security)

Control which image sources are allowed:

```bash
docker run -v $(pwd):/workspace \
  ghcr.io/gosayram/kaniko:latest \
  --dockerfile=/workspace/Dockerfile \
  --destination=<your-registry/your-image:tag> \
  --context=dir:///workspace \
  --allowed-registries=gcr.io/*,docker.io/* \
  --denied-registries=untrusted.io/*
```

### Generating SLSA Provenance

Generate supply chain security attestations:

```bash
docker run -v $(pwd):/workspace \
  ghcr.io/gosayram/kaniko:latest \
  --dockerfile=/workspace/Dockerfile \
  --destination=<your-registry/your-image:tag> \
  --context=dir:///workspace \
  --generate-provenance
```

### In Kubernetes

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kaniko
spec:
  containers:
    - name: kaniko
      image: ghcr.io/gosayram/kaniko:latest
      args:
        - "--dockerfile=/workspace/Dockerfile"
        - "--context=gs://bucket>/context.tar.gz"
        - "--destination=gcr.io/your-project/your-image:tag"
      volumeMounts:
        - name: kaniko-secret
          mountPath: /secret
      env:
        - name: GOOGLE_APPLICATION_CREDENTIALS
          value: /secret/kaniko-secret.json
  restartPolicy: Never
  volumes:
    - name: kaniko-secret
      secret:
        secretName: kaniko-secret
```

### Kubernetes with Default User

⚠️ **SECURITY WARNING**: Only use this for development or legacy builds. **NEVER use `--default-user=root` in production!**

For builds that need root privileges:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kaniko-root
spec:
  containers:
    - name: kaniko
      image: ghcr.io/gosayram/kaniko:latest
      args:
        - "--dockerfile=/workspace/Dockerfile"
        - "--context=gs://bucket>/context.tar.gz"
        - "--destination=gcr.io/your-project/your-image:tag"
        - "--default-user=root"
      volumeMounts:
        - name: kaniko-secret
          mountPath: /secret
      env:
        - name: GOOGLE_APPLICATION_CREDENTIALS
          value: /secret/kaniko-secret.json
  restartPolicy: Never
  volumes:
    - name: kaniko-secret
      secret:
        secretName: kaniko-secret
```

**Recommended approach**: Always specify a non-root user in your Dockerfile:
```dockerfile
FROM node:18-alpine
# ... your build steps ...
USER node
CMD ["node", "app.js"]
```

## 🔒 Security Best Practices

### User Security

**⚠️ CRITICAL SECURITY REQUIREMENTS:**

1. **NEVER use `--default-user=root` in production environments**
2. **Always specify a non-root user in your Dockerfile with `USER` instruction**
3. **Not specifying a user or overriding it with root is considered unsafe and prohibited in production**
4. **The `--default-user` flag should only be used for development or legacy builds that cannot be modified**

### Recommended Dockerfile Pattern

```dockerfile
FROM node:18-alpine

# Install dependencies as root (if needed)
RUN apk add --no-cache curl

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Switch to non-root user
USER nextjs

# Copy application files
COPY --chown=nextjs:nodejs . .

# Run application as non-root user
CMD ["node", "app.js"]
```

### Production Security Checklist

- ✅ **Specify non-root user in Dockerfile**
- ✅ **Use `USER` instruction in Dockerfile**
- ✅ **Avoid `--default-user=root` in production**
- ✅ **Test containers with non-root user**
- ✅ **Use minimal base images**
- ✅ **Regular security updates**

## 🔐 Rootless Security Mode (Default)

Kaniko now runs in **secure rootless mode by default**, providing enhanced security without requiring additional configuration. This modern security implementation automatically determines the optimal execution mode based on your Dockerfile and configuration.

### Automatic Security Mode Detection

Kaniko automatically determines the security mode based on the target user:

#### Secure Mode (Rootless) - Default
- **Target User**: Non-root user (e.g., `kaniko:kaniko`, `node:node`)
- **Execution**: Runs in rootless mode after initialization
- **Security**: Enhanced isolation and minimal privileges
- **Activation**: Automatic when target user is non-root

#### Legacy Mode (Root) - Only When Necessary
- **Target User**: Root user (explicitly specified)
- **Execution**: Runs with root privileges
- **Security**: Traditional mode with security warnings
- **Activation**: Automatic when target user is root (with warnings)

### Security Mode Examples

```bash
# Secure rootless mode (default) - no additional flags needed
docker run -v $(pwd):/workspace \
  ghcr.io/gosayram/kaniko:latest \
  --dockerfile=/workspace/Dockerfile \
  --destination=myimage:latest \
  --context=dir:///workspace

# Automatic detection based on Dockerfile USER instruction
# Dockerfile: USER node → Secure rootless mode
# Dockerfile: USER root → Legacy mode with warnings
```

### Rootless Mode Benefits

- **Enhanced Security**: Runs with minimal privileges after initialization
- **Automatic Configuration**: No manual setup required
- **Backward Compatibility**: Existing Dockerfiles work without changes
- **Intelligent Fallback**: Automatically switches to root mode only when necessary
- **Security Warnings**: Clear warnings when running in legacy root mode

### Configuration Options

```bash
# Explicitly specify target user (affects security mode)
--default-user=myuser:mygroup

# Security mode is automatically determined based on:
# 1. USER instruction in Dockerfile
# 2. --default-user flag
# 3. Default kaniko user (kaniko:kaniko)
```

## 📋 Table of Contents

- [kaniko - Build Images In Kubernetes](#kaniko---build-images-in-kubernetes)
  - [🚀 Quick Start](#-quick-start)
    - [Basic Usage](#basic-usage)
    - [Using Default User](#using-default-user)
    - [Using Source Policy (Security)](#using-source-policy-security)
    - [Generating SLSA Provenance](#generating-slsa-provenance)
    - [In Kubernetes](#in-kubernetes)
    - [Kubernetes with Default User](#kubernetes-with-default-user)
  - [🔒 Security Best Practices](#-security-best-practices)
    - [User Security](#user-security)
    - [Recommended Dockerfile Pattern](#recommended-dockerfile-pattern)
    - [Production Security Checklist](#production-security-checklist)
  - [🔐 Rootless Security Mode (Default)](#-rootless-security-mode-default)
    - [Automatic Security Mode Detection](#automatic-security-mode-detection)
      - [Secure Mode (Rootless) - Default](#secure-mode-rootless---default)
      - [Legacy Mode (Root) - Only When Necessary](#legacy-mode-root---only-when-necessary)
    - [Security Mode Examples](#security-mode-examples)
    - [Rootless Mode Benefits](#rootless-mode-benefits)
    - [Configuration Options](#configuration-options)
  - [📋 Table of Contents](#-table-of-contents)
  - [🔧 How does kaniko work?](#-how-does-kaniko-work)
    - [🚀 **MODERN ARCHITECTURE** - Advanced Features](#-modern-architecture---advanced-features)
      - [**📋 Supported Dockerfile Commands**](#-supported-dockerfile-commands)
      - [**🔧 Advanced Build Engine**](#-advanced-build-engine)
      - [**🌐 Network \& Registry Intelligence**](#-network--registry-intelligence)
      - [**📊 Monitoring \& Profiling**](#-monitoring--profiling)
      - [**🔒 Security \& Compliance**](#-security--compliance)
  - [🚨 Known Issues](#-known-issues)
  - [🔧 Recent Improvements](#-recent-improvements)
    - [Timeout and Reliability Enhancements](#timeout-and-reliability-enhancements)
    - [Enhanced Logging](#enhanced-logging)
  - [🎥 Demo](#-demo)
  - [📚 Tutorial](#-tutorial)
  - [🛠️ Using kaniko](#️-using-kaniko)
    - [kaniko Build Contexts](#kaniko-build-contexts)
    - [Using Azure Blob Storage](#using-azure-blob-storage)
    - [Using Private Git Repository](#using-private-git-repository)
    - [Using Standard Input](#using-standard-input)
    - [Running kaniko](#running-kaniko)
      - [Running kaniko in a Kubernetes cluster](#running-kaniko-in-a-kubernetes-cluster)
        - [Kubernetes secret](#kubernetes-secret)
      - [Running kaniko in gVisor](#running-kaniko-in-gvisor)
      - [Running kaniko in Google Cloud Build](#running-kaniko-in-google-cloud-build)
      - [Running kaniko in Docker](#running-kaniko-in-docker)
    - [Caching](#caching)
      - [Caching Layers](#caching-layers)
      - [Caching Base Images](#caching-base-images)
      - [🚀 **ADVANCED CACHING** - Smart Cache Features](#-advanced-caching---smart-cache-features)
        - [**Smart Cache with LRU Eviction**](#smart-cache-with-lru-eviction)
        - [**Advanced Cache Configuration**](#advanced-cache-configuration)
        - [**Cache Performance Optimization**](#cache-performance-optimization)
        - [**Multi-Platform Cache Support**](#multi-platform-cache-support)
        - [**Cache Monitoring \& Analytics**](#cache-monitoring--analytics)
    - [Pushing to Different Registries](#pushing-to-different-registries)
      - [Pushing to Docker Hub](#pushing-to-docker-hub)
      - [Pushing to Google GCR](#pushing-to-google-gcr)
      - [Pushing to GCR using Workload Identity](#pushing-to-gcr-using-workload-identity)
      - [Pushing to Amazon ECR](#pushing-to-amazon-ecr)
      - [Pushing to Azure Container Registry](#pushing-to-azure-container-registry)
      - [Pushing to JFrog Container Registry or to JFrog Artifactory](#pushing-to-jfrog-container-registry-or-to-jfrog-artifactory)
    - [Additional Flags](#additional-flags)
      - [Flag `--build-arg`](#flag---build-arg)
      - [Flag `--cache`](#flag---cache)
      - [Flag `--cache-dir`](#flag---cache-dir)
      - [Flag `--cache-repo`](#flag---cache-repo)
      - [Flag `--cache-copy-layers`](#flag---cache-copy-layers)
      - [Flag `--cache-run-layers`](#flag---cache-run-layers)
      - [Flag `--cache-ttl duration`](#flag---cache-ttl-duration)
      - [Flag `--cleanup`](#flag---cleanup)
      - [Flag `--compressed-caching`](#flag---compressed-caching)
      - [Flag `--context-sub-path`](#flag---context-sub-path)
      - [Flag `--custom-platform`](#flag---custom-platform)
      - [Flag `--default-user`](#flag---default-user)
      - [Flag `--digest-file`](#flag---digest-file)
      - [Flag `--dockerfile`](#flag---dockerfile)
      - [Flag `--force`](#flag---force)
      - [Flag `--git`](#flag---git)
      - [Flag `--image-name-with-digest-file`](#flag---image-name-with-digest-file)
      - [Flag `--image-name-tag-with-digest-file`](#flag---image-name-tag-with-digest-file)
      - [Flag `--insecure`](#flag---insecure)
      - [Flag `--insecure-pull`](#flag---insecure-pull)
      - [Flag `--insecure-registry`](#flag---insecure-registry)
      - [Flag `--label`](#flag---label)
      - [Flag `--log-format`](#flag---log-format)
      - [Flag `--log-timestamp`](#flag---log-timestamp)
      - [Flag `--no-push`](#flag---no-push)
      - [Flag `--no-push-cache`](#flag---no-push-cache)
      - [Flag `--oci-layout-path`](#flag---oci-layout-path)
      - [Flag `--push-ignore-immutable-tag-errors`](#flag---push-ignore-immutable-tag-errors)
      - [Flag `--multi-platform`](#flag---multi-platform)
      - [Flag `--driver`](#flag---driver)
      - [Flag `--publish-index`](#flag---publish-index)
      - [Flag `--legacy-manifest-list`](#flag---legacy-manifest-list)
      - [Flag `--index-annotations`](#flag---index-annotations)
      - [Flag `--arch-cache-repo-suffix`](#flag---arch-cache-repo-suffix)
      - [Flag `--digests-from`](#flag---digests-from)
      - [Flag `--require-native-nodes`](#flag---require-native-nodes)
      - [Flag `--oci-mode`](#flag---oci-mode)
      - [Flag `--compression`](#flag---compression)
      - [Flag `--compression-level`](#flag---compression-level)
      - [Flag `--push-retry`](#flag---push-retry)
      - [Flag `--push-retry-initial-delay`](#flag---push-retry-initial-delay)
      - [Flag `--push-retry-max-delay`](#flag---push-retry-max-delay)
      - [Flag `--push-retry-backoff-multiplier`](#flag---push-retry-backoff-multiplier)
      - [Flag `--registry-certificate`](#flag---registry-certificate)
      - [Flag `--registry-client-cert`](#flag---registry-client-cert)
      - [Flag `--registry-map`](#flag---registry-map)
      - [Flag `--registry-mirror`](#flag---registry-mirror)
      - [Flag `--skip-default-registry-fallback`](#flag---skip-default-registry-fallback)
      - [Flag `--credential-helpers`](#flag---credential-helpers)
      - [Flag `--reproducible`](#flag---reproducible)
      - [Flag `--single-snapshot`](#flag---single-snapshot)
      - [Flag `--skip-push-permission-check`](#flag---skip-push-permission-check)
      - [Flag `--skip-tls-verify`](#flag---skip-tls-verify)
      - [Flag `--skip-tls-verify-pull`](#flag---skip-tls-verify-pull)
      - [Flag `--skip-tls-verify-registry`](#flag---skip-tls-verify-registry)
      - [Flag `--skip-unused-stages`](#flag---skip-unused-stages)
      - [Flag `--snapshot-mode`](#flag---snapshot-mode)
      - [Flag `--tar-path`](#flag---tar-path)
      - [Flag `--target`](#flag---target)
      - [Flag `--use-new-run`](#flag---use-new-run)
      - [Flag `--preserve-context`](#flag---preserve-context)
      - [Flag `--use-oci-stages`](#flag---use-oci-stages)
      - [Flag `--materialize`](#flag---materialize)
      - [Flag `--pre-cleanup`](#flag---pre-cleanup)
      - [Flag `--verbosity`](#flag---verbosity)
      - [Flag `--ignore-var-run`](#flag---ignore-var-run)
      - [Flag `--ignore-path`](#flag---ignore-path)
      - [Flag `--kaniko-dir`](#flag---kaniko-dir)
      - [Flag `--force-build-metadata`](#flag---force-build-metadata)
      - [Flag `--max-file-size`](#flag---max-file-size)
      - [Flag `--max-tar-file-size`](#flag---max-tar-file-size)
      - [Flag `--max-total-archive-size`](#flag---max-total-archive-size)
      - [Flag `--enable-unified-cache`](#flag---enable-unified-cache)
      - [Flag `--optimize-execution-order`](#flag---optimize-execution-order)
      - [Flag `--enable-lazy-image-loading`](#flag---enable-lazy-image-loading)
    - [Debug Flags](#debug-flags)
      - [Flag `--debug-full`](#flag---debug-full)
      - [Flag `--debug-build-steps`](#flag---debug-build-steps)
      - [Flag `--debug-multi-platform`](#flag---debug-multi-platform)
      - [Flag `--debug-oci`](#flag---debug-oci)
      - [Flag `--debug-drivers`](#flag---debug-drivers)
      - [Flag `--debug-filesystem`](#flag---debug-filesystem)
      - [Flag `--debug-cache`](#flag---debug-cache)
      - [Flag `--debug-registry`](#flag---debug-registry)
      - [Flag `--debug-signing`](#flag---debug-signing)
      - [Flag `--debug-output-files`](#flag---debug-output-files)
      - [Flag `--debug-level`](#flag---debug-level)
      - [Flag `--debug-components`](#flag---debug-components)
    - [Environment Variables](#environment-variables)
      - [Build Configuration](#build-configuration)
      - [Network Configuration](#network-configuration)
      - [Timeout Configuration](#timeout-configuration)
      - [Resource Limits Configuration](#resource-limits-configuration)
      - [Directory Hashing Configuration](#directory-hashing-configuration)
      - [Registry Configuration](#registry-configuration)
      - [Credential Environment Variables](#credential-environment-variables)
      - [Flag `--image-fs-extract-retry`](#flag---image-fs-extract-retry)
      - [Flag `--image-download-retry`](#flag---image-download-retry)
      - [Flag `--incremental-snapshots`](#flag---incremental-snapshots)
      - [Flag `--max-expected-changes`](#flag---max-expected-changes)
      - [Flag `--integrity-check`](#flag---integrity-check)
      - [Flag `--full-scan-backup`](#flag---full-scan-backup)
      - [Flag `--max-memory-usage-bytes`](#flag---max-memory-usage-bytes)
      - [Flag `--max-file-size-bytes`](#flag---max-file-size-bytes)
      - [Flag `--max-total-file-size-bytes`](#flag---max-total-file-size-bytes)
      - [Flag `--memory-monitoring`](#flag---memory-monitoring)
      - [Flag `--gc-threshold`](#flag---gc-threshold)
      - [Flag `--monitoring-interval`](#flag---monitoring-interval)
      - [Flag `--max-parallel-commands`](#flag---max-parallel-commands)
      - [Flag `--command-timeout`](#flag---command-timeout)
      - [Flag `--enable-parallel-exec`](#flag---enable-parallel-exec)
      - [Flag `--max-cache-entries`](#flag---max-cache-entries)
      - [Flag `--max-preload-size`](#flag---max-preload-size)
      - [Flag `--preload-timeout`](#flag---preload-timeout)
      - [Flag `--enable-smart-cache`](#flag---enable-smart-cache)
      - [Flag `--max-concurrent-cache-checks`](#flag---max-concurrent-cache-checks)
      - [Flag `--max-workers`](#flag---max-workers)
      - [Flag `--max-parallel-hashing`](#flag---max-parallel-hashing)
      - [Flag `--max-parallel-copy`](#flag---max-parallel-copy)
      - [Flag `--disable-compression`](#flag---disable-compression)
      - [Flag `--max-file-hash-size`](#flag---max-file-hash-size)
      - [Flag `--max-network-concurrency`](#flag---max-network-concurrency)
      - [Flag `--cache-max-conns`](#flag---cache-max-conns)
      - [Flag `--cache-max-conns-per-host`](#flag---cache-max-conns-per-host)
      - [Flag `--cache-max-concurrent-requests`](#flag---cache-max-concurrent-requests)
      - [Flag `--cache-disable-http2`](#flag---cache-disable-http2)
      - [Flag `--cache-request-timeout`](#flag---cache-request-timeout)
      - [Flag `--prefetch-window`](#flag---prefetch-window)
      - [Flag `--cache-result-ttl`](#flag---cache-result-ttl)
      - [Flag `--cache-result-max-entries`](#flag---cache-result-max-entries)
      - [Flag `--cache-result-max-memory-mb`](#flag---cache-result-max-memory-mb)
      - [Flag `--file-hash-cache-max-entries`](#flag---file-hash-cache-max-entries)
      - [Flag `--file-hash-cache-max-memory-mb`](#flag---file-hash-cache-max-memory-mb)
      - [Flag `--layer-load-max-concurrent`](#flag---layer-load-max-concurrent)
      - [Flag `--enable-predictive-cache`](#flag---enable-predictive-cache)
      - [Flag `--predictive-cache-max-layers`](#flag---predictive-cache-max-layers)
      - [Flag `--predictive-cache-max-memory-mb`](#flag---predictive-cache-max-memory-mb)
      - [Flag `--local-cache-use-mmap`](#flag---local-cache-use-mmap)
      - [Flag `--local-cache-compress`](#flag---local-cache-compress)
      - [Flag `--local-cache-compression`](#flag---local-cache-compression)
      - [Flag `--compression-level`](#flag---compression-level-1)
      - [Flag `--generate-provenance`](#flag---generate-provenance)
      - [Flag `--allowed-registries`](#flag---allowed-registries)
      - [Flag `--denied-registries`](#flag---denied-registries)
      - [Flag `--allowed-repos`](#flag---allowed-repos)
      - [Flag `--denied-repos`](#flag---denied-repos)
      - [Flag `--require-signature`](#flag---require-signature)
    - [Debug Image](#debug-image)
  - [🔒 Security](#-security)
    - [Verifying Signed Kaniko Images](#verifying-signed-kaniko-images)
    - [🛡️ **ADVANCED SECURITY** - Security Features](#️-advanced-security---security-features)
      - [**Security Features**](#security-features)
      - [**Security Best Practices**](#security-best-practices)
  - [📈 Kaniko Builds - Profiling](#-kaniko-builds---profiling)
    - [🚀 **PERFORMANCE OPTIMIZATION** - Advanced Build Features](#-performance-optimization---advanced-build-features)
      - [**Memory Management \& Monitoring**](#memory-management--monitoring)
      - [**Memory Configuration**](#memory-configuration)
      - [**Parallel Execution \& Performance**](#parallel-execution--performance)
      - [**How Parallel Execution Works**](#how-parallel-execution-works)
      - [**Parallel Execution Configuration**](#parallel-execution-configuration)
      - [**Best Practices for Parallel Execution**](#best-practices-for-parallel-execution)
      - [**CPU Optimization \& Resource Management**](#cpu-optimization--resource-management)
      - [**CPU Configuration**](#cpu-configuration)
      - [**CPU Optimization Best Practices**](#cpu-optimization-best-practices)
      - [**Build Optimization Engine**](#build-optimization-engine)
      - [**Optimization Features**](#optimization-features)
      - [**Advanced Snapshotting**](#advanced-snapshotting)
      - [**Snapshot Configuration**](#snapshot-configuration)
      - [**Performance Monitoring**](#performance-monitoring)
    - [📊 **ADVANCED LOGGING \& MONITORING** - Enterprise-Grade Observability](#-advanced-logging--monitoring---enterprise-grade-observability)
      - [**Enhanced Logging Formats**](#enhanced-logging-formats)
      - [**Logging Configuration**](#logging-configuration)
      - [**Progress Tracking \& Monitoring**](#progress-tracking--monitoring)
      - [**Monitoring Features**](#monitoring-features)
      - [**Integration \& Observability**](#integration--observability)
  - [🏗️ Built-in Multi-Architecture Support](#️-built-in-multi-architecture-support)
    - [✅ **PRODUCTION-READY** - Key Features](#-production-ready---key-features)
    - [Quick Start Examples](#quick-start-examples)
      - [Local Development](#local-development)
      - [Kubernetes Multi-Arch Build](#kubernetes-multi-arch-build)
      - [CI Integration](#ci-integration)
    - [✅ **FULLY IMPLEMENTED** - Configuration Flags](#-fully-implemented---configuration-flags)
      - [Multi-Platform Configuration](#multi-platform-configuration)
      - [Enhanced Registry Push Configuration](#enhanced-registry-push-configuration)
    - [Migration Guide](#migration-guide)
      - [From Manifest-tool to Built-in Multi-Arch](#from-manifest-tool-to-built-in-multi-arch)
      - [Key Migration Benefits](#key-migration-benefits)
      - [Breaking Changes Considerations](#breaking-changes-considerations)
    - [Performance and Reliability](#performance-and-reliability)
    - [Validation and Testing](#validation-and-testing)
    - [✅ **COMPREHENSIVE** - Documentation](#-comprehensive---documentation)
    - [🏗️ **ADVANCED PLATFORM SUPPORT** - Multi-Architecture Excellence](#️-advanced-platform-support---multi-architecture-excellence)
      - [**Platform Detection \& Management**](#platform-detection--management)
      - [**Multi-Platform Features**](#multi-platform-features)
      - [**Platform Configuration**](#platform-configuration)
      - [**Supported Platforms**](#supported-platforms)
      - [**Platform Intelligence**](#platform-intelligence)
  - [🏗️ Creating Multi-arch Container Manifests Using Kaniko and Manifest-tool](#️-creating-multi-arch-container-manifests-using-kaniko-and-manifest-tool)
    - [General Workflow](#general-workflow)
    - [Limitations and Pitfalls](#limitations-and-pitfalls)
    - [Example CI Pipeline (GitLab)](#example-ci-pipeline-gitlab)
      - [Building the Separate Container Images](#building-the-separate-container-images)
      - [Merging the Container Manifests](#merging-the-container-manifests)
      - [On the Note of Adding Versioned Tags](#on-the-note-of-adding-versioned-tags)
  - [🔄 Comparison with Other Tools](#-comparison-with-other-tools)
  - [🚀 **MODERN ADVANTAGES** - Comparison with Other Tools](#-modern-advantages---comparison-with-other-tools)
    - [✅ **Kaniko's Modern Advantages:**](#-kanikos-modern-advantages)
    - [✅ **Kaniko's Unique Modern Features:**](#-kanikos-unique-modern-features)
  - [👥 Community](#-community)
    - [✅ **MODERN DEVELOPMENT** - Key Infrastructure](#-modern-development---key-infrastructure)
    - [🗂️ **ADVANCED FILESYSTEM OPERATIONS** - Optimized File Handling](#️-advanced-filesystem-operations---optimized-file-handling)
      - [**Smart Filesystem Scanning**](#smart-filesystem-scanning)
      - [**Filesystem Configuration**](#filesystem-configuration)
      - [**Advanced Path Handling**](#advanced-path-handling)
      - [**Filesystem Features**](#filesystem-features)
  - [⚠️ Limitations](#️-limitations)
    - [mtime and snapshotting](#mtime-and-snapshotting)
    - [Dockerfile commands `--chown` support](#dockerfile-commands---chown-support)
    - [🌐 **ADVANCED NETWORK \& REGISTRY OPERATIONS** - Enterprise Connectivity](#-advanced-network--registry-operations---enterprise-connectivity)
      - [**Network Optimization**](#network-optimization)
      - [**Network Configuration**](#network-configuration-1)
      - [**Registry Intelligence**](#registry-intelligence)
      - [**Registry Features**](#registry-features)
      - [**Advanced Registry Operations**](#advanced-registry-operations)
      - [**Network Security**](#network-security)
    - [📦 **OCI COMPLIANCE \& STANDARDS** - Industry-Leading Compatibility](#-oci-compliance--standards---industry-leading-compatibility)
      - [**OCI 1.1 Compliance**](#oci-11-compliance)
      - [**OCI Features**](#oci-features)
      - [**OCI Configuration**](#oci-configuration)
      - [**Standards Compliance**](#standards-compliance)
      - [**Verification \& Testing**](#verification--testing)
  - [📖 References](#-references)

## 🔧 How does kaniko work?

The kaniko executor image is responsible for building an image from a Dockerfile and pushing it to a registry. Within the executor image, we extract the filesystem of the base image (the FROM image in the Dockerfile). We then execute the commands in the Dockerfile, snapshotting the filesystem in userspace after each one. After each command, we append a layer of changed files to the base image (if there are any) and update image metadata.

### 🚀 **MODERN ARCHITECTURE** - Advanced Features

Kaniko's modern implementation includes several advanced subsystems:

#### **📋 Supported Dockerfile Commands**
- **FROM** - Base image specification with multi-platform support
- **RUN** - Shell and direct command execution with parallel processing and heredoc syntax support (`<<EOF`)
- **COPY/ADD** - File copying with `--chown` support, optimization, and heredoc syntax support (`<<EOF`)
- **ENV** - Environment variable management
- **ARG** - Build argument handling with predefined args (BUILDPLATFORM, TARGETPLATFORM, TARGETOS, TARGETARCH, TARGETSTAGE, etc.)
- **USER** - User switching with security validation
- **WORKDIR** - Working directory management
- **EXPOSE** - Port exposure
- **VOLUME** - Volume mount points
- **LABEL** - Image metadata
- **CMD/ENTRYPOINT** - Container execution commands
- **ONBUILD** - Build triggers
- **STOPSIGNAL** - Signal handling
- **HEALTHCHECK** - Health check configuration
- **SHELL** - Custom shell specification

#### **🔧 Advanced Build Engine**
- **Multi-Stage Builds** - Full support with dependency analysis
- **Parallel Command Execution** - Independent commands run concurrently
- **Smart Snapshotting** - Incremental snapshots with integrity checks
- **Optimized Filesystem Operations** - Safe snapshot optimizer with 60-80% performance improvement
- **Memory Management** - Automatic garbage collection and memory monitoring
- **Build Optimization** - Pattern detection and automated suggestions
- **LLB Graph Optimization** - BuildKit-inspired graph optimization with edge merging (enabled by default)
- **Scheduler with Edge Merging** - Intelligent operation scheduling and deduplication
- **Lazy Image Loading** - On-demand layer loading for memory efficiency (enabled by default)

#### **🌐 Network & Registry Intelligence**
- **Connection Pooling** - Optimized HTTP connection management with configurable limits
- **Parallel Layer Pulling** - Concurrent image layer downloads with intelligent batching
- **Registry Compatibility** - Enhanced support for Docker Hub, GCR, ECR, ACR, JFrog
- **Registry Intelligence** - Automatic capability detection and optimization per registry
- **Retry Mechanisms** - Exponential backoff with configurable retry policies
- **DNS Optimization** - Caching and connection reuse for improved performance
- **Manifest Caching** - Intelligent manifest caching with TTL and invalidation
- **Rate Limiting** - Automatic rate limit detection and compliance

#### **📊 Monitoring & Profiling**
- **Structured Logging** - JSON, text, color, and custom kaniko formats with context
- **Performance Metrics** - Build timing, memory usage, and throughput tracking
- **Progress Tracking** - Real-time build progress with indicators and grouping
- **Error Analysis** - Detailed error reporting with context and stack traces
- **Build Profiling** - Integration with performance analysis tools
- **Memory Monitoring** - Real-time memory usage tracking and garbage collection metrics
- **Cache Analytics** - Hit rates, miss rates, and cache performance statistics
- **Network Metrics** - Connection pool usage, retry statistics, and latency tracking

#### **🔒 Security & Compliance**
- **Source Policy** - Validate and control image sources before loading
- **SLSA Provenance** - Generate supply chain security attestations
- **Fast/Slow Cache** - BuildKit-inspired hierarchical cache system
- **Unified Cache** - Automatic cache selection and predictive prefetching

## 🚨 Known Issues

- kaniko does not support building Windows containers.
- Running kaniko in any Docker image other than the official kaniko image is not supported due to implementation details.
  - This includes copying the kaniko executables from the official image into another image (e.g. a Jenkins CI agent).
  - In particular, it cannot use chroot or bind-mount because its container must not require privilege, so it unpacks directly into its own container root and may overwrite anything already there.
- kaniko does not support the v1 Registry API ([Registry v1 API Deprecation](https://www.docker.com/blog/registry-v1-api-deprecation/))

## 🔧 Recent Improvements

### Timeout and Reliability Enhancements

Kaniko now includes comprehensive timeout mechanisms to prevent hangs and improve reliability:

- **File System Operations**: Timeouts for file resolution, directory scanning, and file hashing operations to prevent hangs on large projects
- **Cache Operations**: Timeouts for cache key computation, prefetch operations, and composite key population to prevent build hangs
- **Command Processing**: Timeouts for individual command execution and file context resolution to ensure builds complete reliably
- **Network Operations**: Timeouts for image retrieval, registry pull/push operations, and remote cache operations
- **Resource Limits**: Configurable limits for file count processing to prevent resource exhaustion
- **Memory Monitoring**: Automatic memory usage checks during directory scanning with warnings when thresholds are exceeded
- **Goroutine Leak Prevention**: Enhanced context cancellation and channel cleanup to prevent goroutine leaks
- **Symlink Handling**: Improved symlink detection and skipping to prevent infinite loops during directory walks

These improvements ensure that kaniko builds complete reliably even with very large build contexts or slow network connections. All timeout values are configurable via constants and can be adjusted for specific use cases (see [Timeout Configuration](#timeout-configuration)).

### Enhanced Logging

- **Color-coded Log Output**: Visual distinction between log levels (INFO - blue, WARN - yellow, ERROR - red)
- **Intelligent Color Detection**: Automatically detects terminal capabilities and respects `NO_COLOR` environment variable
- **Performance Logging**: Enhanced timing information for file operations and build stages

## 🎥 Demo

![Demo](/docs/demo.gif)

## 📚 Tutorial

For a detailed example of kaniko with local storage, please refer to a [getting started tutorial](./docs/tutorial.md).

Please see [References](#References) for more docs & video tutorials

## 🛠️ Using kaniko

To use kaniko to build and push an image for you, you will need:

1. A [build context](#kaniko-build-contexts), aka something to build
2. A [running instance of kaniko](#running-kaniko)

### kaniko Build Contexts

kaniko's build context is very similar to the build context you would send your Docker daemon for an image build; it represents a directory containing a Dockerfile which kaniko will use to build your image. For example, a `COPY` command in your Dockerfile should refer to a file in the build context.

You will need to store your build context in a place that kaniko can access. Right now, kaniko supports these storage solutions:

- GCS Bucket
- S3 Bucket
- Azure Blob Storage
- Local Directory
- Local Tar
- Standard Input
- Git Repository

_Note about Local Directory: this option refers to a directory within the kaniko container. If you wish to use this option, you will need to mount in your build context into the container as a directory._

_Note about Local Tar: this option refers to a tar gz file within the kaniko container. If you wish to use this option, you will need to mount in your build context into the container as a file._

_Note about Standard Input: the only Standard Input allowed by kaniko is in `.tar.gz` format._

If using a GCS or S3 bucket, you will first need to create a compressed tar of your build context and upload it to your bucket. Once running, kaniko will then download and unpack the compressed tar of the build context before starting the image build.

To create a compressed tar, you can run:

```shell
tar -C <path to build context> -zcvf context.tar.gz .
```

Then, copy over the compressed tar into your bucket. For example, we can copy over the compressed tar to a GCS bucket with gsutil:

```shell
gsutil cp context.tar.gz gs://<bucket name>
```

When running kaniko, use the `--context` flag with the appropriate prefix to specify the location of your build context:

| Source             | Prefix                                                                | Example                                                                       |
| ------------------ | --------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Local Directory    | dir://[path to a directory in the kaniko container]                   | `dir:///workspace`                                                            |
| Local Tar Gz       | tar://[path to a .tar.gz in the kaniko container]                     | `tar:///path/to/context.tar.gz`                                               |
| Standard Input     | tar://[stdin]                                                         | `tar://stdin`                                                                 |
| GCS Bucket         | gs://[bucket name]/[path to .tar.gz]                                  | `gs://kaniko-bucket/path/to/context.tar.gz`                                   |
| S3 Bucket          | s3://[bucket name]/[path to .tar.gz]                                  | `s3://kaniko-bucket/path/to/context.tar.gz`                                   |
| Azure Blob Storage | https://[account].[azureblobhostsuffix]/[container]/[path to .tar.gz] | `https://myaccount.blob.core.windows.net/container/path/to/context.tar.gz`    |
| Git Repository     | git://[repository url][#reference][#commit-id]                        | `git://github.com/acme/myproject.git#refs/heads/mybranch#<desired-commit-id>` |

If you don't specify a prefix, kaniko will assume a local directory. For example, to use a GCS bucket called `kaniko-bucket`, you would pass in `--context=gs://kaniko-bucket/path/to/context.tar.gz`.

### Using Azure Blob Storage

If you are using Azure Blob Storage for context file, you will need to pass [Azure Storage Account Access Key](https://docs.microsoft.com/en-us/azure/storage/common/storage-configure-connection-string?toc=%2fazure%2fstorage%2fblobs%2ftoc.json) as an environment variable named `AZURE_STORAGE_ACCESS_KEY` through Kubernetes Secrets

### Using Private Git Repository

You can use `Personal Access Tokens` for Build Contexts from Private Repositories from [GitHub](https://blog.github.com/2012-09-21-easier-builds-and-deployments-using-git-over-https-and-oauth/).

You can either pass this in as part of the git URL (e.g., `git://TOKEN@github.com/acme/myproject.git#refs/heads/mybranch`) or using the environment variable `GIT_TOKEN`.

You can also pass `GIT_USERNAME` and `GIT_PASSWORD` (password being the token) if you want to be explicit about the username.

### Using Standard Input

If running kaniko and using Standard Input build context, you will need to add the docker or kubernetes `-i, --interactive` flag. Once running, kaniko will then get the data from `STDIN` and create the build context as a compressed tar. It will then unpack the compressed tar of the build context before starting the image build. If no data is piped during the interactive run, you will need to send the EOF signal by yourself by pressing `Ctrl+D`.

Complete example of how to interactively run kaniko with `.tar.gz` Standard Input data, using docker:

```shell
echo -e 'FROM alpine \nRUN echo "created from standard input"' > Dockerfile | tar -cf - Dockerfile | gzip -9 | docker run \
  --interactive -v $(pwd):/workspace ghcr.io/gosayram/kaniko:latest \
  --context tar://stdin \
  --destination=<gcr.io/$project/$image:$tag>
```

Complete example of how to interactively run kaniko with `.tar.gz` Standard Input data, using Kubernetes command line with a temporary container and completely dockerless:

```shell
echo -e 'FROM alpine \nRUN echo "created from standard input"' > Dockerfile | tar -cf - Dockerfile | gzip -9 | kubectl run kaniko \
--rm --stdin=true \
--image=ghcr.io/gosayram/kaniko:latest --restart=Never \
--overrides='{
  "apiVersion": "v1",
  "spec": {
    "containers": [
      {
        "name": "kaniko",
        "image": "ghcr.io/gosayram/kaniko:latest",
        "stdin": true,
        "stdinOnce": true,
        "args": [
          "--dockerfile=Dockerfile",
          "--context=tar://stdin",
          "--destination=gcr.io/my-repo/my-image"
        ],
        "volumeMounts": [
          {
            "name": "cabundle",
            "mountPath": "/kaniko/ssl/certs/"
          },
          {
            "name": "docker-config",
            "mountPath": "/kaniko/.docker/"
          }
        ]
      }
    ],
    "volumes": [
      {
        "name": "cabundle",
        "configMap": {
          "name": "cabundle"
        }
      },
      {
        "name": "docker-config",
        "configMap": {
          "name": "docker-config"
        }
      }
    ]
  }
}'
```

### Running kaniko

There are several different ways to deploy and run kaniko:

- [In a Kubernetes cluster](#running-kaniko-in-a-kubernetes-cluster)
- [In gVisor](#running-kaniko-in-gvisor)
- [In Google Cloud Build](#running-kaniko-in-google-cloud-build)
- [In Docker](#running-kaniko-in-docker)

#### Running kaniko in a Kubernetes cluster

Requirements:

- Standard Kubernetes cluster (e.g. using [GKE](https://cloud.google.com/kubernetes-engine/))
- [Kubernetes Secret](#kubernetes-secret)
- A [build context](#kaniko-build-contexts)

##### Kubernetes secret

To run kaniko in a Kubernetes cluster, you will need a standard running Kubernetes cluster and a Kubernetes secret, which contains the auth required to push the final image.

To create a secret to authenticate to Google Cloud Registry, follow these steps:

1. Create a service account in the Google Cloud Console project you want to push the final image to with `Storage Admin` permissions.
2. Download a JSON key for this service account
3. Rename the key to `kaniko-secret.json`
4. To create the secret, run:

```shell
kubectl create secret generic kaniko-secret --from-file=<path to kaniko-secret.json>
```

_Note: If using a GCS bucket in the same GCP project as a build context, this service account should now also have permissions to read from that bucket._

The Kubernetes Pod spec should look similar to this, with the args parameters filled in:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kaniko
spec:
  containers:
    - name: kaniko
      image: ghcr.io/gosayram/kaniko:latest
      args:
        - "--dockerfile=<path to Dockerfile within the build context>"
        - "--context=gs://<GCS bucket>/<path to .tar.gz>"
        - "--destination=<gcr.io/$PROJECT/$IMAGE:$TAG>"
      volumeMounts:
        - name: kaniko-secret
          mountPath: /secret
      env:
        - name: GOOGLE_APPLICATION_CREDENTIALS
          value: /secret/kaniko-secret.json
  restartPolicy: Never
  volumes:
    - name: kaniko-secret
      secret:
        secretName: kaniko-secret
```

This example pulls the build context from a GCS bucket. To use a local directory build context, you could consider using configMaps to mount in small build contexts.

#### Running kaniko in gVisor

Running kaniko in [gVisor](https://github.com/google/gvisor) provides an additional security boundary. You will need to add the `--force` flag to run kaniko in gVisor, since currently there isn't a way to determine whether or not a container is running in gVisor.

```shell
docker run --runtime=runsc -v $(pwd):/workspace -v ~/.config:/root/.config \
ghcr.io/gosayram/kaniko:latest \
--dockerfile=<path to Dockerfile> --context=/workspace \
--destination=gcr.io/my-repo/my-image --force
```

We pass in `--runtime=runsc` to use gVisor. This example mounts the current directory to `/workspace` for the build context and the `~/.config` directory for GCR credentials.

#### Running kaniko in Google Cloud Build

Requirements:

- A [build context](#kaniko-build-contexts)

To run kaniko in GCB, add it to your build config as a build step:

```yaml
steps:
  - name: ghcr.io/gosayram/kaniko:latest
    args:
      [
        "--dockerfile=<path to Dockerfile within the build context>",
        "--context=dir://<path to build context>",
        "--destination=<gcr.io/$PROJECT/$IMAGE:$TAG>",
      ]
```

kaniko will build and push the final image in this build step.

#### Running kaniko in Docker

Requirements:

- [Docker](https://docs.docker.com/install/)

We can run the kaniko executor image locally in a Docker daemon to build and push an image from a Dockerfile.

For example, when using gcloud and GCR you could run kaniko as follows:

```shell
docker run \
    -v "$HOME"/.config/gcloud:/root/.config/gcloud \
    -v /path/to/context:/workspace \
    ghcr.io/gosayram/kaniko:latest \
    --dockerfile /workspace/Dockerfile \
    --destination "gcr.io/$PROJECT_ID/$IMAGE_NAME:$TAG" \
    --context dir:///workspace/
```

There is also a utility script [`run_in_docker.sh`](./run_in_docker.sh) that can be used as follows:

```shell
./run_in_docker.sh <path to Dockerfile> <path to build context> <destination of final image>
```

_NOTE: `run_in_docker.sh` expects a path to a Dockerfile relative to the absolute path of the build context._

An example run, specifying the Dockerfile in the container directory `/workspace`, the build context in the local directory `/home/user/kaniko-project`, and a Google Container Registry as a remote image destination:

```shell
./run_in_docker.sh /workspace/Dockerfile /home/user/kaniko-project gcr.io/$PROJECT_ID/$TAG
```

### Caching

#### Caching Layers

kaniko can cache layers created by `RUN`(configured by flag `--cache-run-layers`) and `COPY` (configured by flag `--cache-copy-layers`) commands in a remote repository. Before executing a command, kaniko checks the cache for the layer. If it exists, kaniko will pull and extract the cached layer instead of executing the command. If not, kaniko will execute the command and then push the newly created layer to the cache.

Note that kaniko cannot read layers from the cache after a cache miss: once a layer has not been found in the cache, all subsequent layers are built locally without consulting the cache.

Users can opt into caching by setting the `--cache=true` flag. A remote repository for storing cached layers can be provided via the `--cache-repo` flag. If this flag isn't provided, a cached repo will be inferred from the `--destination` provided.

#### Caching Base Images

kaniko can cache images in a local directory that can be volume mounted into the kaniko pod. To do so, the cache must first be populated, as it is read-only. We provide a kaniko cache warming image at `gcr.io/kaniko-project/warmer`:

```shell
docker run -v $(pwd):/workspace gcr.io/kaniko-project/warmer:latest --cache-dir=/workspace/cache --image=<image to cache> --image=<another image to cache>
docker run -v $(pwd):/workspace gcr.io/kaniko-project/warmer:latest --cache-dir=/workspace/cache --dockerfile=<path to dockerfile>
docker run -v $(pwd):/workspace gcr.io/kaniko-project/warmer:latest --cache-dir=/workspace/cache --dockerfile=<path to dockerfile> --build-arg version=1.19
```

`--image` can be specified for any number of desired images. `--dockerfile` can be specified for the path of dockerfile for cache.These command will combined to cache those images by digest in a local directory named `cache`. Once the cache is populated, caching is opted into with the same `--cache=true` flag as above. The location of the local cache is provided via the `--cache-dir` flag, defaulting to `/cache` as with the cache warmer. See the `examples` directory for how to use with kubernetes clusters and persistent cache volumes.

#### 🚀 **ADVANCED CACHING** - Smart Cache Features

Kaniko includes advanced caching capabilities for enterprise-scale builds:

##### **Smart Cache with LRU Eviction**
- **Automatic Preloading** - Popular base images preloaded for faster builds
- **LRU Eviction Policy** - Intelligent cache management with configurable limits
- **Predictive Caching** - Machine learning-based cache optimization
- **Cache Statistics** - Hit rates, miss rates, and performance metrics
- **Multi-Platform Cache** - Separate cache repositories per architecture
- **Background Workers** - Asynchronous cache operations for better performance

##### **Advanced Cache Configuration**
```bash
# Enable smart cache with enhanced features
--enable-smart-cache=true                    # Default: true
--max-cache-entries=3000                      # Maximum cache entries (default: 2000)
--max-preload-size=150                       # Images to preload (default: 100)
--preload-timeout=15m                        # Preload operation timeout (default: 10m)
--cache-ttl=72h                              # Cache time-to-live (default: 2 weeks)

# Connection pooling for registry cache (defaults optimized for performance)
--cache-max-conns=10                         # Max idle connections in pool (default: 10)
--cache-max-conns-per-host=5                 # Max idle connections per host (default: 5)
--cache-max-concurrent-requests=5            # Max concurrent requests (default: 5)
--cache-request-timeout=30s                 # Request timeout (default: 30s)
--cache-disable-http2=false                  # Disable HTTP/2 (default: false, HTTP/2 enabled)

# Aggressive prefetching (improved cache hit rate)
--prefetch-window=10                         # Commands to prefetch (default: 10, increased from 3)

# Result cache (avoids redundant cache lookups)
--cache-result-ttl=5m                        # TTL for cached results (default: 5m)
--cache-result-max-entries=1000              # Max cached results (default: 1000)
--cache-result-max-memory-mb=100             # Max memory for results (default: 100 MB)

# File hash cache (avoids recomputing file hashes)
--file-hash-cache-max-entries=10000          # Max cached file hashes (default: 10000)
--file-hash-cache-max-memory-mb=200          # Max memory for file hashes (default: 200 MB)

# Parallel layer loading
--max-concurrent-cache-checks=5              # Concurrent cache checks (default: 5)
--layer-load-max-concurrent=3                # Concurrent layer loads (default: 3)

# Predictive caching (experimental)
--enable-predictive-cache=false              # Enable predictive caching (default: false)
--predictive-cache-max-layers=20             # Max layers to prefetch (default: 20)
--predictive-cache-max-memory-mb=50          # Max memory for prefetching (default: 50 MB)

# Local cache optimizations (experimental)
--local-cache-use-mmap=false                 # Use memory-mapped files (default: false)
--local-cache-compress=false                 # Compress local cache files (default: false)
--local-cache-compression=zstd               # Compression algorithm (default: zstd)

# Compression
--compressed-caching=true                    # Enable compression (default: true)
--compression=zstd                           # Compression algorithm (default: zstd)
--compression-level=3                        # Compression level (default: 3)
```

##### **Cache Performance Optimization**
- **40-60% Better Cache Utilization** compared to basic cache
- **HTTP Connection Pooling** - Reuses connections to registry for faster cache operations (default: 10 max connections, 5 per host)
- **Result Caching** - Caches cache check results to avoid redundant lookups (default: 1000 entries, 100 MB, 5m TTL)
- **File Hash Caching** - Avoids recomputing file hashes (default: 10000 entries, 200 MB)
- **Batch Layer Retrieval** - Parallel layer loading for improved throughput (default: 3 concurrent loads)
- **Aggressive Prefetching** - Prefetches next 10 commands (increased from 3) for better cache hit rate
- **Automatic Cache Warming** for frequently used images
- **Intelligent Cache Policies** based on build patterns
- **Memory-Efficient Caching** with configurable limits
- **Cache Integrity Checks** to ensure data consistency
- **Parallel Cache Operations** for improved throughput
- **Cache Compression** with multiple algorithms (gzip, zstd)
- **Cache Validation** with checksums and integrity verification
- **Predictive Caching** (experimental) - Prefetches layers based on build history patterns

##### **Multi-Platform Cache Support**
```bash
# Architecture-specific cache repositories
--arch-cache-repo-suffix=-${ARCH}  # Separate cache per architecture
--cache-repo=myregistry.com/cache   # Base cache repository
```

##### **Cache Monitoring & Analytics**
- **Real-time Cache Statistics** - Hit rates, miss rates, and performance
- **Cache Size Monitoring** - Automatic cleanup when limits exceeded
- **Build Performance Tracking** - Cache impact on build times
- **Optimization Recommendations** - Automated cache tuning suggestions
- **Cache Health Monitoring** - Proactive cache maintenance and cleanup
- **Performance Dashboards** - Visual cache performance metrics
- **Cache Usage Patterns** - Analysis of cache access patterns
- **Automated Cache Optimization** - Self-tuning cache parameters

### Pushing to Different Registries

kaniko uses Docker credential helpers to push images to a registry.

kaniko comes with support for GCR, Docker `config.json` and Amazon ECR, but configuring another credential helper should allow pushing to a different registry.

#### Pushing to Docker Hub

Get your docker registry user and password encoded in base64

    echo -n USER:PASSWORD | base64

Create a `config.json` file with your Docker registry url and the previous generated base64 string

**Note:** Please use v1 endpoint. See #1209 for more details

```json
{
  "auths": {
    "https://index.docker.io/v1/": {
      "auth": "xxxxxxxxxxxxxxx"
    }
  }
}
```

Run kaniko with the `config.json` inside `/kaniko/.docker/config.json`

```shell
docker run -ti --rm -v `pwd`:/workspace -v `pwd`/config.json:/kaniko/.docker/config.json:ro ghcr.io/gosayram/kaniko:latest --dockerfile=Dockerfile --destination=yourimagename
```

#### Pushing to Google GCR

To create a credentials to authenticate to Google Cloud Registry, follow these steps:

1. Create a [service account](https://console.cloud.google.com/iam-admin/serviceaccounts) or in the Google Cloud Console project you want to push the final image to with `Storage Admin` permissions.
2. Download a JSON key for this service account
3. (optional) Rename the key to `kaniko-secret.json`, if you don't rename, you have to change the name used the command(in the volume part)
4. Run the container adding the path in GOOGLE_APPLICATION_CREDENTIALS env var

```shell
docker run -ti --rm -e GOOGLE_APPLICATION_CREDENTIALS=/kaniko/config.json \
-v `pwd`:/workspace -v `pwd`/kaniko-secret.json:/kaniko/config.json:ro ghcr.io/gosayram/kaniko:latest \
--dockerfile=Dockerfile --destination=yourimagename
```

#### Pushing to GCR using Workload Identity

If you have enabled Workload Identity on your GKE cluster then you can use the workload identity to push built images to GCR without adding a `GOOGLE_APPLICATION_CREDENTIALS` in your kaniko pod specification.

Learn more on how to [enable](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity#enable_on_cluster) and [migrate existing apps](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity#migrate_applications_to) to workload identity.

To authenticate using workload identity you need to run the kaniko pod using the Kubernetes Service Account (KSA) bound to Google Service Account (GSA) which has `Storage.Admin` permissions to push images to Google Container registry.

Please follow the detailed steps [here](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity#authenticating_to) to create a Kubernetes Service Account, Google Service Account and create an IAM policy binding between the two to allow the Kubernetes Service account to act as the Google service account.

To grant the Google Service account the right permission to push to GCR, run the following GCR command

```
gcloud projects add-iam-policy-binding $PROJECT \
  --member=serviceAccount:[gsa-name]@${PROJECT}.iam.gserviceaccount.com \
  --role=roles/storage.objectAdmin
```

Please ensure, kaniko pod is running in the namespace and with a Kubernetes Service Account.

#### Pushing to Amazon ECR

The Amazon ECR [credential helper](https://github.com/awslabs/amazon-ecr-credential-helper) is built into the kaniko executor image.

1. Configure credentials

   1. You can use instance roles when pushing to ECR from a EC2 instance or from EKS, by [configuring the instance role permissions](https://docs.aws.amazon.com/AmazonECR/latest/userguide/ECR_on_EKS.html) (the AWS managed policy `EC2InstanceProfileForImageBuilderECRContainerBuilds` provides broad permissions to upload ECR images and may be used as configuration baseline). Additionally, set `AWS_SDK_LOAD_CONFIG=true` as environment variable within the kaniko pod. If running on an EC2 instance with an instance profile, you may also need to set `AWS_EC2_METADATA_DISABLED=true` for kaniko to pick up the correct credentials.

   2. Or you can create a Kubernetes secret for your `~/.aws/credentials` file so that credentials can be accessed within the cluster. To create the secret, run: `shell kubectl create secret generic aws-secret --from-file=<path to .aws/credentials> `

The Kubernetes Pod spec should look similar to this, with the args parameters filled in. Note that `aws-secret` volume mount and volume are only needed when using AWS credentials from a secret, not when using instance roles.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kaniko
spec:
  containers:
    - name: kaniko
      image: ghcr.io/gosayram/kaniko:latest
      args:
        - "--dockerfile=<path to Dockerfile within the build context>"
        - "--context=s3://<bucket name>/<path to .tar.gz>"
        - "--destination=<aws_account_id.dkr.ecr.region.amazonaws.com/my-repository:my-tag>"
      volumeMounts:
        # when not using instance role
        - name: aws-secret
          mountPath: /root/.aws/
  restartPolicy: Never
  volumes:
    # when not using instance role
    - name: aws-secret
      secret:
        secretName: aws-secret
```

#### Pushing to Azure Container Registry

An ACR [credential helper](https://github.com/chrismellard/docker-credential-acr-env) is built into the kaniko executor image, which can be used to authenticate with well-known Azure environmental information.

To configure credentials, you will need to do the following:

1. Update the `credStore` section of `config.json`:

```json
{ "credsStore": "acr" }
```

A downside of this approach is that ACR authentication will be used for all registries, which will fail if you also pull from DockerHub, GCR, etc. Thus, it is better to configure the credential tool only for your ACR registries by using `credHelpers` instead of `credsStore`:

```json
{ "credHelpers": { "mycr.azurecr.io": "acr-env" } }
```

You can mount in the new config as a configMap:

```shell
kubectl create configmap docker-config --from-file=<path to config.json>
```

2. Configure credentials

You can create a Kubernetes secret with environment variables required for Service Principal authentication and expose them to the builder container.

```
AZURE_CLIENT_ID=<clientID>
AZURE_CLIENT_SECRET=<clientSecret>
AZURE_TENANT_ID=<tenantId>
```

If the above are not set then authentication falls back to managed service identities and the MSI endpoint is attempted to be contacted which will work in various Azure contexts such as App Service and Azure Kubernetes Service where the MSI endpoint will authenticate the MSI context the service is running under.

The Kubernetes Pod spec should look similar to this, with the args parameters filled in. Note that `azure-secret` secret is only needed when using Azure Service Principal credentials, not when using a managed service identity.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: kaniko
spec:
  containers:
    - name: kaniko
      image: ghcr.io/gosayram/kaniko:latest
      args:
        - "--dockerfile=<path to Dockerfile within the build context>"
        - "--context=s3://<bucket name>/<path to .tar.gz>"
        - "--destination=mycr.azurecr.io/my-repository:my-tag"
      envFrom:
        # when authenticating with service principal
        - secretRef:
            name: azure-secret
      volumeMounts:
        - name: docker-config
          mountPath: /kaniko/.docker/
  volumes:
    - name: docker-config
      configMap:
        name: docker-config
  restartPolicy: Never
```

#### Pushing to JFrog Container Registry or to JFrog Artifactory

Kaniko can be used with both [JFrog Container Registry](https://www.jfrog.com/confluence/display/JFROG/JFrog+Container+Registry) and JFrog Artifactory.

Get your JFrog Artifactory registry user and password encoded in base64

    echo -n USER:PASSWORD | base64

Create a `config.json` file with your Artifactory Docker local registry URL and the previous generated base64 string

```json
{
  "auths": {
    "artprod.company.com": {
      "auth": "xxxxxxxxxxxxxxx"
    }
  }
}
```

For example, for Artifactory cloud users, the docker registry should be: `<company>.<local-repository-name>.io`.

Run kaniko with the `config.json` inside `/kaniko/.docker/config.json`

    docker run -ti --rm -v `pwd`:/workspace -v `pwd`/config.json:/kaniko/.docker/config.json:ro ghcr.io/gosayram/kaniko:latest --dockerfile=Dockerfile --destination=yourimagename

After the image is uploaded, using the JFrog CLI, you can [collect](https://www.jfrog.com/confluence/display/CLI/CLI+for+JFrog+Artifactory#CLIforJFrogArtifactory-PushingDockerImagesUsingKaniko) and [publish](https://www.jfrog.com/confluence/display/CLI/CLI+for+JFrog+Artifactory#CLIforJFrogArtifactory-PublishingBuild-Info) the build information to Artifactory and trigger [build vulnerabilities scanning](https://www.jfrog.com/confluence/display/JFROG/Declarative+Pipeline+Syntax#DeclarativePipelineSyntax-ScanningBuildswithJFrogXray) using JFrog Xray.

To collect and publish the image's build information using the Jenkins Artifactory plugin, see instructions for [scripted pipeline](https://www.jfrog.com/confluence/display/JFROG/Scripted+Pipeline+Syntax#ScriptedPipeline+Syntax-UsingKaniko) and [declarative pipeline](https://www.jfrog.com/confluence/display/JFROG/Declarative+Pipeline+Syntax#DeclarativePipeline+Syntax-UsingKaniko).

### Additional Flags

#### Flag `--build-arg`

This flag allows you to pass in ARG values at build time, similarly to Docker. You can set it multiple times for multiple arguments.

Note that passing values that contain spaces is not natively supported - you need to ensure that the IFS is set to null before your executor command. You can set this by adding `export IFS=''` before your executor call. See the following example

```bash
export IFS=''
/kaniko/executor --build-arg "MY_VAR='value with spaces'" ...
```

**Predefined Build Arguments**: Kaniko automatically provides the following predefined build arguments that are available in your Dockerfile:

- `BUILDPLATFORM` - Platform of the build machine (e.g., `linux/amd64`)
- `BUILDOS` - Operating system of the build machine (e.g., `linux`)
- `BUILDOSVERSION` - OS version of the build machine
- `BUILDARCH` - Architecture of the build machine (e.g., `amd64`)
- `BUILDVARIANT` - Variant of the build architecture (e.g., `v7` for ARM)
- `TARGETPLATFORM` - Platform of the target image (e.g., `linux/arm64`)
- `TARGETOS` - Operating system of the target image (e.g., `linux`)
- `TARGETOSVERSION` - OS version of the target image
- `TARGETARCH` - Architecture of the target image (e.g., `arm64`)
- `TARGETVARIANT` - Variant of the target architecture
- `TARGETSTAGE` - Name of the target build stage (or `default` if not specified)

These predefined arguments are automatically initialized and can be used in your Dockerfile ARG instructions. They are particularly useful for multi-platform builds and conditional logic based on build or target platform.

**Example Dockerfile usage**:
```dockerfile
ARG TARGETPLATFORM
ARG TARGETARCH
RUN echo "Building for ${TARGETPLATFORM} with architecture ${TARGETARCH}"
```

#### Flag `--cache`

Set this flag as `--cache=true` to opt into caching with kaniko.

#### Flag `--cache-dir`

Set this flag to specify a local directory cache for base images. Defaults to `/cache`.

_This flag must be used in conjunction with the `--cache=true` flag._

#### Flag `--cache-repo`

Set this flag to specify a remote repository that will be used to store cached layers.

If this flag is not provided, a cache repo will be inferred from the `--destination` flag. If `--destination=gcr.io/kaniko-project/test`, then cached layers will be stored in `gcr.io/kaniko-project/test/cache`.

_This flag must be used in conjunction with the `--cache=true` flag._

#### Flag `--cache-copy-layers`

Set this flag to cache copy layers.

#### Flag `--cache-run-layers`

Set this flag to cache run layers (default=true).

#### Flag `--cache-ttl duration`

Cache timeout in hours. Defaults to two weeks.

#### Flag `--cleanup`

Set this flag to clean the filesystem at the end of the build.

#### Flag `--compressed-caching`

Set this to false in order to prevent tar compression for cached layers. This will increase the runtime of the build, but decrease the memory usage especially for large builds. Try to use `--compressed-caching=false` if your build fails with an out of memory error. Defaults to true.

#### Flag `--context-sub-path`

Set a sub path within the given `--context`.

Its particularly useful when your context is, for example, a git repository, and you want to build one of its subfolders instead of the root folder.

#### Flag `--custom-platform`

Allows to build with another default platform than the host, similarly to docker build --platform xxx the value has to be on the form `--custom-platform=linux/arm`, with acceptable values listed here: [GOOS/GOARCH](https://gist.github.com/asukakenji/f15ba7e588ac42795f421b48b8aede63).

It's also possible specifying CPU variants adding it as a third parameter (like `--custom-platform=linux/arm/v5`). Currently CPU variants are only known to be used for the ARM architecture as listed here: [GOARM](https://go.dev/wiki/GoArm#supported-architectures)

_The resulting images cannot provide any metadata about CPU variant due to a limitation of the OCI-image specification._

_This is not virtualization and cannot help to build an architecture not natively supported by the build host. This is used to build i386 on an amd64 Host for example, or arm32 on an arm64 host._

#### Flag `--default-user`

Set this flag to specify the default user when no USER instruction is present in the Dockerfile. 

**Default behavior (without flag):**
- If no user is specified in the Dockerfile or base image, Kaniko automatically sets `kaniko:kaniko` as the default user for security
- This ensures builds run with minimal privileges by default

**Examples:**
- No flag specified - Uses secure default `kaniko:kaniko` (recommended)
- `--default-user=root` - Use root as the default user (⚠️ **SECURITY RISK**)
- `--default-user=appuser` - Use a specific user as default
- `--default-user=nobody` - Use nobody as the default user

**Use cases:**
- Dockerfiles that need to install system packages or modify system files (use `--default-user=root`)
- Builds that require root privileges for certain operations
- Legacy Dockerfiles that don't specify USER instructions

**⚠️ SECURITY WARNING:**
- **NEVER use `--default-user=root` in production environments**
- **Always specify a non-root user in your Dockerfile with `USER` instruction**
- **Not specifying a user or overriding it with root is considered unsafe and prohibited in production**
- **This flag should only be used for development or legacy builds that cannot be modified**
- **By default, Kaniko uses `kaniko:kaniko` for security when no user is specified**

**Note:** This flag only applies when the base image doesn't have a user set. If the Dockerfile contains a `USER` instruction, it takes precedence over this flag.

#### Flag `--digest-file`

Set this flag to specify a file in the container. This file will receive the digest of a built image. This can be used to automatically track the exact image built by kaniko.

For example, setting the flag to `--digest-file=/dev/termination-log` will write the digest to that file, which is picked up by Kubernetes automatically as the `{{.state.terminated.message}}` of the container.

#### Flag `--dockerfile`

Path to the dockerfile to be built. (default "Dockerfile")

#### Flag `--force`

Force building outside of a container

#### Flag `--git`

Branch to clone if build context is a git repository (default branch=,single-branch=false,recurse-submodules=false,insecure-skip-tls=false)

#### Flag `--image-name-with-digest-file`

Specify a file to save the image name w/ digest of the built image to.

#### Flag `--image-name-tag-with-digest-file`

Specify a file to save the image name w/ image tag and digest of the built image to.

#### Flag `--insecure`

Set this flag if you want to push images to a plain HTTP registry. It is supposed to be used for testing purposes only and should not be used in production!

#### Flag `--insecure-pull`

Set this flag if you want to pull images from a plain HTTP registry. It is supposed to be used for testing purposes only and should not be used in production!

#### Flag `--insecure-registry`

You can set `--insecure-registry <registry-name>` to use plain HTTP requests when accessing the specified registry. It is supposed to be used for testing purposes only and should not be used in production! You can set it multiple times for multiple registries.

#### Flag `--label`

Set this flag as `--label key=value` to set some metadata to the final image. This is equivalent as using the `LABEL` within the Dockerfile.

#### Flag `--log-format`

Set this flag as `--log-format=<text|color|json>` to set the log format. Defaults to `color`.

#### Flag `--log-timestamp`

Set this flag as `--log-timestamp=<true|false>` to add timestamps to `<text|color>` log format. Defaults to `false`.

#### Flag `--no-push`

Set this flag if you only want to build the image, without pushing to a registry. This can also be defined through `KANIKO_NO_PUSH` environment variable.

NOTE: this will still push cache layers to the repo, to disable pushing cache layers use `--no-push-cache`

#### Flag `--no-push-cache`

Set this flag if you do not want to push cache layers to a registry. Can be used in addition to `--no-push` to push no layers to a registry.

#### Flag `--oci-layout-path`

Set this flag to specify a directory in the container where the OCI image layout of a built image will be placed. This can be used to automatically track the exact image built by kaniko.

For example, to surface the image digest built in a [Tekton task](https://github.com/tektoncd/pipeline/blob/v0.6.0/docs/resources.md#surfacing-the-image-digest-built-in-a-task), this flag should be set to match the image resource `outputImageDir`.

_Note: Depending on the built image, the media type of the image manifest might be either `application/vnd.oci.image.manifest.v1+json` or `application/vnd.docker.distribution.manifest.v2+json`._

#### Flag `--push-ignore-immutable-tag-errors`

Set this boolean flag to `true` if you want the Kaniko process to exit with success when a push error related to tag immutability occurs.

This is useful for example if you have parallel builds pushing the same tag and do not care which one actually succeeds.

Defaults to `false`.

#### Flag `--multi-platform`

Set this flag to specify a comma-separated list of target platforms for multi-architecture builds. For example: `--multi-platform=linux/amd64,linux/arm64`. This enables native multi-platform coordination without privileged operations.

#### Flag `--driver`

Set this flag to specify the execution driver for multi-architecture builds. Options: `local` (single architecture, host only), `k8s` (Kubernetes cluster with native nodes), `ci` (CI aggregation mode). Defaults to `local`.

#### Flag `--publish-index`

Set this boolean flag to `true` to publish an OCI Image Index after completing multi-architecture builds. This creates a manifest that references all platform-specific images. Defaults to `false`.

#### Flag `--legacy-manifest-list`

Set this boolean flag to `true` to create a Docker Manifest List for backward compatibility in addition to the OCI Image Index. Defaults to `false`.

#### Flag `--index-annotations`

Set this flag to add key-value annotations to the OCI Image Index. Format: `--index-annotations=key=value,key2=value2`. Useful for adding custom metadata to multi-arch manifests.

#### Flag `--arch-cache-repo-suffix`

Set this flag to specify a suffix for per-architecture cache repositories. Format: `--arch-cache-repo-suffix=-${ARCH}`. This enables separate cache repositories for each architecture.

#### Flag `--digests-from`

Set this flag to specify a path to digest files for CI driver integration. Format: `--digests-from=/path/to/digests`. Used in CI mode to collect digests from separate builds.

#### Flag `--require-native-nodes`

Set this boolean flag to `true` to fail if non-native architecture is requested. This ensures builds only run on nodes with the correct architecture support. Defaults to `true`.

#### Flag `--oci-mode`

Set this flag to specify OCI compliance mode. Options: `oci` (strict OCI 1.1 compliance), `auto` (automatic detection), `docker` (Docker format). Defaults to `auto`.

#### Flag `--compression`

Set this flag to specify layer compression format. Options: `gzip` (default), `zstd` (better compression ratio). Format: `--compression=zstd`.

#### Flag `--compression-level`

Set this flag to specify the compression level. Format: `--compression-level=<level>`. Default: `-1` (uses default compression level for the selected algorithm). Valid range depends on the compression algorithm.

#### Flag `--push-retry`

Set this flag to the number of retries that should happen for the push of an image to a remote destination. Defaults to `0`.

#### Flag `--push-retry-initial-delay`

Set this flag to specify the initial delay in milliseconds before the first retry attempt. Format: `--push-retry-initial-delay=1000`. Consecutive retries use exponential backoff. Defaults to `1000` milliseconds (1 second).

#### Flag `--push-retry-max-delay`

Set this flag to specify the maximum delay in milliseconds between retry attempts. Format: `--push-retry-max-delay=30000`. This caps the exponential backoff growth. Defaults to `30000` milliseconds (30 seconds).

#### Flag `--push-retry-backoff-multiplier`

Set this flag to specify the exponential backoff multiplier for retry delays. Format: `--push-retry-backoff-multiplier=2.0`. Higher values increase delay growth between retries. Defaults to `2.0`.

#### Flag `--registry-certificate`

Set this flag to provide a certificate for TLS communication with a given registry.

Expected format is `my.registry.url=/path/to/the/certificate.cert`

#### Flag `--registry-client-cert`

Set this flag to provide a certificate/key pair for mutual TLS (mTLS) communication with a given [registry that requires mTLS](https://docs.docker.com/engine/security/certificates/) for authentication.

Expected format is `my.registry.url=/path/to/client/cert.crt,/path/to/client/key.key`

#### Flag `--registry-map`

Set this flag if you want to remap registries references. Usefull for air gap environement for example. You can use this flag more than once, if you want to set multiple mirrors for a given registry. You can mention several remap in a single flag too, separated by semi-colon. If an image is not found on the first mirror, Kaniko will try the next mirror(s), and at the end fallback on the original registry.

Registry maps can also be defined through `KANIKO_REGISTRY_MAP` environment variable.

Expected format is `original-registry=remapped-registry[;another-reg=another-remap[;...]]` for example.

Note that you **can** specify a URL with scheme for this flag. Some valid options are:

- `index.docker.io=mirror.gcr.io`
- `gcr.io=127.0.0.1`
- `quay.io=192.168.0.1:5000`
- `index.docker.io=docker-io.mirrors.corp.net;index.docker.io=mirror.gcr.io;gcr.io=127.0.0.1` will try `docker-io.mirrors.corp.net` then `mirror.gcr.io` for `index.docker.io` and `127.0.0.1` for `gcr.io`
- `docker.io=harbor.provate.io/theproject`

#### Flag `--registry-mirror`

Set this flag if you want to use a registry mirror instead of the default `index.docker.io`. You can use this flag more than once, if you want to set multiple mirrors. If an image is not found on the first mirror, Kaniko will try the next mirror(s), and at the end fallback on the default registry.

Mirror can also be defined through `KANIKO_REGISTRY_MIRROR` environment variable.

Expected format is `mirror.gcr.io` or `mirror.gcr.io/path` for example.

Note that you **can** specify a URL with scheme for this flag. Some valid options are:

- `mirror.gcr.io`
- `127.0.0.1`
- `192.168.0.1:5000`
- `mycompany-docker-virtual.jfrog.io`
- `harbor.provate.io/theproject`

#### Flag `--skip-default-registry-fallback`

Set this flag if you want the build process to fail if none of the mirrors listed in flag [registry-mirror](#flag---registry-mirror) can pull some image. This should be used with mirrors that implements a whitelist or some image restrictions.

If [registry-mirror](#flag---registry-mirror) is not set or is empty, this flag is ignored.

#### Flag `--credential-helpers`

Set this flag to selectively enable credential helpers for registry authentication. You can specify multiple helpers by setting the flag repeatedly. Available helpers: `env`, `google`, `ecr`, `acr`, `gitlab`.

**Default behavior**: If not specified, all available credential helpers are used.

**Examples**:
- `--credential-helpers=env` - Use only environment-based credentials
- `--credential-helpers=google --credential-helpers=ecr` - Use Google and ECR helpers
- `--credential-helpers=""` - Disable all credential helpers

**Supported helpers**:
- `env` - Environment variable-based credentials (DOCKER_USERNAME, DOCKER_PASSWORD, etc.)
- `google` - Google Container Registry credentials
- `ecr` - Amazon ECR credentials
- `acr` - Azure Container Registry credentials
- `gitlab` - GitLab Container Registry credentials

#### Flag `--reproducible`

Set this flag to strip timestamps out of the built image and make it reproducible.

#### Flag `--single-snapshot`

This flag takes a single snapshot of the filesystem at the end of the build, so only one layer will be appended to the base image.

#### Flag `--skip-push-permission-check`

Set this flag to skip push permission check. This can be useful to delay Kanikos first request for delayed network-policies.

#### Flag `--skip-tls-verify`

Set this flag to skip TLS certificate validation when pushing to a registry. It is supposed to be used for testing purposes only and should not be used in production!

#### Flag `--skip-tls-verify-pull`

Set this flag to skip TLS certificate validation when pulling from a registry. It is supposed to be used for testing purposes only and should not be used in production!

#### Flag `--skip-tls-verify-registry`

You can set `--skip-tls-verify-registry <registry-name>` to skip TLS certificate validation when accessing the specified registry. It is supposed to be used for testing purposes only and should not be used in production! You can set it multiple times for multiple registries.

#### Flag `--skip-unused-stages`

This flag builds only used stages if defined to `true`. Otherwise it builds by default all stages, even the unnecessary ones until it reaches the target stage / end of Dockerfile

#### Flag `--snapshot-mode`

You can set the `--snapshot-mode=<full (default), redo, time>` flag to set how kaniko will snapshot the filesystem.

- If `--snapshot-mode=full` is set, the full file contents and metadata are considered when snapshotting. This is the least performant option, but also the most robust.

- If `--snapshot-mode=redo` is set, the file mtime, size, mode, owner uid and gid will be considered when snapshotting. This may be up to 50% faster than "full", particularly if your project has a large number files.

- If `--snapshot-mode=time` is set, only file mtime will be considered when snapshotting (see [limitations related to mtime](#mtime-and-snapshotting)).

#### Flag `--tar-path`

Set this flag as `--tar-path=<path>` to save the image as a tarball at path. You need to set `--destination` as well (for example `--destination=image`). If you want to save the image as tarball only you also need to set `--no-push`.

#### Flag `--target`

Set this flag to indicate which build stage is the target build stage.

#### Flag `--use-new-run`

Using this flag enables an experimental implementation of the Run command which does not rely on snapshotting at all. In this approach, in order to compute which files were changed, a marker file is created before executing the Run command. Then the entire filesystem is walked (takes ~1-3 seconds for 700Kfiles) to find all files whose ModTime is greater than the marker file. With this new run command implementation, the total build time is reduced seeing performance improvements in the range of ~75%. This new run mode trades off accuracy/correctness in some cases (potential for missed files in a "snapshot") for improved performance by avoiding the full filesystem snapshots.

#### Flag `--preserve-context`

Set this flag to preserve build context across build stages by taking a snapshot of the full filesystem before build and restoring it after switching stages. The context is also restored at the end if used together with `--cleanup`.

This is useful for multi-stage builds where you need to maintain the build context across different stages, especially when stages modify the filesystem in ways that need to be preserved.

**Example**: `--preserve-context` - Preserves build context across all stages

#### Flag `--use-oci-stages`

Set this flag to use OCI image layout for intermediate stages instead of tarballs. This improves performance and OCI compatibility. Can also be enabled via `FF_KANIKO_OCI_STAGES` environment variable.

**Benefits**:
- Better performance for multi-stage builds
- Improved OCI compliance
- More efficient storage of intermediate stages

**Example**: `--use-oci-stages` or set `FF_KANIKO_OCI_STAGES=true`

#### Flag `--materialize`

Set this flag to guarantee that the final state of the filesystem corresponds to what was specified as the build target, even if we have 100% cache hit rate and wouldn't need to unpack any layers.

This ensures that the final image filesystem is fully materialized, which is important for:
- Verifying the final image state
- Ensuring all files are present even with perfect cache hits
- Debugging and validation scenarios

**Example**: `--materialize` - Forces filesystem materialization for final stage

#### Flag `--pre-cleanup`

Set this flag to clean the filesystem prior to build, allowing customized kaniko images to work properly. This is useful when you need a clean filesystem state before starting the build process.

**Use cases**:
- Custom kaniko images with pre-existing files
- Ensuring clean build environment
- Debugging filesystem-related issues

**Example**: `--pre-cleanup` - Cleans filesystem before build starts

#### Flag `--verbosity`

Set this flag as `--verbosity=<panic|fatal|error|warn|info|debug|trace>` to set the logging level. Defaults to `info`.

#### Flag `--ignore-var-run`

Ignore /var/run when taking image snapshot. Set it to false to preserve /var/run/* in destination image. (Default true).

#### Flag `--ignore-path`

Set this flag as `--ignore-path=<path>` to ignore path when taking an image snapshot. Set it multiple times for multiple ignore paths.

#### Flag `--kaniko-dir`

Set this flag to specify the path to the kaniko directory. This takes precedence over the `KANIKO_DIR` environment variable. Defaults to `/kaniko`.

#### Flag `--force-build-metadata`

Set this boolean flag to `true` to force add metadata layers to the build image. Defaults to `false`.

#### Flag `--max-file-size`

Set this flag to specify the maximum size for individual files (e.g., `500MB`, `1GB`). Default: `500MB`. This helps prevent processing of extremely large files that could cause memory issues.

#### Flag `--max-tar-file-size`

Set this flag to specify the maximum size for files in tar archives (e.g., `5GB`, `10GB`). Default: `5GB`. This helps prevent processing of extremely large tar files.

#### Flag `--max-total-archive-size`

Set this flag to specify the maximum total size for all files in an archive (e.g., `10GB`, `20GB`). Default: `10GB`. This helps prevent out-of-memory errors with very large build contexts.

#### Flag `--enable-unified-cache`

Set this boolean flag to `true` to enable unified cache for combining multiple cache sources (local, registry, S3, etc.). Defaults to `false`.

#### Flag `--optimize-execution-order`

Set this boolean flag to use dependency graph to optimize command execution order. When enabled, Kaniko builds an LLB graph and uses a scheduler to optimize execution order and merge identical operations. This provides BuildKit-style optimization. Defaults to `true`.

**Example**: `--optimize-execution-order=true`

#### Flag `--enable-lazy-image-loading`

Set this boolean flag to `true` to load image layers on demand for memory optimization. When enabled, layers are loaded only when needed, reducing memory usage for large images. Defaults to `true`.

**Example**: `--enable-lazy-image-loading=true`

### Debug Flags

Kaniko provides comprehensive debug flags for troubleshooting and development:

#### Flag `--debug-full`

Enable comprehensive debug logging for all components. When enabled, all debug flags are activated. Defaults to `false`.

#### Flag `--debug-build-steps`

Debug individual build steps and commands. Provides detailed logging for each Dockerfile command execution. Defaults to `false`.

#### Flag `--debug-multi-platform`

Debug multi-platform build coordination. Provides detailed logging for multi-architecture build coordination. Defaults to `false`.

#### Flag `--debug-oci`

Debug OCI index and manifest operations. Provides detailed logging for OCI compliance operations. Defaults to `false`.

#### Flag `--debug-drivers`

Debug driver operations (local, k8s, ci). Provides detailed logging for execution driver operations. Defaults to `false`.

#### Flag `--debug-filesystem`

Debug filesystem operations and snapshots. Provides detailed logging for filesystem scanning and snapshot operations. Defaults to `false`.

#### Flag `--debug-cache`

Debug cache operations and layer management. Provides detailed logging for cache hit/miss and layer management. Defaults to `false`.

#### Flag `--debug-registry`

Debug registry push/pull operations. Provides detailed logging for registry communication. Defaults to `false`.

#### Flag `--debug-signing`

Debug image signing operations. Provides detailed logging for cosign signing operations. Defaults to `false`.

#### Flag `--debug-output-files`

Output debug information to files. When enabled, debug information is written to files for later analysis. Defaults to `false`.

#### Flag `--debug-level`

Set the debug log level. Options: `trace`, `debug`, `info`. Defaults to `debug`.

#### Flag `--debug-components`

Specify specific components to debug (comma-separated). Allows fine-grained control over which components produce debug output. Defaults to empty (all components).

**Example**: `--debug-components=filesystem,cache`

**Note**: Debug flags can also be configured via environment variables:
- `KANIKO_DEBUG=true` - Enable full debug mode
- `KANIKO_DEBUG_LEVEL=<level>` - Set debug log level
- `KANIKO_DEBUG_COMPONENTS=<components>` - Set debug components (comma-separated)

### Environment Variables

Kaniko supports several environment variables for configuration:

#### Build Configuration

- `FF_KANIKO_OCI_STAGES` - Enable OCI image layout for intermediate stages instead of tarballs. Set to `true`, `1`, `yes`, or `on` to enable. This is equivalent to using the `--use-oci-stages` flag.

#### Network Configuration

- `FF_KANIKO_DISABLE_HTTP2` - Disable HTTP/2.0 for compatibility with registries that don't support it. Set to `true`, `1`, `yes`, or `on` to disable HTTP/2 and force HTTP/1.1. This is useful when working with registries that have issues with HTTP/2 protocol.

#### Timeout Configuration

The following environment variables control timeouts for various operations to prevent hangs and improve reliability:

- `RESOLVE_SOURCES_TIMEOUT` - Timeout for resolving source files during build context initialization. Defaults to `5m`. Format: `5m`, `10m`, `30m`.
- `DIRECTORY_SCAN_TIMEOUT` - Timeout for directory scanning operations. Defaults to `10m`. Format: `10m`, `15m`, `30m`.
- `IMAGE_RETRIEVE_TIMEOUT` - Timeout for retrieving images from remote registries. Defaults to `15m`. Format: `15m`, `30m`, `1h`.
- `REMOTE_CACHE_TIMEOUT` - Timeout for remote cache operations. Defaults to `5m`. Format: `5m`, `10m`, `15m`.
- `HASH_DIR_TIMEOUT` - Timeout for directory hashing operations. Defaults to `10m`. Format: `10m`, `15m`, `30m`.

**Internal Timeout Constants** (configured in code, not via environment variables):

- **Prefetch Operations**: 5 minutes - Timeout for prefetch key calculation
- **Files Used from Context**: 2 minutes - Timeout for resolving files used by commands
- **Populate Cache Key**: 5 minutes - Timeout for populating composite cache keys
- **Cache Key Computation**: 10 minutes - Timeout for overall cache key computation
- **Process Command**: 15 minutes - Timeout for processing individual commands
- **Directory Walk**: 5 minutes - Timeout for walking directory structures
- **Find Similar Paths**: 3 minutes - Timeout for finding similar file paths
- **Find Build Output**: 3 minutes - Timeout for finding build output directories
- **Resolve Environment**: 5 minutes - Timeout for resolving environment variables and wildcards
- **File Hashing**: 30 seconds - Timeout for hashing individual files
- **Max Push Timeout**: 5 minutes - Maximum timeout for push operations to prevent conflicts

**Example**:
```bash
export FF_KANIKO_OCI_STAGES=true
export FF_KANIKO_DISABLE_HTTP2=true
export RESOLVE_SOURCES_TIMEOUT=10m
export DIRECTORY_SCAN_TIMEOUT=15m
export IMAGE_RETRIEVE_TIMEOUT=30m
export REMOTE_CACHE_TIMEOUT=10m
export HASH_DIR_TIMEOUT=15m
```

#### Resource Limits Configuration

- `MAX_FILES_PROCESSED` - Maximum number of files to process during directory scanning. Defaults to `1000000` (1M files). This helps prevent resource exhaustion on very large projects. When the limit is exceeded, Kaniko automatically falls back to a standard filesystem walk.

**Example**:
```bash
export MAX_FILES_PROCESSED=2000000
```

#### Directory Hashing Configuration

- `USE_ADAPTIVE_DIR_HASH` - Enable adaptive directory hashing strategy for better performance on large monorepos. Defaults to `true`. When enabled:
  - Small files (<10MB) are hashed using full content hashing for maximum accuracy
  - Large files (>=10MB) are hashed using metadata-only (mtime, size, mode, uid, gid) for better performance
  - Directories with >1000 files use metadata-only hashing for all files
  - This can improve directory hashing performance by 10-100x for large projects
  - Set to `false` to use the legacy timeout-based hashing approach

**Example**:
```bash
export USE_ADAPTIVE_DIR_HASH=true
```

#### Registry Configuration

- `KANIKO_NO_PUSH` - Equivalent to `--no-push` flag. Set to disable pushing images to registry.
- `KANIKO_REGISTRY_MAP` - Equivalent to `--registry-map` flag. Define registry remapping.
- `KANIKO_REGISTRY_MIRROR` - Equivalent to `--registry-mirror` flag. Define registry mirror.
- `KANIKO_DIR` - Equivalent to `--kaniko-dir` flag. Set kaniko directory path.

#### Credential Environment Variables

When using the `env` credential helper (via `--credential-helpers=env`), the following environment variables can be used for authentication:

- `DOCKER_USERNAME` - Username for Docker registry authentication
- `DOCKER_PASSWORD` - Password for Docker registry authentication
- `DOCKER_REGISTRY` - Registry URL (optional, defaults to Docker Hub)

**Example**:
```bash
export DOCKER_USERNAME=myuser
export DOCKER_PASSWORD=mypassword
export DOCKER_REGISTRY=registry.example.com
```

#### Flag `--image-fs-extract-retry`

Set this flag to the number of retries that should happen for the extracting an image filesystem. Defaults to `0`.

#### Flag `--image-download-retry`

Set this flag to the number of retries that should happen when downloading the remote image. Consecutive retries occur with exponential backoff and an initial delay of 1 second. Defaults to `0`.

#### Flag `--incremental-snapshots`

Set this flag to `true` to enable incremental snapshots for better performance. This feature caches file metadata between snapshots to reduce filesystem scanning time by up to 60-80%. Kaniko will only scan changed files instead of the entire filesystem. Defaults to `true`.

**Note**: This feature includes automatic integrity checks and fallback to full scans when needed to ensure data integrity.

#### Flag `--max-expected-changes`

Set this flag to specify the maximum number of expected file changes before triggering a full scan when using incremental snapshots. If more files change than this threshold, kaniko will perform a full scan for safety. Defaults to `5000`.

**Example**: `--max-expected-changes=2000`

#### Flag `--integrity-check`

Set this flag to `true` to enable integrity checks for incremental snapshots. When enabled, kaniko will verify that incremental scans don't miss any changes and automatically fall back to full scans if integrity concerns are detected. Defaults to `true`.

#### Flag `--full-scan-backup`

Set this flag to `true` to enable automatic full scan backup when integrity concerns are detected during incremental snapshots. This ensures data integrity is never compromised for performance. Defaults to `true`.

#### Flag `--max-memory-usage-bytes`

Set this flag to specify the maximum memory usage in bytes. When this limit is approached (80% by default), kaniko will trigger garbage collection automatically. Supports human-readable formats like `2GB`, `4GB`. Defaults to `2GB`.

**Example**: `--max-memory-usage-bytes=4GB`

#### Flag `--max-file-size-bytes`

Set this flag to specify the maximum size for a single file during build. Files exceeding this size will trigger a warning or error depending on configuration. Supports formats like `500MB`, `1GB`. Defaults to `500MB`.

**Example**: `--max-file-size-bytes=1GB`

#### Flag `--max-total-file-size-bytes`

Set this flag to specify the maximum total size for all files in the build context. This helps prevent out-of-memory errors with very large contexts. Supports formats like `10GB`, `20GB`. Defaults to `10GB`.

**Example**: `--max-total-file-size-bytes=20GB`

#### Flag `--memory-monitoring`

Set this flag to `true` to enable continuous memory monitoring and automatic garbage collection. When enabled, kaniko will monitor memory usage and trigger GC when the threshold is exceeded. Defaults to `true`.

#### Flag `--gc-threshold`

Set this flag to specify the memory usage percentage threshold (1-100) for triggering garbage collection. When memory usage exceeds this percentage, automatic GC will be triggered. Defaults to `80`.

**Example**: `--gc-threshold=85`

#### Flag `--monitoring-interval`

Set this flag to specify the memory monitoring interval in seconds. Kaniko will check memory usage at this interval and trigger GC if needed. Defaults to `5` seconds.

**Example**: `--monitoring-interval=10`

#### Flag `--max-parallel-commands`

Set this flag to specify the maximum number of Dockerfile commands to execute in parallel. Set to `0` to auto-detect based on CPU cores. Parallel execution can significantly speed up builds with independent commands. Defaults to auto-detect.

**Example**: `--max-parallel-commands=4`

**Note**: Kaniko automatically analyzes command dependencies to ensure safe parallel execution.

#### Flag `--command-timeout`

Set this flag to specify the timeout for individual command execution. Commands running longer than this timeout will be terminated. Supports formats like `30m`, `1h`. Defaults to `30m`.

**Example**: `--command-timeout=1h`

#### Flag `--enable-parallel-exec`

Set this flag to `true` to enable parallel execution of independent Dockerfile commands. This can provide 20-40% performance improvement for builds with many independent commands. Defaults to `false` (sequential execution is default for stability).

#### Flag `--max-cache-entries`

Set this flag to specify the maximum number of entries in the LRU cache. Higher values allow caching more layers but use more memory. Optimized default for 1GB cache. Defaults to `2000`.

**Example**: `--max-cache-entries=3000`

#### Flag `--max-preload-size`

Set this flag to specify the maximum number of images to preload into cache. Preloading popular base images can significantly speed up builds. Defaults to `100`.

**Example**: `--max-preload-size=150`

#### Flag `--preload-timeout`

Set this flag to specify the timeout for preload operations. Supports formats like `5m`, `10m`. Increased default for large cache operations. Defaults to `10m`.

**Example**: `--preload-timeout=15m`

#### Flag `--enable-smart-cache`

Set this flag to `true` to enable smart cache with LRU eviction and automatic preloading capabilities. The smart cache provides 40-60% better cache utilization compared to the basic cache. Defaults to `true`.

#### Flag `--max-concurrent-cache-checks`

Set this flag to specify the maximum number of concurrent cache checks. This controls parallel cache lookups for better performance. Defaults to `3` for optimal balance between speed and CPU resource usage, especially with multiple parallel builds.

**Example**: `--max-concurrent-cache-checks=10`

#### Flag `--max-workers`

Set this flag to specify the maximum number of workers for parallel operations. When set to `0` (default), automatically uses `min(6, NumCPU)` with a maximum of 8 workers. This conservative default helps avoid excessive CPU usage when running multiple parallel builds.

**Example**: `--max-workers=4`

#### Flag `--max-parallel-hashing`

Set this flag to specify the maximum number of parallel file hashing operations. When set to `0` (default), automatically uses `4` workers. This conservative default helps reduce CPU usage for CPU-intensive hashing operations.

**Example**: `--max-parallel-hashing=8`

#### Flag `--max-parallel-copy`

Set this flag to specify the maximum number of parallel file copy operations. When set to `0` (default), automatically uses `2` workers. This conservative default is optimized for I/O-bound operations and helps prevent excessive CPU usage.

**Example**: `--max-parallel-copy=4`

#### Flag `--disable-compression`

Set this flag to `true` to disable layer compression for maximum build speed. This significantly reduces CPU usage but increases layer size. Useful for development builds or when CPU resources are limited. Defaults to `false`.

**Example**: `--disable-compression=true`

#### Flag `--max-file-hash-size`

Set this flag to specify the maximum file size in bytes for full hashing. Files larger than this limit use partial hashing (first 64KB + last 64KB + file size) to reduce CPU usage while maintaining good change detection. Defaults to `10485760` (10MB).

**Example**: `--max-file-hash-size=20971520` (20MB)

#### Flag `--max-network-concurrency`

Set this flag to specify the maximum number of parallel network requests. When set to `0` (default), automatically uses `5` workers. This conservative default is optimized for I/O-bound network operations and helps prevent excessive CPU usage.

**Example**: `--max-network-concurrency=10`

#### Flag `--cache-max-conns`

Set this flag to specify the maximum number of idle connections in the HTTP connection pool for registry cache operations. Reusing connections significantly improves cache performance. Defaults to `10`.

**Example**: `--cache-max-conns=20`

#### Flag `--cache-max-conns-per-host`

Set this flag to specify the maximum number of idle connections per host in the connection pool. Defaults to `5`.

**Example**: `--cache-max-conns-per-host=10`

#### Flag `--cache-max-concurrent-requests`

Set this flag to specify the maximum number of concurrent requests to the registry for cache operations. Defaults to `5`.

**Example**: `--cache-max-concurrent-requests=10`

#### Flag `--cache-disable-http2`

Set this flag to `true` to disable HTTP/2 for cache requests and use HTTP/1.1 instead. HTTP/2 is enabled by default for better performance. Defaults to `false`.

**Example**: `--cache-disable-http2=true`

#### Flag `--cache-request-timeout`

Set this flag to specify the timeout for cache requests to the registry. Supports formats like `30s`, `1m`. Defaults to `30s`.

**Example**: `--cache-request-timeout=1m`

#### Flag `--prefetch-window`

Set this flag to specify the number of next commands to prefetch cache keys for. Increasing this value improves cache hit rate but uses more resources. Defaults to `10` (increased from 3 for better performance).

**Example**: `--prefetch-window=15`

#### Flag `--cache-result-ttl`

Set this flag to specify the time-to-live for cached cache check results. This avoids redundant cache lookups. Supports formats like `5m`, `10m`. Defaults to `5m`.

**Example**: `--cache-result-ttl=10m`

#### Flag `--cache-result-max-entries`

Set this flag to specify the maximum number of cached cache check results. Higher values reduce redundant lookups but use more memory. Defaults to `1000`.

**Example**: `--cache-result-max-entries=2000`

#### Flag `--cache-result-max-memory-mb`

Set this flag to specify the maximum memory usage in MB for cached cache check results. Defaults to `100 MB`.

**Example**: `--cache-result-max-memory-mb=200`

#### Flag `--file-hash-cache-max-entries`

Set this flag to specify the maximum number of cached file hashes. This avoids recomputing hashes for the same files. Defaults to `10000`.

**Example**: `--file-hash-cache-max-entries=20000`

#### Flag `--file-hash-cache-max-memory-mb`

Set this flag to specify the maximum memory usage in MB for cached file hashes. Defaults to `200 MB`.

**Example**: `--file-hash-cache-max-memory-mb=400`

#### Flag `--layer-load-max-concurrent`

Set this flag to specify the maximum number of concurrent layer loads from cache. Parallel loading improves throughput. Defaults to `3`.

**Example**: `--layer-load-max-concurrent=5`

#### Flag `--enable-predictive-cache`

Set this flag to `true` to enable predictive caching, which prefetches layers based on build history patterns. This is an experimental feature. Defaults to `false`.

**Example**: `--enable-predictive-cache=true`

#### Flag `--predictive-cache-max-layers`

Set this flag to specify the maximum number of layers to prefetch with predictive caching. Defaults to `20`.

**Example**: `--predictive-cache-max-layers=30`

#### Flag `--predictive-cache-max-memory-mb`

Set this flag to specify the maximum memory in MB to use for predictive cache prefetching. Defaults to `50 MB`.

**Example**: `--predictive-cache-max-memory-mb=100`

#### Flag `--local-cache-use-mmap`

Set this flag to `true` to use memory-mapped files for faster local cache access. This is an experimental feature. Defaults to `false`.

**Example**: `--local-cache-use-mmap=true`

#### Flag `--local-cache-compress`

Set this flag to `true` to compress local cache files to save disk space. This is an experimental feature. Defaults to `false`.

**Example**: `--local-cache-compress=true`

#### Flag `--local-cache-compression`

Set this flag to specify the compression algorithm for local cache files. Options: `gzip`, `zstd`. Defaults to `zstd`. This is an experimental feature.

**Example**: `--local-cache-compression=gzip`

#### Flag `--compression-level`

Set this flag to specify the compression level. For zstd, the default is `2` which provides optimal balance between speed, size, and CPU usage. Higher values provide better compression but are slower and use more CPU. The conservative default helps reduce CPU usage, especially with multiple parallel builds.

**Example**: `--compression-level=6`

#### Flag `--generate-provenance`

Generate SLSA provenance attestation for supply chain security. When enabled, Kaniko generates a SLSA provenance document after successful build, providing traceability and security compliance. Defaults to `false`.

**Example**: `--generate-provenance`

#### Flag `--allowed-registries`

List of allowed registry patterns (wildcards supported). Only images from these registries will be allowed. Use comma-separated values for multiple registries.

**Example**: `--allowed-registries=gcr.io/*,docker.io/*`

#### Flag `--denied-registries`

List of denied registry patterns (wildcards supported). Images from these registries will be rejected. Use comma-separated values for multiple registries.

**Example**: `--denied-registries=untrusted.io/*`

#### Flag `--allowed-repos`

List of allowed repository patterns (wildcards supported). Only images from these repositories will be allowed.

**Example**: `--allowed-repos=myproject/*`

#### Flag `--denied-repos`

List of denied repository patterns (wildcards supported). Images from these repositories will be rejected.

**Example**: `--denied-repos=untrusted-project/*`

#### Flag `--require-signature`

Require images to be signed (source policy validation). When enabled, only signed images will be allowed. Defaults to `false`.

**Example**: `--require-signature`

**Note**: Source policy flags work together to provide fine-grained control over image sources. If any policy flag is set, source validation is automatically enabled.

### Debug Image

The kaniko executor image is based on scratch and doesn't contain a shell. We provide `ghcr.io/gosayram/kaniko:debug`, a debug image which consists of the kaniko executor image along with a busybox shell to enter.

You can launch the debug image with a shell entrypoint:

```shell
docker run -it --entrypoint=/busybox/sh ghcr.io/gosayram/kaniko:debug
```

## 🔒 Security

kaniko by itself **does not** make it safe to run untrusted builds inside your cluster, or anywhere else.

kaniko relies on the security features of your container runtime to provide build security.

The minimum permissions kaniko needs inside your container are governed by a few things:

- The permissions required to unpack your base image into its container
- The permissions required to execute the RUN commands inside the container

If you have a minimal base image (SCRATCH or similar) that doesn't require permissions to unpack, and your Dockerfile doesn't execute any commands as the root user, you can run kaniko without root permissions. It should be noted that Docker runs as root by default, so you still require (in a sense) privileges to use kaniko.

You may be able to achieve the same default seccomp profile that Docker uses in your Pod by setting [seccomp](https://kubernetes.io/docs/concepts/policy/pod-security-policy/#seccomp) profiles with annotations on a [PodSecurityPolicy](https://cloud.google.com/kubernetes-engine/docs/how-to/pod-security-policies) to create or update security policies on your cluster.

### Verifying Signed Kaniko Images

kaniko images are signed for versions >= 1.5.2 using [cosign](https://github.com/sigstore/cosign)!

To verify a public image, install [cosign](https://github.com/sigstore/cosign) and use the provided [public key](cosign.pub):

```
$ cat cosign.pub
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9aAfAcgAxIFMTstJUv8l/AMqnSKw
P+vLu3NnnBDHCfREQpV/AJuiZ1UtgGpFpHlJLCNPmFkzQTnfyN5idzNl6Q==
-----END PUBLIC KEY-----

$ cosign verify -key ./cosign.pub ghcr.io/gosayram/kaniko:latest
```

### 🛡️ **ADVANCED SECURITY** - Security Features

Kaniko includes comprehensive security features:

#### **Security Features**
- **Command Validation** - Security validation for all Dockerfile commands
- **Path Sanitization** - Safe path resolution and validation
- **Environment Variable Security** - Secure environment variable handling
- **User Security** - Non-root user execution by default
- **Registry Security** - TLS verification and certificate validation

#### **Security Best Practices**
- **Always specify non-root users** in Dockerfiles
- **Use minimal base images** to reduce attack surface
- **Regular security updates** of base images
- **Use trusted registries** with proper authentication
- **Use source policy** to control which image sources are allowed
- **Generate SLSA provenance** for supply chain security

## 📈 Kaniko Builds - Profiling

If your builds are taking long, we recently added support to analyze kaniko function calls using [Slow Jam](https://github.com/google/slowjam) To start profiling,

1. Add an environment variable `STACKLOG_PATH` to your [pod definition](https://github.com/Gosayram/kaniko/blob/master/examples/pod-build-profile.yaml#L15).
2. If you are using the kaniko `debug` image, you can copy the file in the `pre-stop` container lifecycle hook.

### 🚀 **PERFORMANCE OPTIMIZATION** - Advanced Build Features

Kaniko includes comprehensive performance optimization capabilities:

#### **Memory Management & Monitoring**
- **Automatic Garbage Collection** - Configurable memory thresholds and GC triggers
- **Memory Monitoring** - Real-time memory usage tracking and alerts
- **Memory Limits** - Configurable limits for memory usage, file sizes, and total context size
- **Memory Optimization** - Efficient memory usage patterns for large builds

#### **Memory Configuration**
```bash
# Memory management settings
--max-memory-usage-bytes=4GB        # Maximum memory usage
--max-file-size-bytes=1GB           # Maximum single file size
--max-total-file-size-bytes=20GB    # Maximum total context size
--memory-monitoring=true            # Enable memory monitoring
--gc-threshold=85                   # GC trigger percentage (1-100)
--monitoring-interval=10            # Memory check interval (seconds)
```

#### **Parallel Execution & Performance**
- **Parallel Command Execution** - Independent Dockerfile commands run concurrently
- **Smart Command Analysis** - Automatic dependency detection for safe parallel execution
- **Performance Optimization** - 20-40% improvement for builds with independent commands
- **Command Timeout Management** - Configurable timeouts for individual commands
- **Race Condition Prevention** - Automatic detection and prevention of filesystem conflicts
- **Thread-Safe Operations** - Safe parallel execution with proper synchronization

#### **How Parallel Execution Works**
Kaniko automatically analyzes Dockerfile commands to determine which can be executed in parallel:

1. **Dependency Analysis** - Commands are analyzed for:
   - File system dependencies (commands that create/modify files used by other commands)
   - Environment variable dependencies (ENV commands affecting RUN commands)
   - Parent directory relationships (mkdir + commands using created directories)

2. **Conflict Detection** - Commands that modify the same files or directories are automatically detected and executed sequentially to prevent race conditions

3. **Execution Groups** - Commands are grouped by dependencies:
   - Commands in the same group can execute in parallel
   - Groups execute sequentially to respect dependencies
   - Snapshots are taken in deterministic order after parallel execution

4. **System Directory Preparation** - System directories are made writable once before parallel execution starts, preventing race conditions when multiple commands need to modify system directories

5. **Error Handling** - If any command fails, other parallel commands are canceled to prevent inconsistent filesystem state

#### **Parallel Execution Configuration**
```bash
# Parallel execution settings
--enable-parallel-exec=true         # Enable parallel command execution
--max-parallel-commands=4           # Maximum parallel commands (0=auto-detect)
--command-timeout=1h                # Command execution timeout
```

#### **Best Practices for Parallel Execution**
- **Independent Commands** - Structure Dockerfile with independent commands for best performance
- **Avoid Shared Resources** - Commands that modify the same files/directories will run sequentially
- **Use Multi-Stage Builds** - Cross-stage dependencies are automatically handled with filesystem sync
- **Monitor Build Logs** - Check execution groups in logs to understand parallelization

#### **CPU Optimization & Resource Management**
Kaniko includes comprehensive CPU optimization features to reduce resource consumption, especially when running multiple parallel builds:

- **Conservative Defaults** - Optimized default values for parallel operations to prevent excessive CPU usage
- **Partial File Hashing** - Large files (>10MB) use partial hashing (first+last 64KB + size) instead of full hashing to reduce CPU-intensive operations
- **Sharded Cache** - File hash cache uses sharding to reduce lock contention and improve parallel performance
- **Optimized Algorithms** - Heap-based sorting (O(log n)) instead of repeated sorting (O(n log n)) in dependency graph
- **Async Logging** - Non-blocking async logging reduces CPU overhead in hot paths
- **Buffer Pooling** - Reusable buffers for I/O operations reduce memory allocations and CPU usage
- **Smart String Operations** - Pre-allocated strings.Builder and optimized string concatenation
- **Conditional Sorting** - Skip sorting when data is already sorted to avoid unnecessary CPU usage

#### **CPU Configuration**
```bash
# CPU resource limits (for optimization and multiple parallel builds)
--max-workers=0                    # Maximum workers (0=auto: min(6, NumCPU), max: 8)
--max-parallel-hashing=0           # Parallel hashing workers (0=auto: 4)
--max-parallel-copy=0              # Parallel copy workers (0=auto: 2)
--max-network-concurrency=0        # Network concurrency (0=auto: 5)
--max-file-hash-size=10485760     # Max file size for full hashing (default: 10MB)
--disable-compression=false        # Disable compression for maximum speed
--compression-level=2              # Compression level (default: 2 for lower CPU usage)
--max-concurrent-cache-checks=3   # Concurrent cache checks (default: 3)
```

#### **CPU Optimization Best Practices**
- **Multiple Parallel Builds** - Use conservative defaults when running multiple builds simultaneously
- **Large Files** - Files larger than 10MB automatically use partial hashing to reduce CPU usage
- **Development Builds** - Use `--disable-compression=true` for faster builds when layer size is not critical
- **Limited CPU Resources** - Lower `--max-workers` and `--max-parallel-hashing` values for CPU-constrained environments
- **Network Operations** - Adjust `--max-network-concurrency` based on network bandwidth and CPU availability

#### **Build Optimization Engine**
- **Pattern Detection** - Automatic detection of common Dockerfile patterns
- **Optimization Suggestions** - Automated recommendations for build improvements
- **Performance Analysis** - Build performance metrics and bottleneck identification
- **Dockerfile Analysis** - Comprehensive analysis of Dockerfile structure and efficiency

#### **Optimization Features**
- **Layer Optimization** - Suggestions for combining RUN commands
- **Cache Optimization** - Recommendations for better cache utilization
- **Multi-Stage Build Suggestions** - Automated multi-stage build recommendations
- **Base Image Optimization** - Suggestions for smaller, more efficient base images
- **Copy Optimization** - Recommendations for more efficient file copying

#### **Advanced Snapshotting**
- **Incremental Snapshots** - 60-80% performance improvement with integrity checks
- **Smart Filesystem Scanning** - Only scan changed files instead of entire filesystem
- **Integrity Verification** - Automatic fallback to full scans when needed
- **Snapshot Optimization** - Configurable snapshot modes for different use cases

#### **Snapshot Configuration**
```bash
# Advanced snapshotting settings
--incremental-snapshots=true        # Enable incremental snapshots
--max-expected-changes=2000         # Threshold for full scan trigger
--integrity-check=true              # Enable integrity checks
--full-scan-backup=true             # Enable automatic full scan backup
--snapshot-mode=full               # Snapshot mode: full, redo, time
```

#### **Performance Monitoring**
- **Build Timing** - Detailed timing information for each build stage
- **Resource Usage** - CPU, memory, and I/O usage tracking
- **Throughput Metrics** - Build throughput and efficiency measurements
- **Performance Reports** - Comprehensive performance analysis and recommendations

### 📊 **ADVANCED LOGGING & MONITORING** - Enterprise-Grade Observability

Kaniko provides comprehensive logging and monitoring capabilities:

#### **Enhanced Logging Formats**
- **Structured JSON Logging** - Machine-readable logs for analysis and monitoring
- **Custom Kaniko Format** - Clean, readable logs with progress indicators
- **Compact Mode** - Minimal logging for CI/CD environments
- **Color-coded Output** - Visual distinction between log levels (INFO - blue, WARN - yellow, ERROR - red)
  - Automatically detects terminal capabilities and disables colors when `NO_COLOR` environment variable is set
  - Intelligent color detection based on `TERM` variable for better CI/CD compatibility
- **Timestamp Control** - Configurable timestamp formatting
- **Context-aware Logging** - Rich context information for debugging
- **Log Grouping** - Related log messages grouped for better readability
- **Performance Logging** - Detailed performance metrics and timing information

#### **Logging Configuration**
```bash
# Logging format options
--log-format=kaniko          # Custom kaniko format with clean output
--log-format=kaniko-compact  # Compact mode for CI/CD
--log-format=json            # Structured JSON logging
--log-format=text            # Plain text logging
--log-format=color           # Color-coded text logging
--log-timestamp=true         # Enable timestamps
--verbosity=debug            # Log level: panic|fatal|error|warn|info|debug|trace
```

#### **Progress Tracking & Monitoring**
- **Real-time Progress** - Live build progress with percentage completion
- **Stage Tracking** - Individual stage progress and timing
- **Resource Monitoring** - Memory, CPU, and I/O usage tracking
- **Build Metrics** - Comprehensive build statistics and performance data
- **Error Context** - Detailed error information with stack traces

#### **Monitoring Features**
- **Build ID Tracking** - Unique build identifiers for correlation
- **Performance Metrics** - Detailed timing and resource usage
- **Memory Profiling** - Memory usage patterns and optimization suggestions
- **Network Monitoring** - Registry communication and transfer statistics
- **Cache Analytics** - Cache hit rates and performance metrics
- **Real-time Metrics** - Live performance monitoring during builds
- **Resource Alerts** - Automatic alerts for resource usage thresholds
- **Build Health Monitoring** - Proactive monitoring of build health

#### **Integration & Observability**
- **Prometheus Metrics** - Export metrics for Prometheus monitoring
- **Structured Logging** - JSON logs for log aggregation systems
- **Build Profiling** - Integration with Slow Jam for performance analysis
- **Error Reporting** - Comprehensive error context and debugging information
- **Audit Logging** - Security and compliance logging capabilities

## 🏗️ Built-in Multi-Architecture Support

Kaniko now includes native multi-architecture build support without requiring privileged operations or external tools. This feature allows you to build container images for multiple platforms simultaneously using different execution drivers.

### ✅ **PRODUCTION-READY** - Key Features

- **No Privileged Operations**: No qemu/binfmt emulation required
- **Multiple Driver Support**: Local, Kubernetes, and CI integration modes
- **OCI 1.1 Compliance**: **10/10 rating** - Full support for OCI Image Index with platform descriptors and annotations
- **Enhanced Registry Compatibility**: Configurable exponential backoff retry mechanisms for reliable pushes
- **Security First**: Minimal RBAC requirements for Kubernetes driver
- **Performance Optimized**: Coordinator overhead <10% vs single-arch builds
- **Comprehensive Testing**: E2E tests for all drivers and multi-platform scenarios
- **Modern Go 1.24+ Infrastructure**: Single-binary executor with modern toolchain support

### Quick Start Examples

#### Local Development
```bash
# Build for host architecture only
docker run --rm -v $(pwd):/workspace ghcr.io/gosayram/kaniko:latest \
  --dockerfile=/workspace/Dockerfile \
  --destination=ghcr.io/org/app:1.0.0 \
  --multi-platform=linux/amd64 \
  --driver=local

# Build for multiple platforms locally
docker run --rm -v $(pwd):/workspace ghcr.io/gosayram/kaniko:latest \
  --dockerfile=/workspace/Dockerfile \
  --destination=ghcr.io/org/app:1.0.0 \
  --multi-platform=linux/amd64,linux/arm64 \
  --driver=local
```

#### Kubernetes Multi-Arch Build
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
        image: ghcr.io/gosayram/kaniko:latest
        args:
        - --context=git=https://github.com/org/app.git#main
        - --dockerfile=Dockerfile
        - --destination=ghcr.io/org/app:1.2.3
        - --multi-platform=linux/amd64,linux/arm64
        - --driver=k8s
        - --publish-index=true
        - --legacy-manifest-list=true
        - --require-native-nodes=true
        - --push-retry=3
        - --push-retry-initial-delay=1s
        - --push-retry-max-delay=30s
```

#### CI Integration
```bash
# Matrix build per architecture, then aggregate
docker run --rm -v $(pwd):/workspace ghcr.io/gosayram/kaniko:latest \
  --dockerfile=/workspace/Dockerfile \
  --destination=ghcr.io/org/app:1.0.0 \
  --multi-platform=linux/amd64,linux/arm64 \
  --driver=ci \
  --digests-from=/artifacts/digests \
  --publish-index=true

# GitHub Actions example with automatic detection
- name: Build multi-arch image
  run: |
    docker run --rm -v $(pwd):/workspace ghcr.io/gosayram/kaniko:latest \
      --dockerfile=/workspace/Dockerfile \
      --destination=${{ github.repository }}:${{ github.sha }} \
      --multi-platform=linux/amd64,linux/arm64,linux/s390x \
      --driver=ci \
      --publish-index=true
```

### ✅ **FULLY IMPLEMENTED** - Configuration Flags

#### Multi-Platform Configuration
- `--multi-platform`: Comma-separated list of platforms (e.g., `linux/amd64,linux/arm64`)
- `--driver`: Execution driver (`local`, `k8s`, or `ci`)
- `--publish-index`: Publish OCI Image Index after builds complete
- `--legacy-manifest-list`: Create Docker Manifest List for backward compatibility
- `--digests-from`: Path to digest files for CI driver integration
- `--require-native-nodes`: Fail if non-native architecture is requested
- `--index-annotations`: Key-value annotations for OCI Image Index
- `--arch-cache-repo-suffix`: Suffix for per-architecture cache repositories
- `--oci-mode`: OCI mode (`oci`, `auto`, `docker`)
- `--compression`: Layer compression (`gzip`, `zstd`)
- `--sign-images`: Enable optional image signing with cosign
- `--cosign-key-path`: Path to cosign private key
- `--cosign-key-password`: Password for cosign key

#### Enhanced Registry Push Configuration
- `--push-retry`: Number of retries for push operations (default: 0)
- `--push-retry-initial-delay`: Initial delay before first retry (default: 1s)
- `--push-retry-max-delay`: Maximum delay between retries (default: 30s)
- `--push-retry-backoff-multiplier`: Exponential backoff multiplier (default: 2.0)

### Migration Guide

#### From Manifest-tool to Built-in Multi-Arch

**Before (using manifest-tool):**
```yaml
# GitLab CI example
build-container:
  stage: container-build
  parallel:
    matrix:
      - ARCH: amd64
      - ARCH: arm64
  script:
    - /kaniko/executor --context "${CI_PROJECT_DIR}" --dockerfile "${CI_PROJECT_DIR}/Dockerfile" --destination "${CI_REGISTRY_IMAGE}:${ARCH}"

merge-manifests:
  stage: container-build
  needs: [build-container]
  image: mplatform/manifest-tool:alpine
  script:
    - manifest-tool push from-args --platforms linux/amd64,linux/arm64 --template "${CI_REGISTRY_IMAGE}:ARCH" --target "${CI_REGISTRY_IMAGE}"
```

**After (using built-in multi-arch):**
```yaml
# Single job with built-in multi-arch support
build-container:
  stage: container-build
  script:
    - /kaniko/executor --context "${CI_PROJECT_DIR}" --dockerfile "${CI_PROJECT_DIR}/Dockerfile" --destination "${CI_REGISTRY_IMAGE}:latest" --multi-platform=linux/amd64,linux/arm64 --driver=ci --publish-index=true
```

#### Key Migration Benefits

1. **Simplified CI/CD**: No need for separate manifest-tool jobs
2. **Better Reliability**: Built-in retry mechanisms for registry pushes
3. **Reduced Complexity**: Single command handles all architectures
4. **Improved Performance**: Lower overhead compared to separate builds
5. **Enhanced Security**: No need to handle manifest-tool separately

#### Breaking Changes Considerations

- **Registry Push Behavior**: Enhanced retry logic may change push timing
- **Image Format**: Default is OCI Image Index, can fallback to Docker Manifest List
- **Node Requirements**: Kubernetes driver requires nodes with target architectures

### Performance and Reliability

- **Coordinator Overhead**: <10% overhead compared to single-arch builds
- **Retry Mechanisms**: Configurable exponential backoff for all registry operations
- **Cache Compatibility**: Works with existing kaniko caching mechanisms
- **Resource Usage**: Optimized for memory and CPU efficiency

### Validation and Testing

- **OCI Compliance**: Built-in validation using crane and oras tools
- **E2E Testing**: Comprehensive test coverage for all drivers
- **Benchmarking**: Performance benchmarks available in `docs/benchmark.md`
- **Verification Scripts**: `scripts/verify-oci.sh` for compliance validation

### ✅ **COMPREHENSIVE** - Documentation

For comprehensive documentation and usage examples, see:
- [Multi-Architecture Usage Guide](docs/multi-arch-usage.md)
- [Driver Implementation Details](docs/multi-arch-usage.md#driver-details)
- [Migration Guide](docs/multi-arch-usage.md#migration-guide)
- [OCI Compliance Guide](docs/oci-compliance.md) - **10/10 compliance rating**
- [Performance Benchmarking](docs/benchmark.md)
- [OCI Verification Tools](docs/oci-verification.md)
- [Security Best Practices](docs/security-best-practices.md)
- [Modern Development Guide](DEVELOPMENT.md)

### 🏗️ **ADVANCED PLATFORM SUPPORT** - Multi-Architecture Excellence

Kaniko provides comprehensive platform support and detection:

#### **Platform Detection & Management**
- **Automatic Platform Detection** - Intelligent detection of available build platforms
- **Cross-Platform Compatibility** - Support for Linux, ARM, and other architectures
- **Platform Validation** - Validation of platform compatibility and requirements
- **Native Node Detection** - Automatic detection of native architecture nodes
- **Platform Capabilities** - Detection of platform-specific capabilities and features

#### **Multi-Platform Features**
- **Architecture-Specific Caching** - Separate cache repositories per architecture
- **Platform-Optimized Builds** - Optimized builds for specific architectures
- **Cross-Platform Testing** - Comprehensive testing across multiple platforms
- **Platform Metadata** - Rich platform metadata and descriptor support
- **Platform Annotations** - Custom annotations for platform-specific information

#### **Platform Configuration**
```bash
# Platform-specific settings
--custom-platform=linux/arm64        # Build for specific platform
--require-native-nodes=true          # Require native architecture nodes
--arch-cache-repo-suffix=-${ARCH}    # Architecture-specific cache
--index-annotations=key=value        # Platform annotations
--oci-mode=oci                       # OCI compliance mode
--compression=zstd                   # Platform-optimized compression
```

#### **Supported Platforms**
- **Linux/AMD64** - Primary platform with full feature support
- **Linux/ARM64** - ARM64 support with native performance
- **Linux/ARM** - ARM32 support for embedded systems
- **Linux/S390X** - IBM Z architecture support
- **Linux/PPC64LE** - PowerPC architecture support
- **Custom Platforms** - Support for custom platform specifications

#### **Platform Intelligence**
- **Build Optimization** - Platform-specific build optimizations
- **Resource Management** - Platform-aware resource allocation
- **Performance Tuning** - Architecture-specific performance tuning
- **Compatibility Checks** - Automatic compatibility validation
- **Feature Detection** - Platform capability detection and utilization

## 🏗️ Creating Multi-arch Container Manifests Using Kaniko and Manifest-tool

While Kaniko now has built-in multi-architecture support, you can still use tools such as [manifest-tool](https://github.com/estesp/manifest-tool) to stitch multiple separate builds together into a single container manifest if needed.

### General Workflow

The general workflow for creating multi-arch manifests is as follows:

1. Build separate container images using Kaniko on build hosts matching your target architecture and tag them with the appropriate ARCH tag.
2. Push the separate images to your container registry.
3. Manifest-tool identifies the separate manifests in your container registry, according to a given template.
4. Manifest-tool pushes a combined manifest referencing the separate manifests.

![Workflow Multi-arch](docs/images/multi-arch.drawio.svg)

### Limitations and Pitfalls

The following conditions must be met:

1. You need access to build-machines running the desired architectures (running Kaniko in an emulator, e.g. QEMU should also be possible but goes beyond the scope of this documentation). This is something to keep in mind when using SaaS build tools such as github.com or gitlab.com, of which at the time of writing neither supports any non-x86_64 SaaS runners ([GitHub](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners/about-github-hosted-runners#supported-runners-and-hardware-resources),[GitLab](https://docs.gitlab.com/ee/ci/runners/saas/linux_saas_runner.html#machine-types-available-for-private-projects-x86-64)), so be prepared to bring your own machines ([GitHub](https://docs.github.com/en/actions/hosting-your-own-runners/managing-self-hosted-runners/about-self-hosted-runners),[GitLab](https://docs.gitlab.com/runner/register/).
2. Kaniko needs to be able to run on the desired architectures. At the time of writing, the official Kaniko container supports [linux/amd64, linux/arm64, linux/s390x and linux/ppc64le (not on \*-debug images)](https://github.com/Gosayram/kaniko/blob/main/.github/workflows/images.yaml).
3. The container registry of your choice must be OCIv1 or Docker v2.2 compatible.

### Example CI Pipeline (GitLab)

It is up to you to find an automation tool that suits your needs best. We recommend using a modern CI/CD system such as GitHub workflows or GitLab CI. As we (the authors) happen to use GitLab CI, the following examples are tailored to this specific platform but the underlying principles should apply anywhere else and the examples are kept simple enough, so that you should be able to follow along, even without any previous experiences with this specific platform. When in doubt, visit the [gitlab-ci.yml reference page](https://docs.gitlab.com/ee/ci/yaml/index.html) for a comprehensive overview of the GitLab CI keywords.

#### Building the Separate Container Images

gitlab-ci.yml:

```yaml
# define a job for building the containers
build-container:
  stage: container-build
  # run parallel builds for the desired architectures
  parallel:
    matrix:
      - ARCH: amd64
      - ARCH: arm64
  tags:
    # run each build on a suitable, preconfigured runner (must match the target architecture)
    - runner-${ARCH}
  image:
    name: ghcr.io/gosayram/kaniko:debug
    entrypoint: [""]
  script:
    # build the container image for the current arch using kaniko
    - >-
      /kaniko/executor --context "${CI_PROJECT_DIR}" --dockerfile
      "${CI_PROJECT_DIR}/Dockerfile" # push the image to the GitLab container
      registry, add the current arch as tag. --destination
      "${CI_REGISTRY_IMAGE}:${ARCH}"
```

#### Merging the Container Manifests

gitlab-ci.yml:

```yaml
# define a job for creating and pushing a merged manifest
merge-manifests:
  stage: container-build
  # all containers must be build before merging them
  # alternatively the job may be configured to run in a later stage
  needs:
    - job: container-build
      artifacts: false
  tags:
    # may run on any architecture supported by manifest-tool image
    - runner-xyz
  image:
    name: mplatform/manifest-tool:alpine
    entrypoint: [""]
  script:
    - >-
      manifest-tool # authorize against your container registry
      --username=${CI_REGISTRY_USER} --password=${CI_REGISTRY_PASSWORD} push
      from-args # define the architectures you want to merge --platforms
      linux/amd64,linux/arm64 # "ARCH" will be automatically replaced by
      manifest-tool # with the appropriate arch from the platform definitions
      --template ${CI_REGISTRY_IMAGE}:ARCH # The name of the final, combined
      image which will be pushed to your registry --target ${CI_REGISTRY_IMAGE}
```

#### On the Note of Adding Versioned Tags

For simplicity's sake we deliberately refrained from using versioned tagged images (all builds will be tagged as "latest") in the previous examples, as we feel like this adds to much platform and workflow specific code.

Nethertheless, for anyone interested in how we handle (dynamic) versioning in GitLab, here is a short rundown:

- If you are only interested in building tagged releases, you can simply use the [GitLab predefined](https://docs.gitlab.com/ee/ci/variables/predefined_variables.html) `CI_COMMIT_TAG` variable when running a tag pipeline.
- When you (like us) want to additionally build container images outside of releases, things get a bit messier. In our case, we added a additional job which runs before the build and merge jobs (don't forget to extend the `needs` section of the build and merge jobs accordingly), which will set the tag to `latest` when running on the default branch, to the commit hash when run on other branches and to the release tag when run on a tag pipeline.

gitlab-ci.yml:

```yaml
container-get-tag:
  stage: pre-container-build-stage
  tags:
    - runner-xyz
  image: busybox
  script:
    # All other branches are tagged with the currently built commit SHA hash
    - |
      # If pipeline runs on the default branch: Set tag to "latest"
      if test "$CI_COMMIT_BRANCH" == "$CI_DEFAULT_BRANCH"; then
        tag="latest"
      # If pipeline is a tag pipeline, set tag to the git commit tag
      elif test -n "$CI_COMMIT_TAG"; then
        tag="$CI_COMMIT_TAG"
      # Else set the tag to the git commit sha
      else
        tag="$CI_COMMIT_SHA"
      fi
    - echo "tag=$tag" > build.env
  # parse tag to the build and merge jobs.
  # See: https://docs.gitlab.com/ee/ci/variables/#pass-an-environment-variable-to-another-job
  artifacts:
    reports:
      dotenv: build.env
```

## 🔄 Comparison with Other Tools

## 🚀 **MODERN ADVANTAGES** - Comparison with Other Tools

Similar tools include:

- [BuildKit](https://github.com/moby/buildkit)
- [img](https://github.com/genuinetools/img)
- [orca-build](https://github.com/cyphar/orca-build)
- [umoci](https://github.com/openSUSE/umoci)
- [buildah](https://github.com/containers/buildah)
- [FTL](https://github.com/GoogleCloudPlatform/runtimes-common/tree/master/ftl)
- [Bazel rules_docker](https://github.com/bazelbuild/rules_docker)

### ✅ **Kaniko's Modern Advantages:**

**BuildKit (and `img`)** can perform as a non-root user from within a container but requires seccomp and AppArmor to be disabled to create nested containers. `kaniko` does not actually create nested containers, so it does not require seccomp and AppArmor to be disabled. BuildKit supports "cross-building" multi-arch containers by leveraging QEMU, while kaniko provides **native multi-arch support without emulation**.

**`orca-build`** depends on `runc` to build images from Dockerfiles, which can not run inside a container. `kaniko` doesn't use `runc` so it doesn't require the use of kernel namespacing techniques. However, `orca-build` does not require Docker or any privileged daemon (so builds can be done entirely without privilege).

**`umoci`** works without any privileges, and also has no restrictions on the root filesystem being extracted (though it requires additional handling if your filesystem is sufficiently complicated). However, it has no `Dockerfile`-like build tooling (it's a slightly lower-level tool that can be used to build such builders -- such as `orca-build`).

**`Buildah`** specializes in building OCI images. Buildah's commands replicate all of the commands that are found in a Dockerfile. This allows building images with and without Dockerfiles while not requiring any root privileges. Buildah's ultimate goal is to provide a lower-level coreutils interface to build images. The flexibility of building images without Dockerfiles allows for the integration of other scripting languages into the build process. Buildah follows a simple fork-exec model and does not run as a daemon but it is based on a comprehensive API in golang, which can be vendored into other tools.

**`FTL` and `Bazel`** aim to achieve the fastest possible creation of Docker images for a subset of images. These can be thought of as a special-case "fast path" that can be used in conjunction with the support for general Dockerfiles kaniko provides.

### ✅ **Kaniko's Unique Modern Features:**

- **Built-in Multi-Architecture**: Native multi-platform coordination without privileged operations
- **Full OCI 1.1 Compliance**: 10/10 compliance rating with comprehensive media type support
- **Enhanced Registry Compatibility**: Exponential backoff retry mechanisms for reliable pushes
- **Modern Go 1.24+ Infrastructure**: Single-binary executor with modern toolchain support
- **Security First**: No privileged operations, minimal RBAC requirements
- **Production Ready**: All major features implemented and tested for production use
- **Advanced Caching**: Smart cache with LRU eviction and automatic preloading
- **Performance Optimization**: Parallel execution, incremental snapshots, and memory management
- **Enterprise Logging**: Structured logging, progress tracking, and comprehensive monitoring
- **Image Signing**: Built-in cosign integration for supply chain security
- **Network Intelligence**: Connection pooling, DNS optimization, and registry intelligence
- **Filesystem Optimization**: Safe snapshot optimizer with 60-80% performance improvement
- **Platform Detection**: Automatic platform detection and architecture-specific optimizations
- **Build Analysis**: Pattern detection and automated optimization suggestions

## 👥 Community

[kaniko-users](https://groups.google.com/forum/#!forum/kaniko-users) Google group

To Contribute to kaniko, see [DEVELOPMENT.md](DEVELOPMENT.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

### ✅ **MODERN DEVELOPMENT** - Key Infrastructure

- **Version Management**: Single source of truth via `.release-version` (current: 1.24.1)
- **Modern Go 1.24+**: Toolchain support with comprehensive dependency management
- **CI/CD Strategy**: Makefile-based with script automation in `hack/` directory
- **Release Process**: Automated via `hack/release.sh` with GitHub API integration
- **Testing**: Comprehensive unit, integration, and E2E test coverage
- **Security**: Optional image signing with cosign, no unsafe features by default

### 🗂️ **ADVANCED FILESYSTEM OPERATIONS** - Optimized File Handling

Kaniko includes sophisticated filesystem operations for efficient builds:

#### **Smart Filesystem Scanning**
- **Incremental Scanning** - Only scan changed files for 60-80% performance improvement
- **Safe Snapshot Optimizer** - Advanced filesystem optimization with integrity checks
- **Hidden File Support** - Comprehensive support for hidden files and directories
- **Symlink Resolution** - Proper handling of symbolic links and their targets
- **Path Validation** - Secure path resolution and validation

#### **Filesystem Configuration**
```bash
# Filesystem optimization settings
--incremental-snapshots=true        # Enable incremental filesystem scanning
--max-expected-changes=2000         # Threshold for full scan trigger
--integrity-check=true              # Enable integrity verification
--full-scan-backup=true             # Automatic fallback to full scans
--snapshot-mode=full                # Snapshot mode: full, redo, time
--ignore-var-run=true               # Ignore /var/run in snapshots
--ignore-path=/tmp                  # Custom ignore paths
```

#### **Advanced Path Handling**
- **Wildcard Support** - Comprehensive wildcard pattern matching
- **Environment Variable Resolution** - Dynamic path resolution with env vars
- **Relative Path Handling** - Proper handling of relative and absolute paths
- **Cross-Platform Compatibility** - Consistent behavior across different platforms
- **Path Sanitization** - Security validation for all file operations

#### **Filesystem Features**
- **Whiteout Support** - Proper handling of file deletions in layers
- **Metadata Preservation** - File permissions, ownership, and timestamps
- **Large File Handling** - Efficient processing of large files and directories
- **Memory-Efficient Operations** - Streaming operations for large files
- **Error Recovery** - Robust error handling and recovery mechanisms

## ⚠️ Limitations

### mtime and snapshotting

When taking a snapshot, kaniko's hashing algorithms include (or in the case of [`--snapshot-mode=time`](#--snapshotmode), only use) a file's [`mtime`](https://en.wikipedia.org/wiki/Inode#POSIX_inode_description) to determine if the file has changed. Unfortunately, there is a delay between when changes to a file are made and when the `mtime` is updated. This means:

- With the time-only snapshot mode (`--snapshot-mode=time`), kaniko may miss changes introduced by `RUN` commands entirely.
- With the default snapshot mode (`--snapshot-mode=full`), whether or not kaniko will add a layer in the case where a `RUN` command modifies a file **but the contents do not** change is theoretically non-deterministic. This _does not_ affect the contents which will still be correct, but it does affect the number of layers.

_Note that these issues are currently theoretical only. If you see this issue occur, please [open an issue](https://github.com/Gosayram/kaniko/issues)._

### Dockerfile commands `--chown` support
Kaniko currently supports `COPY --chown` and `ADD --chown` Dockerfile command. It does not support `RUN --chown`.

### 🌐 **ADVANCED NETWORK & REGISTRY OPERATIONS** - Enterprise Connectivity

Kaniko provides sophisticated network and registry capabilities:

#### **Network Optimization**
- **Connection Pooling** - Optimized HTTP connection management with configurable pools
- **Parallel Operations** - Concurrent image pulls and registry operations
- **DNS Optimization** - Intelligent DNS caching and connection reuse
- **Retry Mechanisms** - Exponential backoff with configurable retry policies
- **Timeout Management** - Configurable timeouts for different operations

#### **Network Configuration**
```bash
# Network optimization settings
--push-retry=3                      # Number of retry attempts
--push-retry-initial-delay=1s       # Initial retry delay
--push-retry-max-delay=30s          # Maximum retry delay
--push-retry-backoff-multiplier=2.0 # Exponential backoff multiplier
--image-download-retry=3            # Image download retries
--image-fs-extract-retry=3          # Filesystem extract retries
```

#### **Registry Intelligence**
- **Multi-Registry Support** - Enhanced support for Docker Hub, GCR, ECR, ACR, JFrog
- **Automatic Capability Detection** - Dynamic detection of registry features and limitations
- **Registry Mapping** - Flexible registry remapping for air-gapped environments
- **Mirror Support** - Registry mirroring with fallback mechanisms
- **Authentication** - Comprehensive authentication support for all major registries
- **TLS Configuration** - Custom certificates and mutual TLS support
- **Rate Limit Detection** - Automatic detection and compliance with registry rate limits
- **Optimization Recommendations** - Registry-specific optimization suggestions

#### **Registry Features**
- **Credential Helpers** - Built-in support for Docker credential helpers
- **Workload Identity** - Native support for Kubernetes workload identity
- **Service Account Integration** - Seamless integration with cloud service accounts
- **Certificate Management** - Custom certificate support for private registries
- **Proxy Support** - HTTP/HTTPS proxy configuration

#### **Advanced Registry Operations**
```bash
# Registry configuration
--registry-map=index.docker.io=mirror.gcr.io  # Registry remapping
--registry-mirror=mirror.gcr.io              # Registry mirroring
--registry-certificate=my.registry.url=/path/to/cert.cert
--registry-client-cert=my.registry.url=/path/to/cert.crt,/path/to/key.key
--skip-default-registry-fallback=true        # Fail if mirrors unavailable
```

#### **Network Security**
- **TLS Verification** - Configurable TLS certificate validation
- **Insecure Registry Support** - Support for HTTP registries (testing only)
- **Certificate Validation** - Custom certificate validation for private registries
- **Mutual TLS** - Client certificate authentication support
- **Security Policies** - Configurable security policies for registry access

### 📦 **OCI COMPLIANCE & STANDARDS** - Industry-Leading Compatibility

Kaniko provides comprehensive OCI compliance and standards support:

#### **OCI 1.1 Compliance**
- **Full OCI 1.1 Support** - Complete compliance with OCI Image Specification v1.1
- **10/10 Compliance Rating** - Perfect score on OCI compliance tests
- **Media Type Support** - Comprehensive support for all OCI media types
- **Manifest Validation** - Built-in validation using crane and oras tools
- **Index Support** - Full support for OCI Image Index with platform descriptors
- **Automatic Validation** - Real-time validation during image creation
- **Compliance Reporting** - Detailed compliance reports and validation results
- **Standards Testing** - Continuous compliance testing with OCI test suite

#### **OCI Features**
- **Image Layout Support** - Native OCI image layout support
- **Manifest Lists** - Support for both OCI Image Index and Docker Manifest Lists
- **Platform Descriptors** - Rich platform descriptor support with annotations
- **Digest Verification** - SHA256 digest verification for all operations
- **Content Addressability** - Full content-addressable storage support

#### **OCI Configuration**
```bash
# OCI compliance settings
--oci-mode=oci                       # Strict OCI 1.1 compliance
--oci-mode=auto                      # Automatic detection
--oci-mode=docker                    # Docker format compatibility
--publish-index=true                 # Publish OCI Image Index
--legacy-manifest-list=true          # Create Docker Manifest List
--index-annotations=key=value        # OCI Index annotations
--oci-layout-path=/path/to/layout    # OCI layout output path
```

#### **Standards Compliance**
- **Docker Compatibility** - Full compatibility with Docker image format
- **Registry Standards** - Support for Docker Registry API v2
- **Content Trust** - Support for Docker Content Trust
- **Image Signing** - Support for OCI image signing standards
- **Metadata Standards** - Compliance with container metadata standards

#### **Verification & Testing**
- **Compliance Testing** - Comprehensive OCI compliance test suite
- **Validation Tools** - Built-in validation using industry-standard tools
- **Verification Scripts** - Automated verification scripts for compliance
- **Benchmark Testing** - Performance benchmarks for OCI operations
- **Cross-Platform Testing** - OCI compliance testing across all platforms

## 📖 References

- [Kaniko - Building Container Images In Kubernetes Without Docker](https://youtu.be/EgwVQN6GNJg).