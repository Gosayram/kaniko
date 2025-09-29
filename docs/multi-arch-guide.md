# Multi-Architecture Build Guide

This guide provides comprehensive instructions for building multi-platform images with Kaniko using different drivers: local, Kubernetes, and CI/CD systems.

## Overview

Kaniko's multi-platform support allows you to build container images for multiple architectures (amd64, arm64, etc.) from a single Dockerfile. The architecture uses a coordinator pattern with pluggable drivers to handle the actual build execution.

## Supported Drivers

| Driver | Use Case | Status | Requirements |
|--------|----------|--------|--------------|
| **Local** | Development, single machine | ✅ Complete | None |
| **Kubernetes** | Production, scalable builds | ✅ Complete | Kubernetes cluster |
| **CI** | CI/CD pipeline integration | ✅ Complete | CI environment |

## Quick Start

### Basic Multi-Platform Build

```bash
# Build for multiple platforms
docker run --rm \
  -v $(pwd):/workspace \
  gcr.io/kaniko-project/executor:latest \
  --dockerfile=/workspace/Dockerfile \
  --context=/workspace \
  --destination=gcr.io/myrepo/myimage:latest \
  --platform=linux/amd64,linux/arm64 \
  --driver=local
```

## Local Driver

The local driver builds all platforms on the current machine using emulation (QEMU).

### Configuration

```bash
# Basic local build
docker run --rm \
  -v $(pwd):/workspace \
  gcr.io/kaniko-project/executor:latest \
  --dockerfile=/workspace/Dockerfile \
  --context=/workspace \
  --destination=gcr.io/myrepo/myimage:latest \
  --platform=linux/amd64,linux/arm64 \
  --driver=local
```

### Advanced Configuration

```bash
# Local build with caching and optimization
docker run --rm \
  -v $(pwd):/workspace \
  -v /var/run/docker.sock:/var/run/docker.sock \
  gcr.io/kaniko-project/executor:latest \
  --dockerfile=/workspace/Dockerfile \
  --context=/workspace \
  --destination=gcr.io/myrepo/myimage:latest \
  --platform=linux/amd64,linux/arm64,linux/s390x \
  --driver=local \
  --cache=true \
  --cache-repo=gcr.io/myrepo/cache \
  --cache-ttl=168h \
  --compression=zstd \
  --push-retry=3
```

### Development Workflow

```bash
#!/bin/bash
# build-dev.sh

PLATFORMS="linux/amd64,linux/arm64"
IMAGE="gcr.io/myrepo/myimage:dev"

echo "Building multi-platform image: $IMAGE"
echo "Platforms: $PLATFORMS"

docker run --rm \
  -v $(pwd):/workspace \
  -v ~/.docker/config.json:/kaniko/.docker/config.json \
  gcr.io/kaniko-project/executor:latest \
  --dockerfile=/workspace/Dockerfile \
  --context=/workspace \
  --destination=$IMAGE \
  --platform=$PLATFORMS \
  --driver=local \
  --cache=true \
  --cache-repo=gcr.io/myrepo/cache \
  --verbosity=info

echo "Build complete: $IMAGE"
```

## Kubernetes Driver

The Kubernetes driver creates Jobs to build each platform on nodes with the appropriate architecture.

### Prerequisites

1. **Kubernetes Cluster** with multi-architecture nodes
2. **Service Account** with necessary permissions
3. **Registry Credentials** mounted as secrets

### RBAC Configuration

```yaml
# kaniko-rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kaniko-builder
  namespace: default
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kaniko-builder-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log", "services"]
  verbs: ["create", "get", "list", "watch", "delete"]
- apiGroups: ["batch"]
  resources: ["jobs"]
  verbs: ["create", "get", "list", "watch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kaniko-builder-binding
  namespace: default
subjects:
- kind: ServiceAccount
  name: kaniko-builder
  namespace: default
roleRef:
  kind: Role
  name: kaniko-builder-role
  apiGroup: rbac.authorization.k8s.io
```

### Registry Secret

```bash
# Create registry secret
kubectl create secret docker-registry dockerconfigjson \
  --docker-server=https://gcr.io \
  --docker-username=_json_key \
  --docker-password="$(cat gcp-service-account.json)" \
  --namespace=default
```

### Kubernetes Build Configuration

```yaml
# kaniko-build.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: kaniko-multiarch-build
  namespace: default
spec:
  template:
    spec:
      serviceAccountName: kaniko-builder
      containers:
      - name: kaniko
        image: gcr.io/kaniko-project/executor:latest
        args:
        - --dockerfile=/workspace/Dockerfile
        - --context=/workspace
        - --destination=gcr.io/myrepo/myimage:latest
        - --platform=linux/amd64,linux/arm64
        - --driver=k8s
        - --cache=true
        - --cache-repo=gcr.io/myrepo/cache
        - --push-retry=3
        - --push-retry-initial-delay=1000
        - --push-retry-max-delay=30000
        volumeMounts:
        - name: workspace
          mountPath: /workspace
        - name: docker-config
          mountPath: /kaniko/.docker/
          readOnly: true
      volumes:
      - name: workspace
        emptyDir: {}
      - name: docker-config
        secret:
          secretName: dockerconfigjson
      restartPolicy: Never
      nodeSelector:
        # Allow building on any node (remove if you require specific archs)
        kubernetes.io/arch: ""
```

### Advanced Kubernetes Configuration

```yaml
# kaniko-advanced-build.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: kaniko-multiarch-build
  namespace: default
spec:
  backoffLimit: 0
  template:
    spec:
      serviceAccountName: kaniko-builder
      containers:
      - name: kaniko
        image: gcr.io/kaniko-project/executor:latest
        args:
        - --dockerfile=/workspace/Dockerfile
        - --context=/workspace
        - --destination=gcr.io/myrepo/myimage:$(date +%s)
        - --platform=linux/amd64,linux/arm64,linux/s390x
        - --driver=k8s
        - --cache=true
        - --cache-repo=gcr.io/myrepo/cache
        - --cache-ttl=168h
        - --compression=zstd
        - --publish-index=true
        - --index-annotations=org.opencontainers.image.title=MyApp
        - --index-annotations=org.opencontainers.image.version=1.0
        - --push-retry=5
        - --push-retry-initial-delay=2000
        - --push-retry-max-delay=60000
        resources:
          requests:
            memory: "2Gi"
            cpu: "1000m"
          limits:
            memory: "4Gi"
            cpu: "2000m"
        volumeMounts:
        - name: workspace
          mountPath: /workspace
        - name: docker-config
          mountPath: /kaniko/.docker/
          readOnly: true
        - name: build-context
          mountPath: /context
      volumes:
      - name: workspace
        emptyDir: {}
      - name: docker-config
        secret:
          secretName: dockerconfigjson
      - name: build-context
        configMap:
          name: build-context
      restartPolicy: Never
      # Require nodes with specific architectures
      nodeSelector:
        # This will be overridden by the driver per-platform
        kubernetes.io/arch: amd64
      tolerations:
      - key: "arch"
        operator: "Equal"
        value: "arm64"
        effect: "NoSchedule"
```

### Kubernetes Build Script

```bash
#!/bin/bash
# build-k8s.sh

set -e

NAMESPACE="default"
IMAGE="gcr.io/myrepo/myimage:$(date +%s)"
PLATFORMS="linux/amd64,linux/arm64"
MANIFEST_FILE="/tmp/manifest.yaml"

echo "Starting Kubernetes multi-platform build..."
echo "Image: $IMAGE"
echo "Platforms: $PLATFORMS"

# Create build context configmap
kubectl create configmap build-context \
  --from-file=Dockerfile=./Dockerfile \
  --namespace=$NAMESPACE \
  --dry-run=client -o yaml | kubectl apply -f -

# Apply the build job
kubectl apply -f - <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: kaniko-build-$(date +%s)
  namespace: $NAMESPACE
spec:
  template:
    spec:
      serviceAccountName: kaniko-builder
      containers:
      - name: kaniko
        image: gcr.io/kaniko-project/executor:latest
        args:
        - --dockerfile=/workspace/Dockerfile
        - --context=/workspace
        - --destination=$IMAGE
        - --platform=$PLATFORMS
        - --driver=k8s
        - --cache=true
        - --cache-repo=gcr.io/myrepo/cache
        - --push-retry=3
        - --push-retry-initial-delay=1000
        - --push-retry-max-delay=30000
        volumeMounts:
        - name: workspace
          mountPath: /workspace
        - name: docker-config
          mountPath: /kaniko/.docker/
          readOnly: true
      volumes:
      - name: workspace
        emptyDir: {}
      - name: docker-config
        secret:
          secretName: dockerconfigjson
      restartPolicy: Never
EOF

# Wait for job completion
echo "Waiting for build job to complete..."
kubectl wait --for=condition=complete job kaniko-build-$(date +%s) --namespace=$NAMESPACE --timeout=60m

# Get job logs
echo "Build logs:"
kubectl logs job/kaniko-build-$(date +%s) --namespace=$NAMESPACE

# Clean up
kubectl delete job kaniko-build-$(date +%s) --namespace=$NAMESPACE
kubectl delete configmap build-context --namespace=$NAMESPACE

echo "Build completed: $IMAGE"
```

## CI Driver

The CI driver is designed for CI/CD pipeline integration, aggregating digests from existing per-architecture builds.

### GitHub Actions Integration

```yaml
# .github/workflows/multiarch-build.yml
name: Multi-Architecture Build

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

env:
  REGISTRY: ghcr.io
  IMAGE_NAME: ${{ github.repository }}

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up QEMU
      uses: docker/setup-qemu-action@v3
      with:
        platforms: amd64,arm64
    
    - name: Log in to Container Registry
      uses: docker/login-action@v3
      with:
        registry: ${{ env.REGISTRY }}
        username: ${{ github.actor }}
        password: ${{ secrets.GITHUB_TOKEN }}
    
    - name: Build and push per-architecture images
      run: |
        #!/bin/bash
        set -e
        
        PLATFORMS="linux/amd64,linux/arm64"
        DIGESTS_DIR="${{ github.workspace }}/digests"
        
        # Create digests directory
        mkdir -p "$DIGESTS_DIR"
        
        # Build for each platform
        for platform in $(echo $PLATFORMS | tr ',' ' '); do
          echo "Building for $platform..."
          
          docker run --rm \
            -v ${{ github.workspace }}:/workspace \
            -v $DIGESTS_DIR:/output \
            gcr.io/kaniko-project/executor:latest \
            --dockerfile=/workspace/Dockerfile \
            --context=/workspace \
            --destination=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}-${platform//\//-} \
            --platform=$platform \
            --driver=local \
            --cache=true \
            --cache-repo=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}/cache \
            --digest-file=/output/${platform//\//-}.digest
        done
        
        echo "Build artifacts:"
        ls -la $DIGESTS_DIR/
    
    - name: Create and push OCI index
      run: |
        #!/bin/bash
        set -e
        
        DIGESTS_DIR="${{ github.workspace }}/digests"
        
        # Aggregate digests
        echo "Aggregating digests..."
        for digest_file in $DIGESTS_DIR/*.digest; do
          platform=$(basename $digest_file .digest | tr '-' '/')
          digest=$(cat $digest_file)
          echo "$platform: $digest"
        done
        
        # Build and push multi-platform image
        docker run --rm \
          -v ${{ github.workspace }}:/workspace \
          -v $DIGESTS_DIR:/output \
          gcr.io/kaniko-project/executor:latest \
          --dockerfile=/workspace/Dockerfile \
          --context=/workspace \
          --destination=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }} \
          --platform=linux/amd64,linux/arm64 \
          --driver=ci \
          --digests-from=/output \
          --publish-index=true \
          --index-annotations="org.opencontainers.image.title=${{ env.IMAGE_NAME }}" \
          --index-annotations="org.opencontainers.image.revision=${{ github.sha }}"
```

### GitLab CI Integration

```yaml
# .gitlab-ci.yml
stages:
  - build
  - push

variables:
  PLATFORMS: "linux/amd64,linux/arm64"
  DIGESTS_DIR: "${CI_PROJECT_DIR}/digests"

cache:
  paths:
    - .cache/

build_per_arch:
  stage: build
  image: gcr.io/kaniko-project/executor:latest
  variables:
    GIT_STRATEGY: none
  script:
    - |
      #!/bin/bash
      set -e
      
      mkdir -p $DIGESTS_DIR
      
      # Build for each platform
      for platform in $(echo $PLATFORMS | tr ',' ' '); do
        echo "Building for $platform..."
        
        /kaniko/executor \
          --dockerfile=Dockerfile \
          --context=$CI_PROJECT_DIR \
          --destination=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA-${platform//\//-} \
          --platform=$platform \
          --driver=local \
          --cache=true \
          --cache-repo=$CI_REGISTRY_IMAGE/cache \
          --digest-file=$DIGESTS_DIR/${platform//\//-}.digest
      done
      
      echo "Build artifacts:"
      ls -la $DIGESTS_DIR/
  artifacts:
    paths:
      - $DIGESTS_DIR/
    expire_in: 1 hour

push_multiarch:
  stage: push
  image: gcr.io/kaniko-project/executor:latest
  needs:
    - build_per_arch
  script:
    - |
      #!/bin/bash
      set -e
      
      # Build and push multi-platform image
      /kaniko/executor \
        --dockerfile=Dockerfile \
        --context=$CI_PROJECT_DIR \
        --destination=$CI_REGISTRY_IMAGE:$CI_COMMIT_SHA \
        --platform=$PLATFORMS \
        --driver=ci \
        --digests-from=$DIGESTS_DIR \
        --publish-index=true \
        --index-annotations="org.opencontainers.image.title=$CI_PROJECT_NAME" \
        --index-annotations="org.opencontainers.image.revision=$CI_COMMIT_SHA"
  only:
    - main
```

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any
    
    environment {
        REGISTRY = 'gcr.io'
        IMAGE_NAME = 'myrepo/myimage'
        PLATFORMS = 'linux/amd64,linux/arm64'
        DIGESTS_DIR = "${WORKSPACE}/digests"
    }
    
    stages {
        stage('Build Per Architecture') {
            steps {
                script {
                    // Create digests directory
                    sh "mkdir -p ${DIGESTS_DIR}"
                    
                    // Build for each platform
                    for (platform in env.PLATFORMS.split(',')) {
                        sh """
                            docker run --rm \\
                                -v ${WORKSPACE}:/workspace \\
                                -v ${DIGESTS_DIR}:/output \\
                                gcr.io/kaniko-project/executor:latest \\
                                --dockerfile=/workspace/Dockerfile \\
                                --context=/workspace \\
                                --destination=${env.REGISTRY}/${env.IMAGE_NAME}:${env.BUILD_ID}-${platform.replace('/', '-')} \\
                                --platform=${platform.trim()} \\
                                --driver=local \\
                                --cache=true \\
                                --cache-repo=${env.REGISTRY}/${env.IMAGE_NAME}/cache \\
                                --digest-file=/output/${platform.replace('/', '-')}.digest
                        """
                    }
                }
            }
        }
        
        stage('Push Multi-Arch') {
            steps {
                script {
                    // Build and push multi-platform image
                    sh """
                        docker run --rm \\
                            -v ${WORKSPACE}:/workspace \\
                            -v ${DIGESTS_DIR}:/output \\
                            gcr.io/kaniko-project/executor:latest \\
                            --dockerfile=/workspace/Dockerfile \\
                            --context=/workspace \\
                            --destination=${env.REGISTRY}/${env.IMAGE_NAME}:${env.BUILD_ID} \\
                            --platform=${env.PLATFORMS} \\
                            --driver=ci \\
                            --digests-from=/output \\
                            --publish-index=true \\
                            --index-annotations="org.opencontainers.image.title=${env.IMAGE_NAME}" \\
                            --index-annotations="org.opencontainers.image.revision=${env.BUILD_ID}"
                    """
                }
            }
        }
    }
    
    post {
        always {
            echo "Cleaning up..."
            sh "rm -rf ${DIGESTS_DIR}"
        }
    }
}
```

## Driver Comparison

### Local Driver

**Pros:**
- Simple to set up
- Fast for development
- No external dependencies

**Cons:**
- Requires emulation (slower)
- Limited to single machine resources
- Not suitable for production

**Best for:**
- Development and testing
- Small projects
- Quick iterations

### Kubernetes Driver

**Pros:**
- Scalable across cluster
- Native architecture builds (no emulation)
- Production-ready
- Resource management

**Cons:**
- Requires Kubernetes cluster
- More complex setup
- Network overhead

**Best for:**
- Production builds
- Large projects
- High-performance requirements

### CI Driver

**Pros:**
- Native CI/CD integration
- Leverages existing CI infrastructure
- Flexible build strategies
- Artifact management

**Cons:**
- Requires CI environment
- Complex configuration
- Pipeline-specific setup

**Best for:**
- CI/CD pipelines
- Automated builds
- Multi-stage workflows

## Advanced Configuration

### Custom Platform Validation

```bash
# Validate platforms before building
docker run --rm \
  -v $(pwd):/workspace \
  gcr.io/kaniko-project/executor:latest \
  --dockerfile=/workspace/Dockerfile \
  --context=/workspace \
  --destination=gcr.io/myrepo/myimage:latest \
  --platform=linux/amd64,linux/arm64 \
  --driver=local \
  --require-native-nodes=false \
  --verbosity=debug
```

### Error Handling and Retries

```bash
# Robust build with error handling
#!/bin/bash
# build-robust.sh

PLATFORMS="linux/amd64,linux/arm64"
IMAGE="gcr.io/myrepo/myimage:latest"
MAX_RETRIES=3

for attempt in $(seq 1 $MAX_RETRIES); do
    echo "Build attempt $attempt of $MAX_RETRIES"
    
    if docker run --rm \
        -v $(pwd):/workspace \
        gcr.io/kaniko-project/executor:latest \
        --dockerfile=/workspace/Dockerfile \
        --context=/workspace \
        --destination=$IMAGE \
        --platform=$PLATFORMS \
        --driver=local \
        --cache=true \
        --push-retry=5 \
        --push-retry-initial-delay=2000 \
        --push-retry-max-delay=60000; then
        echo "Build successful!"
        exit 0
    else
        echo "Build failed, retrying..."
        sleep 30
    fi
done

echo "Build failed after $MAX_RETRIES attempts"
exit 1
```

### Performance Optimization

```bash
# Optimized production build
docker run --rm \
  -v $(pwd):/workspace \
  gcr.io/kaniko-project/executor:latest \
  --dockerfile=/workspace/Dockerfile \
  --context=/workspace \
  --destination=gcr.io/myrepo/myimage:latest \
  --platform=linux/amd64,linux/arm64 \
  --driver=k8s \
  --cache=true \
  --cache-repo=gcr.io/myrepo/cache \
  --cache-ttl=336h \
  --compression=zstd \
  --compression-level=3 \
  --publish-index=true \
  --push-retry=3 \
  --push-retry-initial-delay=1000 \
  --push-retry-max-delay=30000 \
  --verbosity=info
```

## Troubleshooting

### Common Issues

#### Local Driver Issues

**Problem: QEMU emulation is slow**
```bash
# Solution: Use smaller images or fewer platforms
docker run --rm \
  -v $(pwd):/workspace \
  gcr.io/kaniko-project/executor:latest \
  --dockerfile=/workspace/Dockerfile \
  --context=/workspace \
  --destination=gcr.io/myrepo/myimage:latest \
  --platform=linux/amd64 \
  --driver=local
```

**Problem: Architecture not supported**
```bash
# Check supported architectures
docker run --rm gcr.io/kaniko-project/executor:latest --help | grep platform

# Use supported platforms only
docker run --rm \
  -v $(pwd):/workspace \
  gcr.io/kaniko-project/executor:latest \
  --dockerfile=/workspace/Dockerfile \
  --context=/workspace \
  --destination=gcr.io/myrepo/myimage:latest \
  --platform=linux/amd64,linux/arm64 \
  --driver=local
```

#### Kubernetes Driver Issues

**Problem: Jobs failing to start**
```bash
# Check service account
kubectl get serviceaccount kaniko-builder

# Check RBAC
kubectl get rolebinding kaniko-builder-binding

# Check node selectors
kubectl get nodes -o wide
```

**Problem: Registry authentication errors**
```bash
# Check secret
kubectl get secret dockerconfigjson -o yaml

# Re-create secret if needed
kubectl delete secret dockerconfigjson
kubectl create secret docker-registry dockerconfigjson \
  --docker-server=https://gcr.io \
  --docker-username=_json_key \
  --docker-password="$(cat gcp-service-account.json)"
```

#### CI Driver Issues

**Problem: Digest files not found**
```bash
# Ensure digests directory exists and is accessible
mkdir -p digests
chmod 755 digests

# Verify digest file paths
docker run --rm \
  -v $(pwd):/workspace \
  -v ./digests:/output \
  gcr.io/kaniko-project/executor:latest \
  --driver=ci \
  --digests-from=/output
```

**Problem: CI environment variables not set**
```bash
# Debug CI environment
echo "CI_PROJECT_DIR: $CI_PROJECT_DIR"
echo "REGISTRY: $REGISTRY"
echo "IMAGE_NAME: $IMAGE_NAME"

# Set required variables
export REGISTRY=${REGISTRY:-"gcr.io"}
export IMAGE_NAME=${IMAGE_NAME:-"myrepo/myimage"}
```

### Debug Commands

```bash
# Enable debug logging
docker run --rm \
  -v $(pwd):/workspace \
  gcr.io/kaniko-project/executor:latest \
  --dockerfile=/workspace/Dockerfile \
  --context=/workspace \
  --destination=gcr.io/myrepo/myimage:latest \
  --platform=linux/amd64,linux/arm64 \
  --driver=local \
  --verbosity=debug

# Check build context
docker run --rm \
  -v $(pwd):/workspace \
  gcr.io/kaniko-project/executor:latest \
  --dockerfile=/workspace/Dockerfile \
  --context=/workspace \
  --no-push \
  --verbosity=info

# Validate Dockerfile
docker run --rm \
  -v $(pwd):/workspace \
  gcr.io/kaniko-project/executor:latest \
  --dockerfile=/workspace/Dockerfile \
  --context=/workspace \
  --no-push \
  --verbosity=debug
```

## Migration Guide

### From Single-Arch to Multi-Arch

1. **Update Dockerfile** (if needed):
   ```dockerfile
   # Add platform-specific instructions if needed
   FROM --platform=$BUILDPLATFORM debian:bullseye AS builder
   RUN apt-get update && apt-get install -y build-essential
   ```

2. **Update build scripts**:
   ```bash
   # Before (single arch)
   docker run --rm \
     -v $(pwd):/workspace \
     gcr.io/kaniko-project/executor:latest \
     --dockerfile=/workspace/Dockerfile \
     --context=/workspace \
     --destination=gcr.io/myrepo/myimage:latest
   
   # After (multi arch)
   docker run --rm \
     -v $(pwd):/workspace \
     gcr.io/kaniko-project/executor:latest \
     --dockerfile=/workspace/Dockerfile \
     --context=/workspace \
     --destination=gcr.io/myrepo/myimage:latest \
     --platform=linux/amd64,linux/arm64 \
     --driver=local
   ```

3. **Update CI/CD pipelines**:
   ```yaml
   # GitHub Actions example
   - name: Build multi-platform
     run: |
       docker run --rm \
         -v ${{ github.workspace }}:/workspace \
         gcr.io/kaniko-project/executor:latest \
         --dockerfile=/workspace/Dockerfile \
         --context=/workspace \
         --destination=${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }} \
         --platform=linux/amd64,linux/arm64 \
         --driver=local \
         --publish-index=true
   ```

### From Docker Manifest List to OCI Index

```bash
# Check current manifest type
crane manifest gcr.io/myrepo/myimage:latest | jq '.mediaType'

# Should be: "application/vnd.oci.image.index.v1+json"

# If not, rebuild with OCI mode
docker run --rm \
  -v $(pwd):/workspace \
  gcr.io/kaniko-project/executor:latest \
  --dockerfile=/workspace/Dockerfile \
  --context=/workspace \
  --destination=gcr.io/myrepo/myimage:latest \
  --platform=linux/amd64,linux/arm64 \
  --driver=local \
  --oci-mode=oci \
  --publish-index=true
```

## Conclusion

Kaniko's multi-platform support provides flexible options for building container images across different architectures. Choose the driver that best fits your use case:

- **Local**: Development and testing
- **Kubernetes**: Production and scalable builds
- **CI**: Pipeline integration and automation

For more information, see the [Kaniko documentation](https://github.com/GoogleContainerTools/kaniko) and [OCI specification](https://github.com/opencontainers/image-spec).