# Multi-Platform Guide

This guide provides step-by-step instructions for using Kaniko's multi-platform features with local, Kubernetes, and CI drivers. See [.plan-idea-docs.md](../.plan-idea-docs.md) for status.

## Prerequisites
- Kaniko executor image: `gcr.io/kaniko-project/executor:latest`
- Docker for local validation.
- For k8s: kubectl, cluster with multi-arch nodes.
- For CI: GitHub Actions or similar with matrix strategy.

## Basic Multi-Platform Build (Local Driver)
Use `--multi-platform` to specify platforms, `--driver=local` (single-arch host).

```bash
kaniko --context=dir:.
  --dockerfile=Dockerfile
  --destination=registry/app:tag
  --multi-platform=linux/amd64,linux/arm64
  --driver=local
  --publish-index=true  # Create OCI index
  --oci-mode=oci
```

Validate:
```bash
oras manifest fetch registry/app:tag --media-type application/vnd.oci.image.index.v1+json | jq .
```

## Kubernetes Driver
Requires k8s cluster with multi-arch nodes (e.g., GKE with arm64 nodes).

### Setup RBAC
Create ServiceAccount and RoleBinding (minimal):
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kaniko-builder
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: kaniko-editor
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["batch"]
  resources: ["jobs"]
  verbs: ["create", "get", "list", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: kaniko-editor-binding
subjects:
- kind: ServiceAccount
  name: kaniko-builder
roleRef:
  kind: Role
  name: kaniko-editor
  apiGroup: rbac.authorization.k8s.io
```

### Secret for Registry
Create dockerconfigjson secret:
```bash
kubectl create secret docker-registry dockerconfigjson \
  --docker-server=registry.io \
  --docker-username=user \
  --docker-password=pass \
  --dry-run=client -o yaml | kubectl apply -f -
```

Mount in Job (see plan example):
```yaml
spec:
  template:
    spec:
      serviceAccountName: kaniko-builder
      volumes:
      - name: docker-config
        secret:
          secretName: dockerconfigjson
      containers:
      - name: kaniko
        volumeMounts:
        - name: docker-config
          mountPath: /kaniko/.docker/
        env:
        - name: DOCKER_CONFIG
          value: /kaniko/.docker/
```

### Run Job
Use template like k8s-job.yaml, update for multi-platform:
```yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: multiarch-kaniko
spec:
  template:
    spec:
      serviceAccountName: kaniko-builder
      containers:
      - name: kaniko
        image: gcr.io/kaniko-project/executor:latest
        args:
        - --context=git://github.com/org/repo#main
        - --dockerfile=Dockerfile
        - --destination=registry/app:tag
        - --multi-platform=linux/amd64,linux/arm64
        - --driver=k8s
        - --publish-index=true
        - --oci-mode=oci
        volumeMounts:
        - name: docker-config
          mountPath: /kaniko/.docker/
        env:
        - name: DOCKER_CONFIG
          value: /kaniko/.docker/
      volumes:
      - name: docker-config
        secret:
          secretName: dockerconfigjson
      restartPolicy: Never
  backoffLimit: 1
```

Apply: `kubectl apply -f job.yaml`, wait `kubectl wait --for=condition=complete job/multiarch-kaniko`.

Validate index as above.

## CI Driver (GitHub Actions Example)
Use matrix for per-arch builds, then CI driver to aggregate.

### Workflow Example (.github/workflows/multiarch.yml)
```yaml
name: Multi-Arch Build
on:
  push:
    branches: [ main ]
jobs:
  matrix-build:
    strategy:
      matrix:
        platform: [linux/amd64, linux/arm64]
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - name: Build for platform
      run: |
        docker buildx build --platform ${{ matrix.platform }} --tag registry/app:${{ matrix.platform }} --load .
        echo "${{ matrix.platform }}.digest" >> $GITHUB_WORKSPACE/digests/digests.txt  # Or use --output type=image,push
    - name: Save digest
      id: digest
      run: |
        digest=$(docker image inspect registry/app:${{ matrix.platform }} --format '{{.Id}}' | cut -d: -f2)
        echo "sha256:${digest}" > digests/${{ matrix.platform }}.digest
    - uses: actions/upload-artifact@v4
      with:
        name: digests
        path: digests/
  aggregate:
    needs: matrix-build
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    - uses: actions/download-artifact@v4
      with:
        name: digests
        path: digests/
    - name: Aggregate with Kaniko CI
      run: |
        kaniko --context=dir:.
          --dockerfile=Dockerfile
          --destination=registry/app:tag
          --driver=ci
          --digests-from=./digests
          --publish-index=true
          --oci-mode=oci
```

## Troubleshooting
- **No nodes for arch**: Ensure cluster has multi-arch nodes (GKE: enable arm64).
- **Secret not found**: Check RBAC, secret exists in namespace.
- **Digest not found**: Verify kaniko prints "sha256:..." in logs for k8s, or .digest files for CI.
- **Timeout**: Increase defaultTimeout in k8s.go if builds long.

See advanced-configuration.md for flag combos.