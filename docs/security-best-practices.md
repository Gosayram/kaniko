# Kaniko Security Best Practices

This guide covers security best practices for using Kaniko in production environments, including image signing with cosign, registry authentication, and secure configuration.

## Security Principles

Kaniko follows a **security-first approach** with these core principles:

1. **No Privileged Operations**: No qemu/binfmt emulation or privileged mounts
2. **Safe Defaults**: Security-sensitive features require explicit opt-in
3. **Minimal Attack Surface**: No execution of arbitrary code during builds
4. **Content Trust**: Digest-based verification prevents tampering

## Image Signing with Cosign

Kaniko supports optional image signing using [cosign](https://docs.sigstore.dev/cosign/overview/) from the Sigstore project.

### Basic Signing Configuration

```bash
# Enable image signing (optional feature)
--sign-images=true

# Use keyless signing (recommended for most users)
# No additional configuration needed - uses Sigstore's public good infrastructure

# Or use key-based signing for offline environments
--cosign-key-path=/secrets/cosign.key
--cosign-key-password=secret  # Optional password protection
```

### Keyless Signing (Recommended)

Keyless signing uses Sigstore's public good infrastructure and doesn't require key management:

```bash
kaniko --sign-images=true \
       --destination=ghcr.io/org/app:1.2.3 \
       --context=dir:///workspace \
       --dockerfile=Dockerfile
```

### Key-Based Signing

For air-gapped environments or specific compliance requirements:

```bash
# Generate a new key pair
cosign generate-key-pair

# Use the generated key for signing
kaniko --sign-images=true \
       --cosign-key-path=cosign.key \
       --destination=ghcr.io/org/app:1.2.3
```

### Verifying Signed Images

```bash
# Verify keyless signatures
cosign verify ghcr.io/org/app:1.2.3

# Verify key-based signatures  
cosign verify --key cosign.pub ghcr.io/org/app:1.2.3

# Verify with specific identity (keyless)
cosign verify --certificate-identity=email@example.com ghcr.io/org/app:1.2.3
```

## Registry Authentication Security

### Secure Credential Management

**Kubernetes Secrets** (Recommended):
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: registry-credentials
type: kubernetes.io/dockerconfigjson
data:
  .dockerconfigjson: <base64-encoded-docker-config>
```

**Cloud Workload Identity** (Most Secure):
- **GCP**: Workload Identity
- **AWS**: IAM Roles for Service Accounts (IRSA)  
- **Azure**: Pod Identity
- **GitHub**: OIDC Token

### Registry Security Best Practices

1. **Use HTTPS Always**: Never use insecure registries in production
2. **Certificate Validation**: Avoid `--skip-tls-verify` in production
3. **Minimal Permissions**: Registry credentials should have push-only permissions
4. **Regular Rotation**: Rotate credentials and keys regularly

## Multi-Platform Security

### Architecture-Specific Considerations

```bash
# Require native architecture nodes (recommended for security)
--require-native-nodes=true

# Architecture-specific cache repositories
--arch-cache-repo-suffix=-${ARCH}

# Platform validation prevents accidental misconfigurations
--multi-platform=linux/amd64,linux/arm64  # Explicit platform specification
```

### Kubernetes Security Context

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  runAsGroup: 1000
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  readOnlyRootFilesystem: true
```

## Network Security

### Egress Controls

```bash
# Use registry mirrors for controlled environments
--registry-mirror=mirror.example.com

# Configure allowed registries
--insecure-registries=registry.example.com:5000

# Set up corporate CA certificates
--registries-certificates=/etc/ssl/certs/corporate-ca.crt
```

### Proxy Configuration

```bash
# Configure HTTP proxy
HTTP_PROXY=http://proxy.example.com:8080
HTTPS_PROXY=http://proxy.example.com:8080
NO_PROXY=localhost,127.0.0.1,.cluster.local
```

## Build Security

### Dockerfile Security Best Practices

1. **Use Official Base Images**: Prefer official, signed base images
2. **Multi-Stage Builds**: Reduce attack surface in final images
3. **Non-Root Users**: Always run as non-root in final images
4. **Minimal Packages**: Only install necessary dependencies
5. **Regular Updates**: Keep base images and packages updated

### Example Secure Dockerfile

```dockerfile
# Use official, signed base image
FROM gcr.io/distroless/base:nonroot

# Set non-root user
USER nonroot:nonroot

# Copy application (built in earlier stage)
COPY --from=builder /app /app

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/app/healthcheck"]

# Entrypoint without shell
ENTRYPOINT ["/app/main"]
```

## Runtime Security

### Read-Only Filesystem

```bash
# Enable read-only root filesystem
--read-only-rootfs=true
```

### Resource Limits

```yaml
# Kubernetes resource limits
resources:
  limits:
    cpu: "2"
    memory: "4Gi"
  requests:
    cpu: "1"
    memory: "2Gi"
```

## Compliance and Auditing

### SBOM Generation

Kaniko integrates with Syft for Software Bill of Materials (SBOM) generation:

```bash
# Generate SBOM as part of CI/CD pipeline
syft ghcr.io/org/app:1.2.3 -o spdx-json > sbom.json
```

### Audit Logging

```bash
# Enable detailed audit logging
--verbosity=debug

# Log format options
--log-format=json
--log-timestamp=true
```

## Security Scanning

### Integration with Security Tools

**Trivy** (Vulnerability Scanning):
```bash
trivy image ghcr.io/org/app:1.2.3
```

**Grype** (Vulnerability Scanning):
```bash
grype ghcr.io/org/app:1.2.3
```

**Snyk** (Vulnerability Scanning):
```bash
snyk container test ghcr.io/org/app:1.2.3
```

## Incident Response

### Security Incident Procedures

1. **Revoke Compromised Credentials**: Immediately rotate all affected keys
2. **Invalidate Signed Images**: Use cosign to revoke signatures
3. **Scan for Vulnerabilities**: Perform comprehensive security scans
4. **Update Base Images**: Rebuild with patched base images
5. **Audit Logs**: Review build and access logs

### Cosign Key Revocation

```bash
# Revoke a compromised key
cosign revoke --key compromised.key ghcr.io/org/app:1.2.3

# Generate new key pair
cosign generate-key-pair

# Re-sign images with new key
kaniko --sign-images=true --cosign-key-path=new.key --destination=ghcr.io/org/app:1.2.3
```

## Regulatory Compliance

### GDPR Compliance

- **Data Minimization**: Only include necessary data in images
- **Right to Erasure**: Implement image deletion procedures
- **Log Retention**: Configure appropriate log retention periods

### HIPAA Compliance

- **Encryption**: Ensure data encryption in transit and at rest
- **Access Controls**: Strict access control to registry and build environments
- **Audit Trails**: Comprehensive logging of all operations

### SOC 2 Compliance

- **Security Policies**: Documented security policies and procedures
- **Access Reviews**: Regular access control reviews
- **Incident Response**: Documented incident response procedures

## Security Configuration Checklist

### ✅ Pre-Build Checklist

- [ ] Base images from trusted sources
- [ ] Dockerfile security best practices applied
- [ ] Multi-stage builds configured
- [ ] Non-root user set in final image
- [ ] Minimal packages installed

### ✅ Build Checklist

- [ ] Image signing enabled (if required)
- [ ] Registry authentication configured securely
- [ ] Network security controls in place
- [ ] Resource limits configured
- [ ] Read-only filesystem enabled

### ✅ Post-Build Checklist

- [ ] Security scanning completed
- [ ] SBOM generated and stored
- [ ] Images signed and verified
- [ ] Access logs reviewed
- [ ] Compliance requirements met

## Troubleshooting Security Issues

### Common Security Issues

**Registry Authentication Failures**:
```bash
# Error: unauthorized access
# Solution: Verify credentials and permissions
```

**Certificate Validation Errors**:
```bash
# Error: certificate signed by unknown authority
# Solution: Add corporate CA certificate
```

**Cosign Signing Failures**:
```bash
# Error: cosign not found
# Solution: Install cosign or disable signing
```

### Debugging Security Configuration

```bash
# Enable debug logging for security operations
--verbosity=debug

# Dry-run to validate security configuration
--dry-run

# Test registry connectivity
--registry-check=true
```

## References

- [Cosign Documentation](https://docs.sigstore.dev/cosign/overview/)
- [Sigstore Project](https://www.sigstore.dev/)
- [OCI Security Specifications](https://github.com/opencontainers/image-spec/security)
- [NIST Container Security](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)

## Support

For security issues or vulnerabilities:

1. **Report Vulnerabilities**: security@kaniko.example.com
2. **Emergency Response**: Follow incident response procedures
3. **Documentation Updates**: Keep this guide updated with latest practices

---

*This security guide reflects best practices as of Kaniko version 1.24.1. Security requirements may evolve, and organizations should regularly review and update their security practices.*