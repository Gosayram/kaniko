# Security Policy

Thank you for helping make Kaniko more secure. We appreciate your efforts and are committed to working with you to resolve any potential issues in a timely manner.

## Security Vulnerabilities

If you discover a security vulnerability, please send an email to security@kaniko-project.org. All security vulnerabilities will be promptly addressed.

### Reporting a Vulnerability

Please include the following information in your vulnerability report:

1. A description of the vulnerability and its potential impact
2. Steps to reproduce the vulnerability
3. Proof-of-concept or exploit code (if available)
4. Your preferred contact information (if you wish to remain anonymous)

## Security Scanning

We use multiple security scanning tools to maintain the security of our codebase:

### Trivy Vulnerability Scanner
- **Purpose**: Scans for vulnerabilities in dependencies and filesystem
- **Configuration**: `trivy.yaml`
- **Frequency**: On every push, pull request, and weekly schedule
- **Output**: SARIF format uploaded to GitHub Security tab

### Code Quality Analysis
- **Tool**: golangci-lint
- **Configuration**: `.golangci.yml`
- **Focus**: Security-focused linters, code quality, and best practices
- **Frequency**: On every push and pull request

### Dependency Management
- **Tools**: Go modules, go-licenses
- **Checks**: 
  - Dependency vulnerability scanning
  - License compliance verification
  - SBOM generation
- **Frequency**: On every push and pull request

### Secret Scanning
- **Tool**: Trivy with secret scanning enabled
- **Focus**: Detects hardcoded secrets, API keys, and sensitive information
- **Frequency**: On every push and pull request

### CodeQL Analysis
- **Tool**: GitHub CodeQL
- **Focus**: Static Application Security Testing (SAST)
- **Languages**: Go
- **Frequency**: Weekly scheduled scans

## Security Best Practices

### For Contributors

1. **Follow Secure Coding Guidelines**
   - Use parameterized queries to prevent injection attacks
   - Validate all user inputs
   - Implement proper error handling without exposing sensitive information

2. **Dependency Management**
   - Keep dependencies up to date
   - Regularly review and update third-party packages
   - Use Go modules for dependency management

3. **Secret Management**
   - Never commit secrets to version control
   - Use environment variables or secure secret management systems
   - Regularly scan for hardcoded secrets

4. **Container Security**
   - Use minimal base images
   - Run containers as non-root users when possible
   - Implement proper file permissions

### For Maintainers

1. **Regular Security Audits**
   - Conduct periodic security reviews
   - Monitor vulnerability databases for related issues
   - Keep security tools and configurations up to date

2. **Incident Response**
   - Establish clear incident response procedures
   - Maintain communication channels for security issues
   - Document security incidents and resolutions

3. **Security Testing**
   - Integrate security testing into CI/CD pipeline
   - Perform penetration testing on major releases
   - Validate security controls regularly

## Vulnerability Disclosure

### Disclosure Timeline

- **Initial Response**: Within 24 hours of report
- **Initial Assessment**: Within 48 hours
- **Fix Development**: Within 7 days for critical issues
- **Release**: Within 14 days for critical issues

### Severity Levels

- **Critical**: Remote code execution, privilege escalation
- **High**: Data exposure, authentication bypass
- **Medium**: Information disclosure, denial of service
- **Low**: Minor security issues, information leakage

## Security Resources

### Tools and Services

- [Trivy](https://github.com/aquasecurity/trivy) - Vulnerability scanner
- [golangci-lint](https://golangci-lint.run/) - Go linter
- [CodeQL](https://codeql.github.com/) - Static analysis
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/) - Dependency vulnerability scanning

### References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Go Security Best Practices](https://go.dev/doc/security)
- [Container Security Best Practices](https://docs.docker.com/develop/security/)

## Contact

For security-related questions or concerns:
- Email: security@kaniko-project.org
- Security Policy: [SECURITY.md](./SECURITY.md)
- Vulnerability Disclosure: See above

## Acknowledgments

We thank the security research community for their contributions to making Kaniko more secure. Special thanks to those who responsibly disclose vulnerabilities following our security policy.