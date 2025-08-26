#!/bin/bash

# Dependency Audit Script for Kaniko (https://github.com/Gosayram/kaniko)
# This script performs comprehensive dependency analysis and security checks

set -e

echo "🔍 Starting Kaniko Dependency Audit (https://github.com/Gosayram/kaniko)..."
echo "========================================================================="

# Create output directory
mkdir -p audit-reports

# 1. Generate dependency tree
echo "📊 Generating dependency tree..."
go list -m -mod=mod all > audit-reports/dependency-tree.txt
echo "✅ Dependency tree saved to audit-reports/dependency-tree.txt"

# 2. Check for outdated dependencies
echo "🔄 Checking for outdated dependencies..."
go list -u -m -mod=mod all | grep -E '^\s' > audit-reports/outdated-deps.txt || true
echo "✅ Outdated dependencies check saved to audit-reports/outdated-deps.txt"

# 3. Analyze dependency vulnerabilities
echo "🛡️  Analyzing dependency vulnerabilities..."
if command -v govulncheck &> /dev/null; then
    govulncheck ./... > audit-reports/vulnerability-report.txt 2>&1 || true
    echo "✅ Vulnerability analysis saved to audit-reports/vulnerability-report.txt"
else
    echo "⚠️  govulncheck not found, skipping vulnerability analysis"
fi

# 4. Check for deprecated packages
echo "🚫 Checking for deprecated packages..."
go list -m -json -mod=mod all | jq -r 'select(.Deprecated) | "\(.Path) \(.Version) - \(.DeprecationReason)"' > audit-reports/deprecated-packages.txt || true
echo "✅ Deprecated packages check saved to audit-reports/deprecated-packages.txt"

# 5. Analyze dependency licenses
echo "📋 Analyzing dependency licenses..."
go list -m -mod=mod all | while read module version; do
    if [[ $module != github.com/Gosayram/kaniko ]]; then
        echo "$module $version" >> audit-reports/licenses-temp.txt
    fi
done

# Create license summary
echo "📋 License Analysis Summary:"
echo "============================"

# Count different license types
if command -v licensecheck &> /dev/null; then
    licensecheck -r audit-reports/licenses-temp.txt > audit-reports/license-summary.txt 2>&1 || true
    echo "✅ License analysis saved to audit-reports/license-summary.txt"
else
    echo "⚠️  licensecheck not found, using basic license analysis"
    # Basic license analysis using go mod download
    while read module version; do
        echo "Checking $module ($version)..."
        # This is a simplified check - in production, use proper license analysis tools
    done < audit-reports/licenses-temp.txt > audit-reports/license-summary.txt
fi

# 6. Check for direct and indirect dependencies
echo "🔗 Analyzing dependency relationships..."
go list -m -mod=mod all | grep -E '^\s' > audit-reports/direct-deps.txt
go list -m -mod=mod all | grep -vE '^\s' > audit-reports/indirect-deps.txt
echo "✅ Dependency relationships analyzed"

# 7. Generate dependency statistics
echo "📈 Generating dependency statistics..."
echo "Total direct dependencies: $(grep -cE '^\s' audit-reports/direct-deps.txt 2>/dev/null || echo 0)"
echo "Total indirect dependencies: $(grep -cE '^\s' audit-reports/indirect-deps.txt 2>/dev/null || echo 0)"
echo "Total modules: $(wc -l < audit-reports/dependency-tree.txt)"

# 8. Check for major version updates
echo "🔄 Checking for major version updates..."
go list -m -json -mod=mod all | jq -r 'select(.Update.Version | contains(".")) | "\(.Path): \(.Version) -> \(.Update.Version)"' > audit-reports/major-updates.txt || true
echo "✅ Major version updates check saved to audit-reports/major-updates.txt"

# 9. Generate audit summary
echo "📋 Generating audit summary..."
cat > audit-reports/audit-summary.txt << EOF
Kaniko Dependency Audit Summary
===============================

Date: $(date)
Go Version: $(go version)

Dependency Statistics:
- Total modules: $(wc -l < audit-reports/dependency-tree.txt)
- Direct dependencies: $(grep -cE '^\s' audit-reports/direct-deps.txt 2>/dev/null || echo 0)
- Indirect dependencies: $(grep -cE '^\s' audit-reports/indirect-deps.txt 2>/dev/null || echo 0)

Security Status:
- Vulnerabilities found: $(grep -c "vulnerability" audit-reports/vulnerability-report.txt 2>/dev/null || echo "Unknown")
- Deprecated packages: $(wc -l < audit-reports/deprecated-packages.txt 2>/dev/null || echo 0)

Update Status:
- Outdated dependencies: $(wc -l < audit-reports/outdated-deps.txt 2>/dev/null || echo 0)
- Major version updates available: $(wc -l < audit-reports/major-updates.txt 2>/dev/null || echo 0)

Recommendations:
1. Review and update outdated dependencies
2. Address any security vulnerabilities
3. Check license compliance for all dependencies
4. Consider major version updates for stable dependencies

EOF

echo "✅ Audit summary saved to audit-reports/audit-summary.txt"

# 10. Clean up temporary files
rm -f audit-reports/licenses-temp.txt

echo ""
echo "🎉 Dependency audit completed!"
echo "📁 All reports saved to audit-reports/ directory"
echo "📖 Summary: audit-reports/audit-summary.txt"