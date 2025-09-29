#!/bin/bash

# Automated Testing and Vulnerability Scanning Script for Kaniko (https://github.com/Gosayram/kaniko)
# This script performs comprehensive testing, security scanning, and quality checks

set -e

echo "🚀 Starting Kaniko Automated Testing and Vulnerability Scanning (https://github.com/Gosayram/kaniko)..."
echo "================================================================================================"

# Create output directory
mkdir -p test-results

# 1. Run unit tests
echo "🧪 Running unit tests..."
go test -v -timeout 30m ./... -coverprofile=test-results/coverage.out 2>&1 | tee test-results/unit-tests.log
echo "✅ Unit tests completed"

# 2. Run integration tests
echo "🔗 Running integration tests..."
if [ -d "integration" ]; then
    cd integration
    go test -v -timeout 60m ./... 2>&1 | tee ../test-results/integration-tests.log
    cd ..
    echo "✅ Integration tests completed"
else
    echo "⚠️  Integration tests directory not found, skipping"
fi

# 3. Generate test coverage report
echo "📊 Generating test coverage report..."
go tool cover -html=test-results/coverage.out -o test-results/coverage.html
echo "✅ Coverage report generated: test-results/coverage.html"

# 4. Run security vulnerability scan
echo "🛡️  Running security vulnerability scan..."
if command -v govulncheck &> /dev/null; then
    govulncheck ./... 2>&1 | tee test-results/vulnerability-scan.log
    echo "✅ Security vulnerability scan completed"
else
    echo "⚠️  govulncheck not found, skipping vulnerability scan"
fi

# 5. Run static analysis
echo "🔍 Running static analysis..."
if command -v golangci-lint &> /dev/null; then
    golangci-lint run --timeout 5m 2>&1 | tee test-results/static-analysis.log
    echo "✅ Static analysis completed"
else
    echo "⚠️  golangci-lint not found, skipping static analysis"
fi

# 6. Run dependency check
echo "📦 Running dependency check..."
go list -json -deps ./... | jq -r '.Deps[] | select(.Indirect != true) | .Path' | sort -u > test-results/dependencies.txt
echo "✅ Dependency check completed"

# 7. Run race condition detection
echo "⚡ Running race condition detection..."
go test -race -v ./... 2>&1 | tee test-results/race-tests.log
echo "✅ Race condition detection completed"

# 8. Run benchmark tests
echo "📈 Running benchmark tests..."
go test -bench=. -benchmem ./... 2>&1 | tee test-results/benchmarks.log
echo "✅ Benchmark tests completed"

# 9. Check for TODO comments
echo "📝 Checking for TODO comments..."
find . -name "*.go" -not -path "./vendor/*" -not -path "./.git/*" | xargs grep -n "TODO\|FIXME\|HACK" > test-results/todo-comments.txt
echo "✅ TODO comments check completed"

# 10. Check for common code issues
echo "🔧 Checking for common code issues..."
go vet ./... 2>&1 | tee test-results/vet-results.log
echo "✅ Code vetting completed"

# 11. Generate test summary
echo "📋 Generating test summary..."
cat > test-results/test-summary.txt << EOF
Kaniko Automated Testing and Vulnerability Scanning Summary
==========================================================

Date: $(date)
Go Version: $(go version)

Test Results:
- Unit Tests: $([ -f test-results/unit-tests.log ] && grep -c "PASS:" test-results/unit-tests.log || echo "N/A")
- Integration Tests: $([ -f test-results/integration-tests.log ] && grep -c "PASS:" test-results/integration-tests.log || echo "N/A")
- Test Coverage: $([ -f test-results/coverage.out ] && go tool cover -func=test-results/coverage.out | grep "total:" | awk '{print $3}' || echo "N/A")

Security Status:
- Vulnerabilities Found: $([ -f test-results/vulnerability-scan.log ] && grep -c "vulnerability" test-results/vulnerability-scan.log || echo "Unknown")
- Static Analysis Issues: $([ -f test-results/static-analysis.log ] && grep -c "error\|warning" test-results/static-analysis.log || echo "0")

Code Quality:
- Vet Issues: $([ -f test-results/vet-results.log ] && grep -c "error" test-results/vet-results.log || echo "0")
- TODO Comments: $(wc -l < test-results/todo-comments.txt 2>/dev/null || echo "0")

Performance:
- Benchmarks: $([ -f test-results/benchmarks.log ] && grep -c "PASS:" test-results/benchmarks.log || echo "N/A")

Recommendations:
1. Address any security vulnerabilities found
2. Fix static analysis issues
3. Improve test coverage if below 80%
4. Review and address TODO comments
5. Optimize performance based on benchmark results

EOF

echo "✅ Test summary saved to test-results/test-summary.txt"

# 12. Clean up temporary files
echo "🧹 Cleaning up temporary files..."
rm -f test-results/coverage.out

echo ""
echo "🎉 Automated testing and vulnerability scanning completed!"
echo "📁 All results saved to test-results/ directory"
echo "📖 Summary: test-results/test-summary.txt"