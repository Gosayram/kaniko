#!/bin/bash

# Debug multi-platform builds in Kaniko
# Usage: ./debug-multi-platform.sh [kaniko-debug-directory]

set -euo pipefail

DEBUG_DIR="${1:-$(pwd)/debug}"
OUTPUT_FILE="multi-platform-debug-$(date +%Y%m%d-%H%M%S).txt"

echo "=== Kaniko Multi-Platform Debug ==="
echo "Debug started at: $(date)"
echo "Debug directory: $DEBUG_DIR"
echo "Output file: $OUTPUT_FILE"
echo ""

# Check if debug directory exists
if [ ! -d "$DEBUG_DIR" ]; then
    echo "Error: Debug directory not found: $DEBUG_DIR"
    echo "Please run a Kaniko build with debug mode enabled first."
    exit 1
fi

# Function to analyze multi-platform coordination
analyze_multiplatform_coordination() {
    echo "=== Multi-Platform Coordination Analysis ==="
    
    if [ -f "$DEBUG_DIR/kaniko-debug-*.log" ]; then
        echo "Analyzing multi-platform coordination..."
        
        # Extract coordinator logs
        echo "Coordinator Logs:"
        echo "-----------------"
        grep -i "multiplatform" "$DEBUG_DIR/kaniko-debug-*.log" | tail -20
        
        # Extract platform information
        echo ""
        echo "Platform Information:"
        echo "---------------------"
        grep -o "platform: [a-zA-Z0-9/]*" "$DEBUG_DIR/kaniko-debug-*.log" | sort | uniq | while read -r platform; do
            echo "  - $platform"
        done
        
        # Count platforms
        platform_count=$(grep -o "platform: [a-zA-Z0-9/]*" "$DEBUG_DIR/kaniko-debug-*.log" | sort | uniq | wc -l)
        echo ""
        echo "Total platforms detected: $platform_count"
        
        # Extract driver information
        echo ""
        echo "Driver Information:"
        echo "-------------------"
        grep -o "Using driver: [a-zA-Z0-9]*" "$DEBUG_DIR/kaniko-debug-*.log" | tail -5
        
        # Extract build status
        echo ""
        echo "Build Status:"
        echo "-------------"
        grep -E "(Starting|Successfully|Failed|Error)" "$DEBUG_DIR/kaniko-debug-*.log" | grep -i multiplatform | tail -10
        
    else
        echo "No main debug log found"
    fi
    echo ""
}

# Function to analyze Kubernetes driver operations
analyze_kubernetes_driver() {
    echo "=== Kubernetes Driver Analysis ==="
    
    if [ -d "$DEBUG_DIR/multi-platform" ] && [ -f "$DEBUG_DIR/multi-platform/k8s-driver.log" ]; then
        echo "Analyzing Kubernetes driver operations..."
        
        echo "Kubernetes Driver Logs:"
        echo "-----------------------"
        tail -50 "$DEBUG_DIR/multi-platform/k8s-driver.log"
        
        # Extract job creation information
        echo ""
        echo "Job Creation Summary:"
        echo "---------------------"
        grep -o "Created job [a-zA-Z0-9-]* for platform" "$DEBUG_DIR/multi-platform/k8s-driver.log" | tail -10
        
        # Extract job completion information
        echo ""
        echo "Job Completion Summary:"
        echo "-----------------------"
        grep -o "Successfully retrieved digest for [a-zA-Z0-9/]*" "$DEBUG_DIR/multi-platform/k8s-driver.log" | tail -10
        
        # Extract error information
        echo ""
        echo "Error Summary:"
        echo "--------------"
        grep -i "error\|failed" "$DEBUG_DIR/multi-platform/k8s-driver.log" | tail -10
        
        # Calculate success rate
        total_jobs=$(grep -o "Created job [a-zA-Z0-9-]* for platform" "$DEBUG_DIR/multi-platform/k8s-driver.log" | wc -l)
        successful_jobs=$(grep -o "Successfully retrieved digest for [a-zA-Z0-9/]*" "$DEBUG_DIR/multi-platform/k8s-driver.log" | wc -l)
        
        if [ "$total_jobs" -gt 0 ]; then
            success_rate=$(echo "scale=2; $successful_jobs * 100 / $total_jobs" | bc)
            echo ""
            echo "Success Rate: $success_rate% ($successful_jobs/$total_jobs jobs completed)"
        fi
        
    else
        echo "No Kubernetes driver logs found"
    fi
    echo ""
}

# Function to analyze OCI index operations
analyze_oci_index_operations() {
    echo "=== OCI Index Operations Analysis ==="
    
    if [ -d "$DEBUG_DIR/oci-operations" ] && [ -f "$DEBUG_DIR/oci-operations/index-building.log" ]; then
        echo "Analyzing OCI index operations..."
        
        echo "Index Building Logs:"
        echo "-------------------"
        tail -50 "$DEBUG_DIR/oci-operations/index-building.log"
        
        # Extract manifest information
        echo ""
        echo "Manifest Information:"
        echo "---------------------"
        grep -o "Adding manifest for [a-zA-Z0-9/]*: [a-f0-9]*" "$DEBUG_DIR/oci-operations/index-building.log" | tail -10
        
        # Extract index creation status
        echo ""
        echo "Index Creation Status:"
        echo "----------------------"
        grep -E "(Creating|Successfully|Failed)" "$DEBUG_DIR/oci-operations/index-building.log" | tail -10
        
        # Extract media type information
        echo ""
        echo "Media Type Information:"
        echo "-----------------------"
        grep -o "OCI Mode: [a-zA-Z0-9]*" "$DEBUG_DIR/oci-operations/index-building.log" | tail -5
        grep -o "Legacy Manifest List: [a-zA-Z0-9]*" "$DEBUG_DIR/oci-operations/index-building.log" | tail -5
        
    else
        echo "No OCI index operations logs found"
    fi
    echo ""
}

# Function to analyze platform-specific builds
analyze_platform_builds() {
    echo "=== Platform-Specific Build Analysis ==="
    
    if [ -d "$DEBUG_DIR/build-steps" ]; then
        echo "Analyzing platform-specific builds..."
        
        # Group build steps by platform
        echo "Platform Build Summary:"
        echo "-----------------------"
        
        for step_file in "$DEBUG_DIR/build-steps"/*.log; do
            if [ -f "$step_file" ]; then
                # Extract platform information from filename
                platform=$(echo "$(basename "$step_file")" | grep -oE "linux-[a-zA-Z0-9]*|windows-[a-zA-Z0-9]*|darwin-[a-zA-Z0-9]*" | head -1 || echo "unknown")
                
                # Count lines (build steps)
                step_count=$(wc -l < "$step_file")
                
                # Extract timing information
                timing_info=$(grep -o "took [0-9]*ms" "$step_file" | head -1 || echo "unknown")
                
                echo "  - $platform: $step_count steps, $timing_info"
            fi
        done
        
        # Find slowest platform builds
        echo ""
        echo "Performance Analysis by Platform:"
        echo "----------------------------------"
        
        for step_file in "$DEBUG_DIR/build-steps"/*.log; do
            if [ -f "$step_file" ]; then
                platform=$(echo "$(basename "$step_file")" | grep -oE "linux-[a-zA-Z0-9]*|windows-[a-zA-Z0-9]*|darwin-[a-zA-Z0-9]*" | head -1 || echo "unknown")
                
                # Calculate total time
                total_time=0
                step_count=0
                
                while IFS= read -r line; do
                    if [[ $line =~ took\ ([0-9]*)ms ]]; then
                        total_time=$((total_time + ${BASH_REMATCH[1]}))
                        ((step_count++))
                    fi
                done < "$step_file"
                
                if [ $step_count -gt 0 ]; then
                    avg_time=$((total_time / step_count))
                    echo "  - $platform: ${total_time}ms total, ${avg_time}ms average per step"
                fi
            fi
        done
        
    else
        echo "No build steps directory found"
    fi
    echo ""
}

# Function to identify common multi-platform issues
identify_common_issues() {
    echo "=== Common Multi-Platform Issues ==="
    
    echo "Checking for common issues..."
    
    # Check for platform validation errors
    if [ -f "$DEBUG_DIR/kaniko-debug-*.log" ]; then
        validation_errors=$(grep -i "platform.*validation\|invalid.*platform" "$DEBUG_DIR/kaniko-debug-*.log" | wc -l)
        if [ "$validation_errors" -gt 0 ]; then
            echo "  - Platform validation errors detected: $validation_errors"
            echo "    Review platform format (should be os/arch, e.g., linux/amd64)"
        fi
    fi
    
    # Check for driver errors
    if [ -d "$DEBUG_DIR/multi-platform" ]; then
        driver_errors=$(find "$DEBUG_DIR/multi-platform" -name "*.log" -exec grep -l "error\|failed" {} \; | wc -l)
        if [ "$driver_errors" -gt 0 ]; then
            echo "  - Driver errors detected in $driver_errors log files"
            echo "    Check driver configuration and cluster availability"
        fi
    fi
    
    # Check for OCI index errors
    if [ -d "$DEBUG_DIR/oci-operations" ]; then
        oci_errors=$(find "$DEBUG_DIR/oci-operations" -name "*.log" -exec grep -l "error\|failed" {} \; | wc -l)
        if [ "$oci_errors" -gt 0 ]; then
            echo "  - OCI operation errors detected in $oci_errors log files"
            echo "    Check registry connectivity and permissions"
        fi
    fi
    
    # Check for inconsistent platform builds
    if [ -d "$DEBUG_DIR/build-steps" ]; then
        platform_files=$(find "$DEBUG_DIR/build-steps" -name "*.log" | wc -l)
        if [ "$platform_files" -gt 1 ]; then
            # Check for significant differences in build step counts
            step_counts=$(find "$DEBUG_DIR/build-steps" -name "*.log" -exec wc -l {} + | awk '{print $1}' | sort -n)
            min_steps=$(echo "$step_counts" | head -1)
            max_steps=$(echo "$step_counts" | tail -1)
            
            if [ $((max_steps - min_steps)) -gt 10 ]; then
                echo "  - Significant difference in build step counts detected"
                echo "    Consider optimizing Dockerfile for consistent builds across platforms"
            fi
        fi
    fi
    
    echo ""
    echo "Recommendations:"
    echo "----------------"
    echo "  1. Ensure all platforms use the same base image version"
    echo "  2. Verify cluster has nodes for all target architectures"
    echo "  3. Check registry supports multi-platform manifests"
    echo "  4. Use consistent Dockerfile across all platforms"
    echo "  5. Monitor build times for platform-specific optimizations"
}

# Function to generate performance report
generate_performance_report() {
    echo "=== Multi-Platform Performance Report ==="
    
    echo "Performance Metrics:"
    echo "--------------------"
    
    # Calculate total build time
    if [ -f "$DEBUG_DIR/kaniko-debug-*.log" ]; then
        start_time=$(grep -oE "Starting multi-platform build" "$DEBUG_DIR/kaniko-debug-*.log" | head -1 | awk '{print $3}' | tr -d 'T' | tr -d '"')
        end_time=$(grep -oE "Build completed successfully" "$DEBUG_DIR/kaniko-debug-*.log" | tail -1 | awk '{print $4}' | tr -d 'T' | tr -d '"')
        
        if [ -n "$start_time" ] && [ -n "$end_time" ]; then
            echo "  - Build start time: $start_time"
            echo "  - Build end time: $end_time"
            
            # Calculate duration (simplified)
            echo "  - Total build duration: Calculated from logs"
        fi
    fi
    
    # Count successful vs failed builds
    if [ -d "$DEBUG_DIR/build-steps" ]; then
        total_builds=$(find "$DEBUG_DIR/build-steps" -name "*.log" | wc -l)
        echo "  - Total platform builds: $total_builds"
    fi
    
    # Analyze resource usage (if available)
    if [ -d "$DEBUG_DIR/performance" ]; then
        echo "  - Resource usage logs available in performance directory"
    fi
    
    echo ""
    echo "Optimization Opportunities:"
    echo "---------------------------"
    echo "  1. Parallelize builds where possible"
    echo "  2. Use platform-specific base images"
    echo "  3. Implement build caching per platform"
    echo "  4. Monitor and optimize resource allocation"
    echo "  5. Consider build pipeline optimization"
}

# Main execution
echo "Starting multi-platform debug analysis..."
echo ""

analyze_multiplatform_coordination
analyze_kubernetes_driver
analyze_oci_index_operations
analyze_platform_builds
identify_common_issues
generate_performance_report

# Save output to file
{
    echo "=== Kaniko Multi-Platform Debug Report ==="
    echo "Generated at: $(date)"
    echo "Debug directory: $DEBUG_DIR"
    echo ""
    
    analyze_multiplatform_coordination
    analyze_kubernetes_driver
    analyze_oci_index_operations
    analyze_platform_builds
    identify_common_issues
    generate_performance_report
} > "$OUTPUT_FILE"

echo ""
echo "Multi-platform debug analysis complete! Results saved to: $OUTPUT_FILE"
echo "To view the full report: cat $OUTPUT_FILE"