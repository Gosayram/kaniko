#!/bin/bash

# Analyze Kaniko build performance and bottlenecks
# Usage: ./analyze-build.sh [kaniko-debug-directory]

set -euo pipefail

DEBUG_DIR="${1:-$(pwd)/debug}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
OUTPUT_FILE="build-analysis-${TIMESTAMP}.txt"

echo "=== Kaniko Build Performance Analysis ==="
echo "Analysis started at: $(date)"
echo "Debug directory: $DEBUG_DIR"
echo "Output file: $OUTPUT_FILE"
echo ""

# Check if debug directory exists
if [ ! -d "$DEBUG_DIR" ]; then
    echo "Error: Debug directory not found: $DEBUG_DIR"
    echo "Please run a Kaniko build with debug mode enabled first."
    exit 1
fi

# Function to analyze build steps
analyze_build_steps() {
    echo "=== Build Step Analysis ==="
    
    if [ -d "$DEBUG_DIR/build-steps" ]; then
        echo "Analyzing build steps..."
        
        total_steps=0
        total_time=0
        slowest_step=""
        slowest_time=0
        
        for step_file in "$DEBUG_DIR/build-steps"/*.log; do
            if [ -f "$step_file" ]; then
                ((total_steps++))
                
                # Extract timing information (assuming format like "2025-09-22T06:07:46Z [build-step] Step X took Yms")
                step_time=$(grep -o "took [0-9]*ms" "$step_file" | head -1 | awk '{print $2}' | sed 's/ms//')
                
                if [ -n "$step_time" ]; then
                    total_time=$((total_time + step_time))
                    
                    if [ "$step_time" -gt "$slowest_time" ]; then
                        slowest_time=$step_time
                        slowest_step=$(basename "$step_file" .log)
                    fi
                fi
                
                echo "  - $(basename "$step_file"): $(wc -l < "$step_file") lines"
            fi
        done
        
        echo "Total build steps: $total_steps"
        if [ $total_steps -gt 0 ]; then
            echo "Average step time: $((total_time / total_steps))ms"
            echo "Slowest step: $slowest_step (${slowest_time}ms)"
        fi
    else
        echo "No build steps directory found"
    fi
    echo ""
}

# Function to analyze multi-platform coordination
analyze_multiplatform() {
    echo "=== Multi-Platform Analysis ==="
    
    if [ -f "$DEBUG_DIR/kaniko-debug-*.log" ]; then
        echo "Analyzing multi-platform coordination..."
        
        # Extract multi-platform related logs
        grep -i "multiplatform\|platform\|driver" "$DEBUG_DIR/kaniko-debug-*.log" | tail -20
        
        # Count platform builds
        platform_count=$(grep -o "platform: [a-zA-Z0-9/]*" "$DEBUG_DIR/kaniko-debug-*.log" | sort | uniq | wc -l)
        echo "Total platforms built: $platform_count"
    else
        echo "No main debug log found"
    fi
    echo ""
}

# Function to analyze OCI operations
analyze_oci_operations() {
    echo "=== OCI Operations Analysis ==="
    
    if [ -d "$DEBUG_DIR/oci-operations" ]; then
        echo "Analyzing OCI operations..."
        
        total_manifests=0
        total_push_time=0
        
        for oci_file in "$DEBUG_DIR/oci-operations"/*.log; do
            if [ -f "$oci_file" ]; then
                ((total_manifests++))
                
                # Extract push timing
                push_time=$(grep -o "push.*took [0-9]*ms" "$oci_file" | awk '{print $3}' | sed 's/ms//' | head -1)
                if [ -n "$push_time" ]; then
                    total_push_time=$((total_push_time + push_time))
                fi
                
                echo "  - $(basename "$oci_file"): $(wc -l < "$oci_file") lines"
            fi
        done
        
        echo "Total OCI operations: $total_manifests"
        if [ $total_manifests -gt 0 ]; then
            echo "Average push time: $((total_push_time / total_manifests))ms"
        fi
    else
        echo "No OCI operations directory found"
    fi
    echo ""
}

# Function to analyze filesystem operations
analyze_filesystem() {
    echo "=== Filesystem Analysis ==="
    
    if [ -d "$DEBUG_DIR/filesystem" ]; then
        echo "Analyzing filesystem operations..."
        
        total_snapshots=0
        total_layer_size=0
        
        for fs_file in "$DEBUG_DIR/filesystem"/*.log; do
            if [ -f "$fs_file" ]; then
                ((total_snapshots++))
                
                # Extract layer size information
                layer_size=$(grep -o "layer size: [0-9]*MB" "$fs_file" | awk '{print $3}' | sed 's/MB//' | head -1)
                if [ -n "$layer_size" ]; then
                    total_layer_size=$(echo "$total_layer_size + $layer_size" | bc)
                fi
                
                echo "  - $(basename "$fs_file"): $(wc -l < "$fs_file") lines"
            fi
        done
        
        echo "Total filesystem operations: $total_snapshots"
        if [ $total_snapshots -gt 0 ]; then
            echo "Average layer size: $(echo "scale=2; $total_layer_size / $total_snapshots" | bc)MB"
        fi
    else
        echo "No filesystem directory found"
    fi
    echo ""
}

# Function to analyze registry operations
analyze_registry() {
    echo "=== Registry Analysis ==="
    
    if [ -d "$DEBUG_DIR/registry" ]; then
        echo "Analyzing registry operations..."
        
        total_pulls=0
        total_pushes=0
        failed_operations=0
        
        for reg_file in "$DEBUG_DIR/registry"/*.log; do
            if [ -f "$reg_file" ]; then
                # Count operations
                pulls=$(grep -c "pull" "$reg_file" || true)
                pushes=$(grep -c "push" "$reg_file" || true)
                errors=$(grep -c "error\|failed" "$reg_file" || true)
                
                total_pulls=$((total_pulls + pulls))
                total_pushes=$((total_pushes + pushes))
                failed_operations=$((failed_operations + errors))
                
                echo "  - $(basename "$reg_file"): $(wc -l < "$reg_file") lines"
            fi
        done
        
        echo "Total pull operations: $total_pulls"
        echo "Total push operations: $total_pushes"
        echo "Failed operations: $failed_operations"
    else
        echo "No registry directory found"
    fi
    echo ""
}

# Function to generate summary report
generate_summary() {
    echo "=== Summary Report ==="
    
    echo "Build Analysis Summary:"
    echo "  - Analysis timestamp: $(date)"
    echo "  - Debug directory: $DEBUG_DIR"
    echo "  - Total log files: $(find "$DEBUG_DIR" -name "*.log" | wc -l)"
    
    # Calculate total debug directory size
    total_size=$(du -sh "$DEBUG_DIR" | cut -f1)
    echo "  - Debug directory size: $total_size"
    
    echo ""
    echo "Recommendations:"
    
    # Check for common issues
    if [ -f "$DEBUG_DIR/kaniko-debug-*.log" ]; then
        error_count=$(grep -c "error\|failed" "$DEBUG_DIR/kaniko-debug-*.log" || true)
        if [ "$error_count" -gt 0 ]; then
            echo "  - Found $error_count potential errors - review logs for details"
        fi
    fi
    
    if [ -d "$DEBUG_DIR/build-steps" ]; then
        step_count=$(find "$DEBUG_DIR/build-steps" -name "*.log" | wc -l)
        if [ "$step_count" -gt 50 ]; then
            echo "  - High number of build steps ($step_count) - consider Dockerfile optimization"
        fi
    fi
    
    if [ -d "$DEBUG_DIR/registry" ]; then
        error_count=$(find "$DEBUG_DIR/registry" -name "*.log" -exec grep -l "error\|failed" {} \; | wc -l)
        if [ "$error_count" -gt 0 ]; then
            echo "  - Registry errors detected - check network connectivity and authentication"
        fi
    fi
    
    echo ""
    echo "For detailed analysis, review the individual log files in $DEBUG_DIR/"
}

# Main execution
echo "Starting Kaniko build analysis..."
echo ""

analyze_build_steps
analyze_multiplatform
analyze_oci_operations
analyze_filesystem
analyze_registry
generate_summary

echo ""
echo "Analysis complete! Results saved to: $OUTPUT_FILE"
echo "To view the full analysis: cat $OUTPUT_FILE"