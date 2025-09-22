#!/bin/bash

# Collect comprehensive debug information from Kaniko builds
# Usage: ./collect-debug-info.sh [kaniko-debug-directory] [output-directory]

set -euo pipefail

DEBUG_DIR="${1:-$(pwd)/debug}"
OUTPUT_DIR="${2:-debug-collection-$(date +%Y%m%d-%H%M%S)}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

echo "=== Kaniko Debug Information Collection ==="
echo "Collection started at: $(date)"
echo "Debug directory: $DEBUG_DIR"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Check if debug directory exists
if [ ! -d "$DEBUG_DIR" ]; then
    echo "Error: Debug directory not found: $DEBUG_DIR"
    echo "Please run a Kaniko build with debug mode enabled first."
    exit 1
fi

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Function to collect system information
collect_system_info() {
    echo "=== Collecting System Information ==="
    
    system_info_file="$OUTPUT_DIR/system-info.txt"
    
    echo "System Information:" > "$system_info_file"
    echo "==================" >> "$system_info_file"
    echo "Collection timestamp: $(date)" >> "$system_info_file"
    echo "" >> "$system_info_file"
    
    # Operating system information
    echo "Operating System:" >> "$system_info_file"
    uname -a >> "$system_info_file"
    cat /etc/os-release 2>/dev/null >> "$system_info_file" || echo "OS release info not available" >> "$system_info_file"
    echo "" >> "$system_info_file"
    
    # Resource information
    echo "Resource Information:" >> "$system_info_file"
    echo "Memory:" >> "$system_info_file"
    free -h 2>/dev/null >> "$system_info_file" || echo "Memory info not available" >> "$system_info_file"
    echo "" >> "$system_info_file"
    echo "Disk:" >> "$system_info_file"
    df -h 2>/dev/null >> "$system_info_file" || echo "Disk info not available" >> "$system_info_file"
    echo "" >> "$system_info_file"
    
    # Network information
    echo "Network Information:" >> "$system_info_file"
    ip addr show 2>/dev/null >> "$system_info_file" || echo "Network info not available" >> "$system_info_file"
    echo "" >> "$system_info_file"
    
    echo "System information collected: $system_info_file"
    echo ""
}

# Function to collect Kaniko configuration
collect_kaniko_config() {
    echo "=== Collecting Kaniko Configuration ==="
    
    config_file="$OUTPUT_DIR/kaniko-config.txt"
    
    echo "Kaniko Configuration:" > "$config_file"
    echo "====================" >> "$config_file"
    echo "Collection timestamp: $(date)" >> "$config_file"
    echo "" >> "$config_file"
    
    # Collect environment variables
    echo "Environment Variables:" >> "$config_file"
    echo "---------------------" >> "$config_file"
    env | grep -i kaniko >> "$config_file" || echo "No Kaniko environment variables found" >> "$config_file"
    echo "" >> "$config_file"
    
    # Collect debug configuration
    echo "Debug Configuration:" >> "$config_file"
    echo "-------------------" >> "$config_file"
    env | grep -i debug >> "$config_file" || echo "No debug environment variables found" >> "$config_file"
    echo "" >> "$config_file"
    
    # Collect registry configuration
    echo "Registry Configuration:" >> "$config_file"
    echo "----------------------" >> "$config_file"
    env | grep -i registry >> "$config_file" || echo "No registry environment variables found" >> "$config_file"
    echo "" >> "$config_file"
    
    echo "Kaniko configuration collected: $config_file"
    echo ""
}

# Function to collect debug logs
collect_debug_logs() {
    echo "=== Collecting Debug Logs ==="
    
    logs_dir="$OUTPUT_DIR/debug-logs"
    mkdir -p "$logs_dir"
    
    # Copy all debug files
    if [ -d "$DEBUG_DIR" ]; then
        echo "Copying debug logs from $DEBUG_DIR to $logs_dir"
        
        # Copy main debug log
        cp "$DEBUG_DIR/kaniko-debug-"*.log "$logs_dir/" 2>/dev/null || echo "No main debug logs found"
        
        # Copy organized debug directories
        for subdir in build-steps multi-platform oci-operations filesystem registry performance; do
            if [ -d "$DEBUG_DIR/$subdir" ]; then
                mkdir -p "$logs_dir/$subdir"
                cp -r "$DEBUG_DIR/$subdir/"*.log "$logs_dir/$subdir/" 2>/dev/null || echo "No logs in $subdir directory"
            fi
        done
        
        # Count collected files
        log_count=$(find "$logs_dir" -name "*.log" | wc -l)
        echo "Collected $log_count debug log files"
    else
        echo "No debug directory found"
    fi
    
    echo ""
}

# Function to collect build information
collect_build_info() {
    echo "=== Collecting Build Information ==="
    
    build_info_file="$OUTPUT_DIR/build-info.txt"
    
    echo "Build Information:" > "$build_info_file"
    echo "=================" >> "$build_info_file"
    echo "Collection timestamp: $(date)" >> "$build_info_file"
    echo "" >> "$build_info_file"
    
    # Extract build information from logs
    if [ -f "$DEBUG_DIR/kaniko-debug-*.log" ]; then
        echo "Build Context:" >> "$build_info_file"
        echo "-------------" >> "$build_info_file"
        grep -o "context: [^[:space:]]*" "$DEBUG_DIR/kaniko-debug-*.log" | tail -5 >> "$build_info_file"
        echo "" >> "$build_info_file"
        
        echo "Dockerfile:" >> "$build_info_file"
        echo "-----------" >> "$build_info_file"
        grep -o "dockerfile: [^[:space:]]*" "$DEBUG_DIR/kaniko-debug-*.log" | tail -5 >> "$build_info_file"
        echo "" >> "$build_info_file"
        
        echo "Destinations:" >> "$build_info_file"
        echo "-------------" >> "$build_info_file"
        grep -o "destination: [^[:space:]]*" "$DEBUG_DIR/kaniko-debug-*.log" | tail -5 >> "$build_info_file"
        echo "" >> "$build_info_file"
        
        echo "Platforms:" >> "$build_info_file"
        echo "----------" >> "$build_info_file"
        grep -o "platform: [a-zA-Z0-9/]*" "$DEBUG_DIR/kaniko-debug-*.log" | sort | uniq >> "$build_info_file"
        echo "" >> "$build_info_file"
        
        echo "Build Duration:" >> "$build_info_file"
        echo "---------------" >> "$build_info_file"
        grep -E "(Starting|Successfully completed)" "$DEBUG_DIR/kaniko-debug-*.log" | tail -10 >> "$build_info_file"
    else
        echo "No build information found in debug logs" >> "$build_info_file"
    fi
    
    echo "Build information collected: $build_info_file"
    echo ""
}

# Function to collect error information
collect_error_info() {
    echo "=== Collecting Error Information ==="
    
    error_info_file="$OUTPUT_DIR/error-info.txt"
    
    echo "Error Information:" > "$error_info_file"
    echo "=================" >> "$error_info_file"
    echo "Collection timestamp: $(date)" >> "$error_info_file"
    echo "" >> "$error_info_file"
    
    # Collect errors from all debug logs
    if [ -d "$DEBUG_DIR" ]; then
        echo "Error Summary:" >> "$error_info_file"
        echo "-------------" >> "$error_info_file"
        
        # Count errors by type
        error_count=0
        for log_file in "$DEBUG_DIR"/**/*.log "$DEBUG_DIR"/*.log 2>/dev/null; do
            if [ -f "$log_file" ]; then
                file_errors=$(grep -i "error\|failed\|exception" "$log_file" | wc -l)
                if [ "$file_errors" -gt 0 ]; then
                    echo "File: $(basename "$log_file")" >> "$error_info_file"
                    echo "  Errors: $file_errors" >> "$error_info_file"
                    ((error_count += file_errors))
                fi
            fi
        done
        
        echo "" >> "$error_info_file"
        echo "Total errors found: $error_count" >> "$error_info_file"
        
        if [ "$error_count" -gt 0 ]; then
            echo "" >> "$error_info_file"
            echo "Detailed Error Log:" >> "$error_info_file"
            echo "------------------" >> "$error_info_file"
            
            # Extract detailed error information
            for log_file in "$DEBUG_DIR"/**/*.log "$DEBUG_DIR"/*.log 2>/dev/null; do
                if [ -f "$log_file" ]; then
                    grep -i -n "error\|failed\|exception" "$log_file" | head -10 >> "$error_info_file" || true
                    echo "" >> "$error_info_file"
                fi
            done
        fi
    else
        echo "No debug directory found" >> "$error_info_file"
    fi
    
    echo "Error information collected: $error_info_file"
    echo ""
}

# Function to collect performance metrics
collect_performance_metrics() {
    echo "=== Collecting Performance Metrics ==="
    
    perf_file="$OUTPUT_DIR/performance-metrics.txt"
    
    echo "Performance Metrics:" > "$perf_file"
    echo "===================" >> "$perf_file"
    echo "Collection timestamp: $(date)" >> "$perf_file"
    echo "" >> "$perf_file"
    
    # Extract timing information
    if [ -d "$DEBUG_DIR" ]; then
        echo "Build Timing Information:" >> "$perf_file"
        echo "------------------------" >> "$perf_file"
        
        # Extract build step timings
        if [ -d "$DEBUG_DIR/build-steps" ]; then
            echo "Build Step Timings:" >> "$perf_file"
            for step_file in "$DEBUG_DIR/build-steps"/*.log; do
                if [ -f "$step_file" ]; then
                    step_name=$(basename "$step_file" .log)
                    timing=$(grep -o "took [0-9]*ms" "$step_file" | head -1 | awk '{print $2}' | sed 's/ms//')
                    echo "  $step_name: ${timing}ms" >> "$perf_file"
                fi
            done
            echo "" >> "$perf_file"
        fi
        
        # Extract multi-platform timings
        if [ -f "$DEBUG_DIR/kaniko-debug-*.log" ]; then
            echo "Multi-Platform Build Timings:" >> "$perf_file"
            grep -o "platform: [a-zA-Z0-9/]*.*took [0-9]*ms" "$DEBUG_DIR/kaniko-debug-*.log" | tail -10 >> "$perf_file"
            echo "" >> "$perf_file"
        fi
        
        # Extract registry operation timings
        if [ -d "$DEBUG_DIR/registry" ]; then
            echo "Registry Operation Timings:" >> "$perf_file"
            for reg_file in "$DEBUG_DIR/registry"/*.log; do
                if [ -f "$reg_file" ]; then
                    op_name=$(basename "$reg_file" .log)
                    timing=$(grep -o "took [0-9]*ms" "$reg_file" | head -1 | awk '{print $2}' | sed 's/ms//')
                    echo "  $op_name: ${timing}ms" >> "$perf_file"
                fi
            done
            echo "" >> "$perf_file"
        fi
        
        # Calculate total metrics
        echo "Summary Metrics:" >> "$perf_file"
        echo "---------------" >> "$perf_file"
        
        total_logs=$(find "$DEBUG_DIR" -name "*.log" | wc -l)
        echo "Total debug log files: $total_logs" >> "$perf_file"
        
        total_size=$(du -sh "$DEBUG_DIR" | cut -f1)
        echo "Total debug directory size: $total_size" >> "$perf_file"
        
        # Count platforms
        platform_count=$(grep -o "platform: [a-zA-Z0-9/]*" "$DEBUG_DIR/kaniko-debug-*.log" | sort | uniq | wc -l 2>/dev/null || echo "0")
        echo "Total platforms built: $platform_count" >> "$perf_file"
    else
        echo "No performance metrics found" >> "$perf_file"
    fi
    
    echo "Performance metrics collected: $perf_file"
    echo ""
}

# Function to generate collection summary
generate_collection_summary() {
    echo "=== Generating Collection Summary ==="
    
    summary_file="$OUTPUT_DIR/collection-summary.txt"
    
    echo "Debug Information Collection Summary" > "$summary_file"
    echo "===================================" >> "$summary_file"
    echo "Collection timestamp: $(date)" >> "$summary_file"
    echo "Debug directory: $DEBUG_DIR" >> "$summary_file"
    echo "Output directory: $OUTPUT_DIR" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # Count collected files
    total_files=$(find "$OUTPUT_DIR" -type f | wc -l)
    total_size=$(du -sh "$OUTPUT_DIR" | cut -f1)
    
    echo "Collection Statistics:" >> "$summary_file"
    echo "---------------------" >> "$summary_file"
    echo "Total files collected: $total_files" >> "$summary_file"
    echo "Total collection size: $total_size" >> "$summary_file"
    echo "" >> "$summary_file"
    
    # List collected files
    echo "Collected Files:" >> "$summary_file"
    echo "---------------" >> "$summary_file"
    find "$OUTPUT_DIR" -type f -name "*.txt" | while read -r file; do
        size=$(du -h "$file" | cut -f1)
        echo "  $(basename "$file"): $size" >> "$summary_file"
    done
    echo "" >> "$summary_file"
    
    # Generate recommendations
    echo "Next Steps:" >> "$summary_file"
    echo "----------" >> "$summary_file"
    echo "1. Review the collected debug information" >> "$summary_file"
    echo "2. Check error-info.txt for any build failures" >> "$summary_file"
    echo "3. Analyze performance-metrics.txt for optimization opportunities" >> "$summary_file"
    echo "4. Use debug scripts for detailed analysis:" >> "$summary_file"
    echo "   - ./analyze-build.sh $OUTPUT_DIR" >> "$summary_file"
    echo "   - ./trace-filesystem.sh $OUTPUT_DIR" >> "$summary_file"
    echo "   - ./debug-multi-platform.sh $OUTPUT_DIR" >> "$summary_file"
    echo "5. Archive this collection for future reference" >> "$summary_file"
    
    echo "Collection summary generated: $summary_file"
    echo ""
}

# Function to create archive
create_archive() {
    echo "=== Creating Archive ==="
    
    archive_file="kaniko-debug-collection-$TIMESTAMP.tar.gz"
    
    # Create archive
    tar -czf "$archive_file" -C "$OUTPUT_DIR" . 2>/dev/null || echo "Failed to create archive"
    
    if [ -f "$archive_file" ]; then
        archive_size=$(du -h "$archive_file" | cut -f1)
        echo "Archive created: $archive_file ($archive_size)"
        echo "Archive contains: $(tar -tzf "$archive_file" | wc -l) files"
    else
        echo "Archive creation failed"
    fi
    
    echo ""
}

# Main execution
echo "Starting debug information collection..."
echo ""

collect_system_info
collect_kaniko_config
collect_debug_logs
collect_build_info
collect_error_info
collect_performance_metrics
generate_collection_summary

# Optional: Create archive
read -p "Create archive of collected information? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    create_archive
fi

echo ""
echo "=== Collection Complete ==="
echo "All debug information collected in: $OUTPUT_DIR"
echo "Collection timestamp: $(date)"
echo ""
echo "To analyze the collected information:"
echo "1. Review the individual text files in $OUTPUT_DIR"
echo "2. Use the debug scripts with the output directory:"
echo "   - ./analyze-build.sh $OUTPUT_DIR"
echo "   - ./trace-filesystem.sh $OUTPUT_DIR"
echo "   - ./debug-multi-platform.sh $OUTPUT_DIR"
echo ""
echo "For troubleshooting, start with error-info.txt and performance-metrics.txt"