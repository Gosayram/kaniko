#!/bin/bash

# Trace filesystem operations during Kaniko build
# Usage: ./trace-filesystem.sh [kaniko-debug-directory]

set -euo pipefail

DEBUG_DIR="${1:-$(pwd)/debug}"
OUTPUT_FILE="filesystem-trace-$(date +%Y%m%d-%H%M%S).txt"

echo "=== Kaniko Filesystem Tracing ==="
echo "Tracing started at: $(date)"
echo "Debug directory: $DEBUG_DIR"
echo "Output file: $OUTPUT_FILE"
echo ""

# Check if debug directory exists
if [ ! -d "$DEBUG_DIR" ]; then
    echo "Error: Debug directory not found: $DEBUG_DIR"
    echo "Please run a Kaniko build with debug mode enabled first."
    exit 1
fi

# Function to trace filesystem operations
trace_filesystem_operations() {
    echo "=== Filesystem Operation Trace ==="
    
    if [ -d "$DEBUG_DIR/filesystem" ]; then
        echo "Tracing filesystem operations..."
        
        # Create a timeline of filesystem operations
        echo "Filesystem Operation Timeline:"
        echo "--------------------------------"
        
        # Process each filesystem log file
        for fs_file in "$DEBUG_DIR/filesystem"/*.log; do
            if [ -f "$fs_file" ]; then
                echo ""
                echo "File: $(basename "$fs_file")"
                echo "--------------------------------"
                
                # Extract and sort operations by timestamp
                grep -E "^\[.*\]" "$fs_file" | sort | while read -r line; do
                    timestamp=$(echo "$line" | grep -oE "\[.*\]" | sed 's/[][]//g')
                    operation=$(echo "$line" | sed 's/^\[.*\] //')
                    
                    echo "[$timestamp] $operation"
                done
            fi
        done
        
        echo ""
        echo "=== Filesystem Statistics ==="
        
        # Count different types of operations
        total_operations=0
        create_operations=0
        modify_operations=0
        delete_operations=0
        copy_operations=0
        
        for fs_file in "$DEBUG_DIR/filesystem"/*.log; do
            if [ -f "$fs_file" ]; then
                file_ops=$(wc -l < "$fs_file")
                total_operations=$((total_operations + file_ops))
                
                create_operations=$((create_operations + $(grep -c "create\|mkdir" "$fs_file" || true)))
                modify_operations=$((modify_operations + $(grep -c "modify\|write\|change" "$fs_file" || true)))
                delete_operations=$((delete_operations + $(grep -c "delete\|remove" "$fs_file" || true)))
                copy_operations=$((copy_operations + $(grep -c "copy\|cp" "$fs_file" || true)))
            fi
        done
        
        echo "Total filesystem operations: $total_operations"
        echo "  - Create operations: $create_operations"
        echo "  - Modify operations: $modify_operations"
        echo "  - Delete operations: $delete_operations"
        echo "  - Copy operations: $copy_operations"
        
        # Analyze layer sizes
        echo ""
        echo "=== Layer Size Analysis ==="
        
        layer_files=()
        while IFS= read -r -d '' file; do
            layer_files+=("$file")
        done < <(find "$DEBUG_DIR/filesystem" -name "*layer*" -type f -print0)
        
        if [ ${#layer_files[@]} -gt 0 ]; then
            echo "Layer files found:"
            for layer_file in "${layer_files[@]}"; do
                size=$(grep -o "layer size: [0-9]*MB" "$layer_file" | awk '{print $3}' | sed 's/MB//' || echo "unknown")
                echo "  - $(basename "$layer_file"): ${size}MB"
            done
            
            # Calculate total layer size
            total_layer_size=0
            for layer_file in "${layer_files[@]}"; do
                size=$(grep -o "layer size: [0-9]*MB" "$layer_file" | awk '{print $3}' | sed 's/MB//' || echo "0")
                total_layer_size=$(echo "$total_layer_size + $size" | bc)
            done
            
            echo ""
            echo "Total layer size: ${total_layer_size}MB"
            echo "Average layer size: $(echo "scale=2; $total_layer_size / ${#layer_files[@]}" | bc)MB"
        else
            echo "No layer files found"
        fi
        
    else
        echo "No filesystem directory found"
    fi
    echo ""
}

# Function to analyze file access patterns
analyze_file_access_patterns() {
    echo "=== File Access Pattern Analysis ==="
    
    if [ -d "$DEBUG_DIR/filesystem" ]; then
        echo "Analyzing file access patterns..."
        
        # Extract most frequently accessed files
        echo "Most frequently accessed files:"
        echo "--------------------------------"
        
        # Combine all filesystem logs and count file accesses
        find "$DEBUG_DIR/filesystem" -name "*.log" -exec cat {} \; 2>/dev/null | \
            grep -oE "/[^[:space:]]*" | \
            sort | \
            uniq -c | \
            sort -nr | \
            head -20 | \
            while read -r count file; do
                echo "  $count accesses: $file"
            done
        
        # Analyze file extensions
        echo ""
        echo "File extension analysis:"
        echo "--------------------------------"
        
        find "$DEBUG_DIR/filesystem" -name "*.log" -exec cat {} \; 2>/dev/null | \
            grep -oE "\.[a-zA-Z0-9]+$" | \
            sort | \
            uniq -c | \
            sort -nr | \
            head -10 | \
            while read -r count ext; do
                echo "  $count files with extension: $ext"
            done
        
    else
        echo "No filesystem directory found"
    fi
    echo ""
}

# Function to identify performance bottlenecks
identify_performance_bottlenecks() {
    echo "=== Performance Bottleneck Analysis ==="
    
    if [ -d "$DEBUG_DIR/filesystem" ]; then
        echo "Identifying filesystem performance bottlenecks..."
        
        # Look for slow operations
        echo "Potential slow operations:"
        echo "--------------------------------"
        
        find "$DEBUG_DIR/filesystem" -name "*.log" -exec grep -l "slow\|timeout\|delay" {} \; | \
            while read -r file; do
                echo "File: $(basename "$file")"
                grep -n "slow\|timeout\|delay" "$file" | head -5
                echo ""
            done
        
        # Check for large file operations
        echo "Large file operations:"
        echo "--------------------------------"
        
        find "$DEBUG_DIR/filesystem" -name "*.log" -exec grep -l "[0-9]\+MB\|[0-9]\+GB" {} \; | \
            while read -r file; do
                echo "File: $(basename "$file")"
                grep -o "[0-9]\+MB\|[0-9]\+GB" "$file" | sort -u | head -5
                echo ""
            done
        
    else
        echo "No filesystem directory found"
    fi
    echo ""
}

# Function to generate recommendations
generate_recommendations() {
    echo "=== Recommendations ==="
    
    echo "Filesystem Optimization Recommendations:"
    echo "----------------------------------------"
    
    # Check for common issues
    if [ -d "$DEBUG_DIR/filesystem" ]; then
        # Check for excessive file operations
        total_ops=$(find "$DEBUG_DIR/filesystem" -name "*.log" -exec wc -l {} + 2>/dev/null | tail -1 | awk '{print $1}')
        if [ "$total_ops" -gt 1000 ]; then
            echo "  - High number of filesystem operations ($total_ops) detected"
            echo "    Consider optimizing Dockerfile to reduce layer count"
        fi
        
        # Check for large files
        large_files=$(find "$DEBUG_DIR/filesystem" -name "*.log" -exec grep -l "[0-9]\+MB" {} \; | wc -l)
        if [ "$large_files" -gt 0 ]; then
            echo "  - Large file operations detected in $large_files log files"
            echo "    Consider using .dockerignore to exclude unnecessary files"
        fi
        
        # Check for frequent file modifications
        modify_ops=$(find "$DEBUG_DIR/filesystem" -name "*.log" -exec grep -c "modify\|write" {} + 2>/dev/null | tail -1 | awk '{print $1}')
        if [ "$modify_ops" -gt 100 ]; then
            echo "  - High number of file modifications ($modify_ops) detected"
            echo "    Consider consolidating RUN commands to reduce layer changes"
        fi
    fi
    
    echo ""
    echo "General Best Practices:"
    echo "----------------------------------------"
    echo "  1. Use .dockerignore to exclude unnecessary files"
    echo "  2. Consolidate RUN commands to reduce layer count"
    echo "  3. Use multi-stage builds to reduce final image size"
    echo "  4. Minimize file operations in the build context"
    echo "  5. Use specific file paths instead of wildcards when possible"
}

# Main execution
echo "Starting filesystem tracing..."
echo ""

trace_filesystem_operations
analyze_file_access_patterns
identify_performance_bottlenecks
generate_recommendations

# Save output to file
{
    echo "=== Kaniko Filesystem Tracing Report ==="
    echo "Generated at: $(date)"
    echo "Debug directory: $DEBUG_DIR"
    echo ""
    
    trace_filesystem_operations
    analyze_file_access_patterns
    identify_performance_bottlenecks
    generate_recommendations
} > "$OUTPUT_FILE"

echo ""
echo "Filesystem tracing complete! Results saved to: $OUTPUT_FILE"
echo "To view the full trace: cat $OUTPUT_FILE"