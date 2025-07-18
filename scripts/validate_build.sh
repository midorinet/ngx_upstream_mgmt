#!/bin/bash

# Simple build validation script
set -e

echo "=== NGINX Upstream Management Module Build Validation ==="

# Check if we have the required files
if [ ! -f "ngx_http_upstream_mgmt_module.c" ]; then
    echo "Error: Main module file not found"
    exit 1
fi

if [ ! -f "ngx_http_upstream_mgmt_module.h" ]; then
    echo "Error: Header file not found"
    exit 1
fi

if [ ! -f "config" ]; then
    echo "Error: Config file not found"
    exit 1
fi

echo "✓ All required files present"

# Check for common syntax issues
echo "Checking for common syntax issues..."

# Check for missing semicolons (basic check)
if grep -n "^[[:space:]]*[^/].*[^;{}]$" ngx_http_upstream_mgmt_module.c | grep -v "^[[:space:]]*#" | grep -v "^[[:space:]]*$" | head -5; then
    echo "Warning: Potential missing semicolons found (manual review needed)"
fi

# Check for balanced braces
OPEN_BRACES=$(grep -o '{' ngx_http_upstream_mgmt_module.c | wc -l)
CLOSE_BRACES=$(grep -o '}' ngx_http_upstream_mgmt_module.c | wc -l)

if [ "$OPEN_BRACES" -ne "$CLOSE_BRACES" ]; then
    echo "Error: Unbalanced braces - Open: $OPEN_BRACES, Close: $CLOSE_BRACES"
    exit 1
fi

echo "✓ Basic syntax checks passed"

# Check for proper includes
if ! grep -q "#include.*ngx_http_upstream_mgmt_module.h" ngx_http_upstream_mgmt_module.c; then
    echo "Error: Missing header include"
    exit 1
fi

echo "✓ Header includes look good"

# Check for module definition
if ! grep -q "ngx_module_t.*ngx_http_upstream_mgmt_module" ngx_http_upstream_mgmt_module.c; then
    echo "Error: Module definition not found"
    exit 1
fi

echo "✓ Module definition found"

echo "=== Build validation completed successfully ==="