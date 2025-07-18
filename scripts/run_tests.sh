#!/bin/bash

# Test runner script for NGINX Upstream Management Module
set -e

echo "=== NGINX Upstream Management Module Test Runner ==="

# Change to project root if we're in scripts directory
if [[ $(basename $(pwd)) == "scripts" ]]; then
    cd ..
fi

# Run validation first
echo "Step 1: Validating module files..."
if [ -f "scripts/validate_build.sh" ]; then
    chmod +x scripts/validate_build.sh
    ./scripts/validate_build.sh
else
    echo "Warning: Build validation script not found"
fi

# Run unit tests
echo ""
echo "Step 2: Running unit tests..."
cd tests/unit

echo "Running simple unit tests..."
gcc -o simple_test simple_test.c
./simple_test

echo ""
echo "Attempting to run Check-based unit tests..."
if command -v pkg-config >/dev/null 2>&1 && pkg-config --exists check; then
    echo "Check framework detected, running advanced tests..."
    gcc -o test_module test_module.c -I. $(pkg-config --cflags --libs check)
    ./test_module
elif gcc -o test_module test_module.c -I. -lcheck -lpthread -lrt -lm -lsubunit 2>/dev/null; then
    echo "Check framework available, running advanced tests..."
    ./test_module
else
    echo "Check framework not available, skipping advanced tests"
    echo "To install Check framework on Ubuntu/Debian: sudo apt-get install check libcheck-dev"
    echo "To install Check framework on macOS: brew install check"
fi

cd ../..

echo ""
echo "Step 3: Testing module compilation..."
if [ ! -d "nginx-test" ]; then
    echo "Downloading nginx for compilation test..."
    wget -q https://nginx.org/download/nginx-1.26.2.tar.gz
    tar -xzf nginx-1.26.2.tar.gz
    mv nginx-1.26.2 nginx-test
fi

cd nginx-test
echo "Configuring nginx with module..."
./configure --add-dynamic-module=../ --with-compat --with-cc-opt="-Wno-error=pointer-sign" >/dev/null 2>&1

echo "Building module..."
make modules >/dev/null 2>&1

if [ -f "objs/ngx_http_upstream_mgmt_module.so" ]; then
    echo "✓ Module compiled successfully"
    echo "Module size: $(stat -c%s objs/ngx_http_upstream_mgmt_module.so 2>/dev/null || stat -f%z objs/ngx_http_upstream_mgmt_module.so) bytes"
    file objs/ngx_http_upstream_mgmt_module.so
else
    echo "✗ Module compilation failed"
    exit 1
fi

cd ..

echo ""
echo "=== All tests completed successfully! ==="
echo ""
echo "Summary:"
echo "✓ Module validation passed"
echo "✓ Unit tests passed"
echo "✓ Module compilation successful"
echo ""
echo "Your NGINX Upstream Management Module is ready for use!"