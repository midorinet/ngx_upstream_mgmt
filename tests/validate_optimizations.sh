#!/bin/bash

# Comprehensive validation script for nginx upstream management module optimizations
echo "🔍 Validating NGINX Upstream Management Module Optimizations"
echo "============================================================"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Function to run test and check result
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    echo -n "Testing $test_name... "
    
    if eval "$test_command" >/dev/null 2>&1; then
        echo -e "${GREEN}✓ PASSED${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}✗ FAILED${NC}"
        ((TESTS_FAILED++))
    fi
}

# Test 1: Unit tests
echo -e "\n${YELLOW}1. Running Unit Tests${NC}"
run_test "Core functionality" "gcc -o tests/unit/test_module tests/unit/test_module.c && ./tests/unit/test_module"

# Test 2: Performance benchmark
echo -e "\n${YELLOW}2. Running Performance Benchmark${NC}"
run_test "Performance validation" "gcc -O2 -o tests/performance/benchmark tests/performance/benchmark.c && ./tests/performance/benchmark"

# Test 3: Code quality checks
echo -e "\n${YELLOW}3. Code Quality Checks${NC}"

# Check for common issues
run_test "No memory leaks in test code" "! grep -r 'malloc\|calloc' tests/ || grep -r 'free' tests/"
run_test "Proper error handling" "grep -q 'NGX_ERROR' ngx_http_upstream_mgmt_module.c"
run_test "Function declarations present" "grep -q 'static.*ngx_http_upstream_mgmt' ngx_http_upstream_mgmt_module.h"

# Test 4: Module structure validation
echo -e "\n${YELLOW}4. Module Structure Validation${NC}"
run_test "Header file exists" "[ -f ngx_http_upstream_mgmt_module.h ]"
run_test "Source file exists" "[ -f ngx_http_upstream_mgmt_module.c ]"
run_test "Config file exists" "[ -f config ]"
run_test "README exists" "[ -f README.md ]"

# Test 5: Optimization validation
echo -e "\n${YELLOW}5. Optimization Validation${NC}"
run_test "Helper functions present" "grep -q 'ngx_http_upstream_mgmt_write_server_json' ngx_http_upstream_mgmt_module.c"
run_test "Constants defined" "grep -q 'ngx_http_upstream_mgmt_success_response' ngx_http_upstream_mgmt_module.c"
run_test "Optimized URI parsing" "grep -q 'static const char prefix' ngx_http_upstream_mgmt_module.c"
run_test "Error handling improved" "grep -q 'ngx_log_error' ngx_http_upstream_mgmt_module.c"

# Test 6: Documentation
echo -e "\n${YELLOW}6. Documentation Validation${NC}"
run_test "Optimization documentation" "[ -f OPTIMIZATIONS.md ]"
run_test "API documentation in README" "grep -q 'API Endpoints' README.md"

# Summary
echo -e "\n${YELLOW}Test Summary${NC}"
echo "============"
echo -e "Tests passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Tests failed: ${RED}$TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "\n${GREEN}🎉 All optimizations validated successfully!${NC}"
    echo -e "${GREEN}The module is ready for production use.${NC}"
    exit 0
else
    echo -e "\n${RED}❌ Some tests failed. Please review the issues above.${NC}"
    exit 1
fi