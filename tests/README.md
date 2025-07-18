# Tests for NGINX Upstream Management Module

This directory contains unit and integration tests for the NGINX Upstream Management Module.

## Directory Structure

```
tests/
├── unit/                   # Unit tests
│   ├── simple_test.c      # Simple unit tests (no dependencies)
│   └── test_module.c      # Advanced unit tests (requires Check framework)
├── integration/           # Integration tests
│   └── test_upstream_mgmt.py  # Python-based integration tests
└── config/               # Test configurations
    └── nginx_test.conf   # Sample nginx configuration for testing
```

## Running Tests

### Quick Test (Recommended)
```bash
# Run all tests with automatic fallbacks
./scripts/run_tests.sh
```

### Manual Testing

#### Unit Tests
```bash
# Simple tests (no dependencies)
cd tests/unit
gcc -o simple_test simple_test.c
./simple_test

# Advanced tests (requires Check framework)
cd tests/unit
gcc -o test_module test_module.c -I. -lcheck -lpthread -lrt -lm -lsubunit
./test_module
```

#### Integration Tests
```bash
# Requires nginx binary and module
cd tests/integration
NGINX_BIN=/path/to/nginx MODULE_PATH=/path/to/module.so python3 -m pytest test_upstream_mgmt.py
```

### Using Makefile
```bash
# Run unit tests only
make unit-test

# Run integration tests only
make integration-test

# Run all tests
make test
```

## Test Dependencies

### Unit Tests
- **Simple tests**: No dependencies (uses standard C library)
- **Advanced tests**: Check framework (`sudo apt-get install check libcheck-dev`)

### Integration Tests
- Python 3.x
- pytest
- requests
- NGINX binary
- Compiled module

## Installing Dependencies

### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install build-essential libpcre3-dev zlib1g-dev libssl-dev check libcheck-dev python3-pytest python3-requests
```

### macOS
```bash
brew install check
pip3 install pytest requests
```

## Test Coverage

### Unit Tests
- ✅ Upstream state parsing (`up`, `drain`, invalid states)
- ✅ Server ID validation
- ✅ JSON parsing for drain values
- ✅ Input validation and error handling

### Integration Tests
- ✅ API endpoint functionality (GET, PATCH)
- ✅ Upstream server listing
- ✅ Server state management (drain/undrain)
- ✅ Error handling and edge cases
- ✅ Traffic routing validation
- ✅ Concurrent operations
- ✅ Security headers and rate limiting

## Adding New Tests

### Unit Tests
Add new test functions to `simple_test.c` or `test_module.c` following the existing patterns.

### Integration Tests
Add new test functions to `test_upstream_mgmt.py` using pytest conventions.

## Continuous Integration

Tests are automatically run in GitHub Actions on:
- Push to main/master branches
- Pull requests
- Weekly schedule
- Manual workflow dispatch

See `.github/workflows/ci.yml` and `.github/workflows/quick-test.yml` for CI configuration.