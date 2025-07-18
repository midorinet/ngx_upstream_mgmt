# NGINX Upstream Management Module Makefile

# Default nginx version
NGINX_VERSION ?= 1.26.2
NGINX_DIR ?= nginx-$(NGINX_VERSION)
NGINX_URL = https://nginx.org/download/$(NGINX_DIR).tar.gz

# Build configuration
BUILD_DIR ?= build
MODULE_NAME = ngx_http_upstream_mgmt_module
MODULE_SO = $(MODULE_NAME).so

# Compiler flags for security and optimization
CFLAGS = -g -O2 -fstack-protector-strong -Wformat -Werror=format-security -Wno-error=pointer-sign
LDFLAGS = -Wl,-z,relro -Wl,-z,now

.PHONY: all clean test install download configure build module unit-test integration-test

all: module

# Download nginx source
download:
	@echo "Downloading nginx $(NGINX_VERSION)..."
	@if [ ! -f $(NGINX_DIR).tar.gz ]; then \
		wget $(NGINX_URL); \
	fi
	@if [ ! -d $(NGINX_DIR) ]; then \
		tar -xzf $(NGINX_DIR).tar.gz; \
	fi

# Configure nginx with module
configure: download
	@echo "Configuring nginx with upstream management module..."
	cd $(NGINX_DIR) && \
	./configure \
		--add-dynamic-module=../ \
		--with-compat \
		--with-debug \
		--with-cc-opt="$(CFLAGS)" \
		--with-ld-opt="$(LDFLAGS)" \
		--prefix=$(PWD)/$(BUILD_DIR) \
		--conf-path=$(PWD)/$(BUILD_DIR)/conf/nginx.conf \
		--error-log-path=$(PWD)/$(BUILD_DIR)/logs/error.log \
		--access-log-path=$(PWD)/$(BUILD_DIR)/logs/access.log \
		--pid-path=$(PWD)/$(BUILD_DIR)/logs/nginx.pid \
		--lock-path=$(PWD)/$(BUILD_DIR)/logs/nginx.lock

# Build the module
build: configure
	@echo "Building nginx and module..."
	cd $(NGINX_DIR) && make modules
	@mkdir -p $(BUILD_DIR)/modules
	@cp $(NGINX_DIR)/objs/$(MODULE_SO) $(BUILD_DIR)/modules/

# Build module only (main target)
module: build
	@echo "Module built successfully: $(BUILD_DIR)/modules/$(MODULE_SO)"
	@file $(BUILD_DIR)/modules/$(MODULE_SO)

# Install nginx and module
install: build
	@echo "Installing nginx and module..."
	cd $(NGINX_DIR) && make install
	@echo "Installation complete in $(BUILD_DIR)/"

# Run unit tests
unit-test:
	@echo "Running unit tests..."
	@cd tests/unit && \
	gcc -o test_module test_module.c -I. -lcheck -lpthread -lrt -lm -lsubunit && \
	./test_module

# Run integration tests
integration-test: module
	@echo "Running integration tests..."
	@export NGINX_BIN=$(PWD)/$(BUILD_DIR)/sbin/nginx && \
	export MODULE_PATH=$(PWD)/$(BUILD_DIR)/modules/$(MODULE_SO) && \
	cd tests/integration && \
	python3 -m pytest -v test_upstream_mgmt.py

# Run all tests
test: unit-test integration-test
	@echo "All tests completed"

# Development build with debug symbols
debug: CFLAGS += -DDEBUG -g3 -O0
debug: module

# Production build with optimizations
release: CFLAGS += -O3 -DNDEBUG
release: module

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -rf $(NGINX_DIR)
	@rm -f $(NGINX_DIR).tar.gz
	@rm -f tests/unit/test_module
	@find . -name "*.o" -delete
	@find . -name "*.so" -delete

# Show build information
info:
	@echo "Build Information:"
	@echo "  NGINX Version: $(NGINX_VERSION)"
	@echo "  Build Directory: $(BUILD_DIR)"
	@echo "  Module Name: $(MODULE_NAME)"
	@echo "  CFLAGS: $(CFLAGS)"
	@echo "  LDFLAGS: $(LDFLAGS)"

# Quick development cycle
dev: clean debug test
	@echo "Development build and test cycle complete"

# Docker build (if Dockerfile exists)
docker:
	@if [ -f Dockerfile ]; then \
		docker build -t nginx-upstream-mgmt .; \
	else \
		echo "Dockerfile not found"; \
	fi

# Help target
help:
	@echo "Available targets:"
	@echo "  all          - Build the module (default)"
	@echo "  module       - Build the module only"
	@echo "  download     - Download nginx source"
	@echo "  configure    - Configure nginx with module"
	@echo "  build        - Build nginx and module"
	@echo "  install      - Install nginx and module"
	@echo "  test         - Run all tests"
	@echo "  unit-test    - Run unit tests only"
	@echo "  integration-test - Run integration tests only"
	@echo "  debug        - Build with debug symbols"
	@echo "  release      - Build optimized for production"
	@echo "  clean        - Clean build artifacts"
	@echo "  info         - Show build information"
	@echo "  dev          - Quick development cycle (clean + debug + test)"
	@echo "  docker       - Build Docker image"
	@echo "  help         - Show this help"