# Makefile for go-pwn-swagger
# Supports building for Linux, macOS, and Windows on both amd64 and arm64

BINARY_NAME=go-pwn-swagger
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"
GO=go
GOFLAGS=-trimpath

# Platforms to build for
PLATFORMS=linux darwin windows
ARCHITECTURES=amd64 arm64

# Output directories
DIST_DIR=dist

.PHONY: all clean test build-all $(PLATFORMS)

# Default target
all: build-all

# Clean build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf $(DIST_DIR)
	@$(GO) clean
	@echo "Clean complete"

# Run tests
test:
	@echo "Running tests..."
	@$(GO) test ./...

# Static analysis
lint:
	@echo "Running linters..."
	@$(GO) vet ./...
	@if command -v golangci-lint > /dev/null; then golangci-lint run; else echo "golangci-lint not installed"; fi

# Build for current platform
build:
	@echo "Building for current platform..."
	@$(GO) build $(GOFLAGS) $(LDFLAGS) -o $(BINARY_NAME) .
	@echo "Build complete: $(BINARY_NAME)"

# Build for all platforms and architectures
build-all: $(PLATFORMS)

# Create the distribution directory
$(DIST_DIR):
	@mkdir -p $(DIST_DIR)

# Platform-specific targets
linux: $(DIST_DIR)
	@echo "Building for Linux..."
	@for arch in $(ARCHITECTURES); do \
		echo "  Building for linux/$$arch..."; \
		mkdir -p $(DIST_DIR)/linux_$$arch; \
		GOOS=linux GOARCH=$$arch $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(DIST_DIR)/linux_$$arch/$(BINARY_NAME) .; \
	done
	@echo "Linux builds complete"

darwin: $(DIST_DIR)
	@echo "Building for macOS (Darwin)..."
	@for arch in $(ARCHITECTURES); do \
		echo "  Building for darwin/$$arch..."; \
		mkdir -p $(DIST_DIR)/darwin_$$arch; \
		GOOS=darwin GOARCH=$$arch $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(DIST_DIR)/darwin_$$arch/$(BINARY_NAME) .; \
	done
	@echo "macOS builds complete"

windows: $(DIST_DIR)
	@echo "Building for Windows..."
	@for arch in $(ARCHITECTURES); do \
		echo "  Building for windows/$$arch..."; \
		mkdir -p $(DIST_DIR)/windows_$$arch; \
		GOOS=windows GOARCH=$$arch $(GO) build $(GOFLAGS) $(LDFLAGS) -o $(DIST_DIR)/windows_$$arch/$(BINARY_NAME).exe .; \
	done
	@echo "Windows builds complete"

# Create zip archives for release
release: build-all
	@echo "Creating release archives..."
	@for platform in $(PLATFORMS); do \
		for arch in $(ARCHITECTURES); do \
			echo "  Creating archive for $$platform/$$arch..."; \
			cd $(DIST_DIR)/$$platform"_"$$arch && \
			if [ "$$platform" = "windows" ]; then \
				zip -q ../$(BINARY_NAME)_$(VERSION)_$$platform"_"$$arch.zip $(BINARY_NAME).exe; \
			else \
				zip -q ../$(BINARY_NAME)_$(VERSION)_$$platform"_"$$arch.zip $(BINARY_NAME); \
			fi && \
			cd ../../; \
		done; \
	done
	@echo "Release archives created in $(DIST_DIR)"

# Display version info
version:
	@echo "Version: $(VERSION)"
	@echo "Build Time: $(BUILD_TIME)"

# Generate checksum for release files
checksums: release
	@echo "Generating checksums..."
	@cd $(DIST_DIR) && \
	shasum -a 256 $(BINARY_NAME)_$(VERSION)_*.zip > $(BINARY_NAME)_$(VERSION)_checksums.txt
	@echo "Checksums generated in $(DIST_DIR)/$(BINARY_NAME)_$(VERSION)_checksums.txt"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	@$(GO) mod download
	@echo "Dependencies installed"

# Help target
help:
	@echo "Available targets:"
	@echo "  all (default) - Build for all platforms"
	@echo "  build         - Build for current platform"
	@echo "  build-all     - Build for all supported platforms"
	@echo "  clean         - Remove build artifacts"
	@echo "  test          - Run tests"
	@echo "  lint          - Run linters"
	@echo "  release       - Create release archives"
	@echo "  checksums     - Generate checksums for release files"
	@echo "  deps          - Install dependencies"
	@echo "  version       - Display version information"
	@echo "  help          - Display this help message"
	@echo ""
	@echo "Supported platforms: $(PLATFORMS)"
	@echo "Supported architectures: $(ARCHITECTURES)"
