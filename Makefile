# KSM MCP Server Makefile

# Variables
BINARY_NAME=ksm-mcp
VERSION?=$(shell git describe --tags --always --dirty)
BUILD_DIR=bin
DOCKER_IMAGE=keepersecurityinc/ksm-mcp-poc
DOCKER_TAG?=latest

# Go variables
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-X main.version=$(VERSION) -w -s"
BUILD_FLAGS=-trimpath $(LDFLAGS)

# Directories
SRC_DIR=./cmd/$(BINARY_NAME)
INTERNAL_DIR=./internal/...
PKG_DIR=./pkg/...

GOLANGCILINT_CMD := $(shell go env GOBIN)/golangci-lint
ifeq ($(GOLANGCILINT_CMD), /golangci-lint) # GOBIN not set or empty
  GOLANGCILINT_CMD := $(shell go env GOPATH)/bin/golangci-lint
  ifeq ($(GOLANGCILINT_CMD), /bin/golangci-lint) # GOPATH not set or empty
    GOLANGCILINT_CMD := $(HOME)/go/bin/golangci-lint
  endif
endif

.PHONY: all build clean test test-coverage test-race lint fmt deps docker-build docker-run help

## Default target
all: clean fmt lint test build

## Build the binary
build:
	@echo "Building $(BINARY_NAME) version $(VERSION)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) $(SRC_DIR)

## Build for multiple platforms
build-all: clean
	@echo "Building for multiple platforms..."
	@mkdir -p $(BUILD_DIR)
	# Linux amd64
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(SRC_DIR)
	# Linux arm64
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(SRC_DIR)
	# macOS amd64
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(SRC_DIR)
	# macOS arm64
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(SRC_DIR)
	# Windows amd64
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(SRC_DIR)

## Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -rf dist/

## Run tests
test:
	@echo "Running tests..."
	$(GOTEST) -v ./...

## Run tests with coverage
test-coverage:
	@echo "Running tests with coverage..."
	$(GOTEST) -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## Run tests with race detection
test-race:
	@echo "Running tests with race detection..."
	$(GOTEST) -race ./...

## Run integration tests
test-integration:
	@echo "Running integration tests..."
	$(GOTEST) -v ./test/integration/...

## Lint code
lint:
	@echo "Running linter..."
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	$(GOLANGCILINT_CMD) run

## Format code
fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

## Install dependencies
deps:
	@echo "Installing dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

## Update dependencies
deps-update:
	@echo "Updating dependencies..."
	$(GOMOD) get -u ./...
	$(GOMOD) tidy

## Verify dependencies
deps-verify:
	@echo "Verifying dependencies..."
	$(GOMOD) verify

## Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .
	docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest

## Run Docker container
docker-run:
	docker run -it --rm \
		-v ~/.keeper/ksm-mcp:/home/ksm/.keeper/ksm-mcp \
		$(DOCKER_IMAGE):$(DOCKER_TAG)

## Build and push Docker image to Docker Hub
docker-push: docker-build
	@echo "Pushing Docker image to Docker Hub..."
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	@if [ "$(DOCKER_TAG)" != "latest" ]; then \
		docker tag $(DOCKER_IMAGE):$(DOCKER_TAG) $(DOCKER_IMAGE):latest; \
		docker push $(DOCKER_IMAGE):latest; \
	fi

## Build multi-platform Docker image and push to Docker Hub
docker-push-multi:
	@echo "Building and pushing multi-platform Docker image..."
	docker buildx create --use --name ksm-mcp-builder || true
	docker buildx build --platform linux/amd64,linux/arm64 \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) \
		-t $(DOCKER_IMAGE):latest \
		--push .
	docker buildx rm ksm-mcp-builder

## Install binary to local system
install: build
	@echo "Installing $(BINARY_NAME) to /usr/local/bin..."
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/

## Uninstall binary from local system
uninstall:
	@echo "Removing $(BINARY_NAME) from /usr/local/bin..."
	sudo rm -f /usr/local/bin/$(BINARY_NAME)

## Run security scan
security:
	@echo "Running security scan..."
	@which gosec > /dev/null || (echo "Installing gosec..." && go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest)
	gosec ./...

## Generate protobuf files (if needed)
proto:
	@echo "Generating protobuf files..."
	# Add protobuf generation commands here if needed

## Run the application locally
run: build
	./$(BUILD_DIR)/$(BINARY_NAME)

## Show available targets
help:
	@echo "Available targets:"
	@echo "  build          - Build the binary"
	@echo "  build-all      - Build for multiple platforms"
	@echo "  clean          - Clean build artifacts"
	@echo "  test           - Run tests"
	@echo "  test-coverage  - Run tests with coverage"
	@echo "  test-race      - Run tests with race detection"
	@echo "  test-integration - Run integration tests"
	@echo "  lint           - Run linter"
	@echo "  fmt            - Format code"
	@echo "  deps           - Install dependencies"
	@echo "  deps-update    - Update dependencies"
	@echo "  deps-verify    - Verify dependencies"
	@echo "  docker-build   - Build Docker image"
	@echo "  docker-run     - Run Docker container"
	@echo "  docker-push    - Build and push Docker image to Docker Hub"
	@echo "  docker-push-multi - Build and push multi-platform image"
	@echo "  install        - Install binary to /usr/local/bin"
	@echo "  uninstall      - Remove binary from /usr/local/bin"
	@echo "  security       - Run security scan"
	@echo "  run            - Build and run the application"
	@echo "  help           - Show this help message"