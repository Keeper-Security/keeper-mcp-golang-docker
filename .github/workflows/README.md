# GitHub Actions Workflows

This directory contains GitHub Actions workflows for the KSM MCP project.

## Release Pipeline

The `release.yml` workflow provides a complete CI/CD pipeline that:

1. **Tests** - Runs all unit tests, integration tests, linting, and security scans
2. **Builds** - Creates binaries for multiple platforms (Linux, macOS, Windows)
3. **Releases** - Creates a GitHub release with all binaries
4. **Docker** - Builds and pushes multi-platform Docker images to Docker Hub

### Workflow Triggers

1. **Tag Push**: Automatically triggered when pushing a version tag (e.g., `v1.0.0`)
2. **Manual Dispatch**: Can be triggered manually from GitHub Actions UI with options:
   - `tag`: Release tag to use (e.g., `v1.0.0`, `v1.0.0-beta.1`)
   - `skip_tests`: Skip the test phase (not recommended for production releases)

### Environment Requirements

The workflow uses the `poc` environment with the following secrets/variables:

- **Secret**: `DOCKER_HUB_TOKEN` - Docker Hub access token
- **Variable**: `DOCKER_HUB_USERNAME` - Docker Hub username

### Pipeline Stages

#### 1. Test Suite
- Verifies code formatting
- Runs golangci-lint for code quality
- Executes unit tests with race detection and coverage
- Runs integration tests
- Performs security scanning with gosec
- Uploads test coverage reports and security scan results

#### 2. Build Binaries
- Builds for multiple platforms:
  - Linux (amd64, arm64)
  - macOS (amd64, arm64)
  - Windows (amd64)
- Validates version consistency between git tag and code
- Creates compressed archives (.tar.gz for Unix, .zip for Windows)

#### 3. GitHub Release
- Creates a GitHub release with:
  - All platform binaries
  - Auto-generated release notes
  - Installation instructions
  - SHA256 checksums
- Marks pre-releases for tags containing `-`

#### 4. Docker Publishing
- Builds multi-platform Docker images (amd64, arm64)
- Pushes to Docker Hub with tags:
  - Version tag (e.g., `v1.0.0`)
  - Major.minor tag (e.g., `1.0`)
  - Latest tag (for stable releases)

#### 5. Summary
- Generates a comprehensive summary of the pipeline execution
- Shows status of each stage
- Provides quick access to Docker pull commands and release page

### Creating a New Release

1. **Update the version** in `cmd/ksm-mcp/main.go`:
   ```go
   const Version = "v1.0.1"  // Must match the tag
   ```

2. **Commit the version change**:
   ```bash
   git add cmd/ksm-mcp/main.go
   git commit -m "Bump version to v1.0.1"
   git push
   ```

3. **Create and push the tag**:
   ```bash
   git tag v1.0.1
   git push origin v1.0.1
   ```

The workflow will automatically:
- Run all tests
- Build binaries for all platforms
- Create a GitHub release with binaries
- Push Docker images to `keepersecurityinc/ksm-mcp-poc`

### Manual Workflow Dispatch

For development or testing purposes, you can trigger the workflow manually:

1. Go to Actions → Release Pipeline
2. Click "Run workflow"
3. Enter the desired tag (e.g., `v1.0.1-beta.1`)
4. Optionally check "Skip tests" for faster builds (not recommended for production)
5. Click "Run workflow"

### Version Validation

- For tag pushes, the workflow validates that the git tag matches the version in the code
- Manual triggers skip this validation, allowing for development builds
- Pre-release tags (containing `-`) are marked as pre-releases in GitHub

### Docker Images

Images are published to Docker Hub at `keepersecurityinc/ksm-mcp-poc` with:
- Multi-platform support (amd64 and arm64)
- Version tags matching the release
- Automatic `latest` tag for stable releases

### Manual Docker Publishing

You can also build and push Docker images locally using the Makefile:

```bash
# Login to Docker Hub first
docker login

# Build and push with specific tag
make docker-push DOCKER_TAG=v1.0.0

# Build and push multi-platform image
make docker-push-multi DOCKER_TAG=v1.0.0
```