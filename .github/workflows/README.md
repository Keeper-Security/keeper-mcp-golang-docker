# Docker Publishing Workflow

This directory contains GitHub Actions workflows for the KSM MCP project.

## Docker Publish Workflow

The `docker-publish.yml` workflow automates Docker image building and publishing to Docker Hub.

### Triggers

1. **Tag Push**: Automatically triggered when pushing a version tag (e.g., `v1.0.0`)
2. **Manual Dispatch**: Can be triggered manually from GitHub Actions UI with custom tags

### Environment Setup

The workflow uses the `poc` environment with the following secrets/variables:

- **Secret**: `DOCKER_HUB_TOKEN` - Docker Hub access token
- **Variable**: `DOCKER_HUB_USERNAME` - Docker Hub username

### Version Validation

For tag pushes, the workflow validates that the git tag matches the version in `cmd/ksm-mcp/main.go`. This ensures consistency between releases and code.

### Manual Docker Publishing

You can also push Docker images manually using the Makefile:

```bash
# Login to Docker Hub first
docker login

# Build and push with default tag (latest)
make docker-push

# Build and push with specific tag
make docker-push DOCKER_TAG=v1.0.0

# Build and push multi-platform image (amd64 + arm64)
make docker-push-multi DOCKER_TAG=v1.0.0
```

### Creating a New Release

1. Update the version in `cmd/ksm-mcp/main.go`:
   ```go
   const Version = "v1.0.1"  // Must match the tag
   ```

2. Commit the version change:
   ```bash
   git add cmd/ksm-mcp/main.go
   git commit -m "Bump version to v1.0.1"
   git push
   ```

3. Create and push the tag:
   ```bash
   git tag v1.0.1
   git push origin v1.0.1
   ```

The workflow will automatically build and push the Docker image to:
- `keepersecurityinc/ksm-mcp-poc:v1.0.1`
- `keepersecurityinc/ksm-mcp-poc:latest`

### Manual Workflow Dispatch

You can also trigger the workflow manually from the GitHub Actions tab:

1. Go to Actions → Docker Build and Publish
2. Click "Run workflow"
3. Enter the desired tag (e.g., `dev`, `beta`, `v1.0.1`)
4. Click "Run workflow"

Note: Manual triggers don't validate version matching, allowing for development/testing tags.