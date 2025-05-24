#!/bin/bash

# KSM MCP Release Script
# Usage: ./scripts/release.sh [version]

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Get version from argument or prompt
VERSION=${1:-}
if [ -z "$VERSION" ]; then
    echo -n "Enter release version (e.g., 1.0.0): "
    read VERSION
fi

# Validate version format
if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9]+)?$'; then
    echo -e "${RED}Error: Invalid version format. Use semantic versioning (e.g., 1.0.0 or 1.0.0-beta1)${NC}"
    exit 1
fi

TAG="v$VERSION"

echo -e "${BLUE}Preparing release $TAG${NC}"

# Check if we're on main branch
CURRENT_BRANCH=$(git branch --show-current)
if [ "$CURRENT_BRANCH" != "main" ]; then
    echo -e "${YELLOW}Warning: Not on main branch (current: $CURRENT_BRANCH)${NC}"
    echo -n "Continue anyway? (y/N): "
    read CONFIRM
    if [ "$CONFIRM" != "y" ]; then
        exit 1
    fi
fi

# Check for uncommitted changes
if ! git diff-index --quiet HEAD --; then
    echo -e "${RED}Error: Uncommitted changes found${NC}"
    git status --short
    exit 1
fi

# Pull latest changes
echo -e "${GREEN}Pulling latest changes...${NC}"
git pull origin main

# Run tests
echo -e "${GREEN}Running tests...${NC}"
make test

# Update version in code
echo -e "${GREEN}Updating version in code...${NC}"
# Update version.go if it exists
if [ -f "internal/version/version.go" ]; then
    sed -i.bak "s/Version = \".*\"/Version = \"$VERSION\"/" internal/version/version.go
    rm internal/version/version.go.bak
fi

# Update README.md version badge if present
if grep -q "version-v[0-9]" README.md; then
    sed -i.bak "s/version-v[0-9].[0-9].[0-9]/version-v$VERSION/" README.md
    rm README.md.bak
fi

# Build all platforms
echo -e "${GREEN}Building binaries for all platforms...${NC}"
make clean
make build-all

# Create changelog
echo -e "${GREEN}Creating changelog...${NC}"
CHANGELOG_FILE="CHANGELOG_${VERSION}.md"
cat > $CHANGELOG_FILE << EOF
# Release Notes for v$VERSION

## What's New

### Features
- 

### Improvements
- 

### Bug Fixes
- 

### Documentation
- 

## Installation

### Docker
\`\`\`bash
docker pull keeper/ksm-mcp:$VERSION
\`\`\`

### Binary Installation
Download the appropriate binary for your platform from the release page.

### Homebrew
\`\`\`bash
brew tap keeper-security/tap
brew install ksm-mcp
\`\`\`

## Checksums
See \`checksums.txt\` in the release assets.
EOF

echo -e "${YELLOW}Please edit the changelog: $CHANGELOG_FILE${NC}"
echo "Press Enter when done..."
read

# Commit version changes
if git diff --quiet; then
    echo -e "${YELLOW}No version changes to commit${NC}"
else
    echo -e "${GREEN}Committing version changes...${NC}"
    git add -A
    git commit -m "chore: bump version to $VERSION"
fi

# Create and push tag
echo -e "${GREEN}Creating tag $TAG...${NC}"
git tag -a "$TAG" -m "Release $VERSION"

# Push changes
echo -e "${GREEN}Pushing changes and tag...${NC}"
git push origin main
git push origin "$TAG"

# Create GitHub release
echo -e "${GREEN}Creating GitHub release...${NC}"
if command -v gh &> /dev/null; then
    gh release create "$TAG" \
        --title "KSM MCP $TAG" \
        --notes-file "$CHANGELOG_FILE" \
        --draft \
        dist/*
    
    echo -e "${GREEN}Draft release created!${NC}"
    echo "Visit the releases page to publish: https://github.com/keeper-security/ksm-mcp/releases"
else
    echo -e "${YELLOW}GitHub CLI not found. Please create the release manually.${NC}"
fi

# Docker build and push (if logged in)
if docker info &> /dev/null; then
    echo -e "${GREEN}Building Docker images...${NC}"
    make docker
    
    echo -e "${YELLOW}To push Docker images, run:${NC}"
    echo "  docker push keeper/ksm-mcp:$VERSION"
    echo "  docker push keeper/ksm-mcp:latest"
fi

# Clean up
rm -f "$CHANGELOG_FILE"

echo -e "${GREEN}✅ Release preparation complete!${NC}"
echo
echo "Next steps:"
echo "1. Review and publish the GitHub release"
echo "2. Push Docker images if not done automatically"
echo "3. Update documentation if needed"
echo "4. Announce the release"