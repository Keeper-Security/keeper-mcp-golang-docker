# Contributing to KSM MCP

Thank you for your interest in contributing to KSM MCP! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Security](#security)
- [Community](#community)

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- **Be respectful**: Treat everyone with respect and kindness
- **Be collaborative**: Work together to resolve conflicts
- **Be inclusive**: Welcome and support people of all backgrounds
- **Be professional**: Maintain professionalism in all interactions

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/ksm-mcp.git
   cd ksm-mcp
   ```

3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/keeper-security/ksm-mcp.git
   ```

4. **Create a branch** for your changes:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Setup

### Prerequisites

- Go 1.21 or higher
- Make
- Docker (for containerized testing)
- golangci-lint (for linting)

### Initial Setup

```bash
# Install dependencies
make deps

# Run tests to verify setup
make test

# Build the binary
make build
```

### Development Workflow

1. **Keep your fork updated**:
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   ```

2. **Make your changes**:
   - Write clean, documented code
   - Add tests for new functionality
   - Update documentation as needed

3. **Run quality checks**:
   ```bash
   # Format code
   make fmt

   # Run linter
   make lint

   # Run tests
   make test

   # Check coverage
   make coverage
   ```

## How to Contribute

### Reporting Issues

- **Check existing issues** first to avoid duplicates
- **Use issue templates** when available
- **Provide clear descriptions** including:
  - Steps to reproduce
  - Expected behavior
  - Actual behavior
  - Environment details
  - Error messages/logs

### Suggesting Features

- **Open a discussion** first for major features
- **Explain the use case** and benefits
- **Consider implementation** complexity
- **Be open to feedback** and alternatives

### Submitting Code

1. **Small, focused changes** are easier to review
2. **One feature per PR** keeps things organized
3. **Include tests** for new functionality
4. **Update documentation** for user-facing changes
5. **Follow coding standards** (see below)

## Pull Request Process

### Before Submitting

- [ ] Code compiles without warnings
- [ ] All tests pass (`make test`)
- [ ] Code is formatted (`make fmt`)
- [ ] Linter passes (`make lint`)
- [ ] Documentation is updated
- [ ] Commit messages are clear

### PR Guidelines

1. **Title**: Use a clear, descriptive title
   ```
   feat: Add support for bulk secret operations
   fix: Resolve rate limiting issue in MCP server
   docs: Update API documentation for new tools
   ```

2. **Description**: Include:
   - What changes were made
   - Why they were necessary
   - Any breaking changes
   - Related issues

3. **Commits**: 
   - Use conventional commits format
   - Keep commits atomic and focused
   - Write clear commit messages

### Review Process

1. **Automated checks** must pass
2. **Code review** by maintainers
3. **Address feedback** promptly
4. **Squash commits** if requested
5. **Maintain patience** - reviews take time

## Coding Standards

### Go Code Style

We follow standard Go conventions:

```go
// Package comment describes the package purpose
package example

import (
    "fmt"
    "strings"
    
    "github.com/keeper-security/ksm-mcp/pkg/types"
)

// ExampleFunction demonstrates our coding style.
// Functions should have clear, descriptive names.
func ExampleFunction(input string) (string, error) {
    // Validate input
    if input == "" {
        return "", fmt.Errorf("input cannot be empty")
    }
    
    // Process with clear variable names
    processed := strings.ToLower(input)
    
    return processed, nil
}
```

### Best Practices

1. **Error Handling**:
   ```go
   if err != nil {
       return fmt.Errorf("failed to process: %w", err)
   }
   ```

2. **Logging**:
   ```go
   logger.Info("Processing request",
       "operation", "create_secret",
       "profile", profileName,
   )
   ```

3. **Comments**:
   - Export comments for public APIs
   - Explain "why" not "what"
   - Keep comments up to date

4. **Testing**:
   - Table-driven tests preferred
   - Mock external dependencies
   - Test edge cases

### File Organization

```
internal/
├── package/
│   ├── file.go          # Main implementation
│   ├── file_test.go     # Unit tests
│   ├── types.go         # Package types
│   └── doc.go           # Package documentation
```

## Testing Guidelines

### Test Categories

1. **Unit Tests**: Test individual functions
   ```go
   func TestValidateInput(t *testing.T) {
       tests := []struct {
           name    string
           input   string
           wantErr bool
       }{
           {"valid input", "test123", false},
           {"empty input", "", true},
       }
       
       for _, tt := range tests {
           t.Run(tt.name, func(t *testing.T) {
               err := ValidateInput(tt.input)
               if (err != nil) != tt.wantErr {
                   t.Errorf("got error = %v, wantErr %v", err, tt.wantErr)
               }
           })
       }
   }
   ```

2. **Integration Tests**: Test component interactions
3. **E2E Tests**: Test complete workflows
4. **Security Tests**: Test security controls

### Running Tests

```bash
# All tests
make test

# Specific package
go test ./internal/mcp/...

# With coverage
make coverage

# E2E tests only
make test-e2e
```

### Writing Good Tests

- **Descriptive names**: Test_ComponentName_Scenario_ExpectedResult
- **Arrange-Act-Assert**: Clear test structure
- **Independent tests**: No shared state
- **Fast execution**: Mock external calls
- **Clear failures**: Good error messages

## Documentation

### Code Documentation

- **Package comments**: Describe package purpose
- **Function comments**: Explain complex logic
- **Type comments**: Document struct fields
- **Examples**: Include usage examples

### User Documentation

Update relevant docs when changing functionality:

- `README.md` - Getting started info
- `docs/API.md` - API reference
- `docs/USER_GUIDE.md` - Usage instructions
- `docs/SECURITY.md` - Security implications
- `examples/` - Working examples

### Documentation Style

- Clear and concise language
- Code examples where helpful
- Screenshots for UI changes
- Version information for API changes

## Security

### Security First

- **Never commit secrets** or credentials
- **Validate all inputs** thoroughly
- **Use secure defaults** always
- **Document security** implications
- **Test security** controls

### Reporting Security Issues

**DO NOT** open public issues for security vulnerabilities.

Email: security@keepersecurity.com

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

## Community

### Getting Help

- **GitHub Discussions**: General questions
- **GitHub Issues**: Bug reports and features
- **Documentation**: Check docs first
- **Examples**: Review example code

### Helping Others

- Answer questions in discussions
- Review pull requests
- Improve documentation
- Share your use cases

## Recognition

Contributors are recognized in:
- Release notes
- Contributors file
- Project documentation

## Thank You!

Your contributions make KSM MCP better for everyone. We appreciate your time and effort in improving the project.

---

**Questions?** Open a discussion on GitHub or reach out to the maintainers.