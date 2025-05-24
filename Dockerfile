# Multi-stage build for security and minimal image size
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make ca-certificates

# Set working directory
WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary with security flags
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -extldflags '-static' -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo 'docker')" \
    -a -installsuffix cgo \
    -o ksm-mcp ./cmd/ksm-mcp

# Create config example
RUN echo '# KSM MCP Configuration\n\
server:\n\
  host: "0.0.0.0"\n\
  port: 8080\n\
  timeout: 30s\n\
\n\
security:\n\
  enable_master_password: false\n\
  session_timeout: 24h\n\
  max_failed_attempts: 5\n\
  enable_audit_log: true\n\
\n\
profiles:\n\
  default: ""\n\
\n\
logging:\n\
  level: "info"\n\
  format: "json"\n\
  output: "stdout"' > config.yaml.example

# Final stage - minimal image
FROM alpine:latest

# Add ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 -S keeper && \
    adduser -u 1000 -S keeper -G keeper

# Create necessary directories
RUN mkdir -p /home/keeper/.keeper/ksm-mcp && \
    mkdir -p /var/log/ksm-mcp && \
    chown -R keeper:keeper /home/keeper /var/log/ksm-mcp

# Copy binary and config from builder
COPY --from=builder /build/ksm-mcp /usr/local/bin/ksm-mcp
COPY --from=builder /build/config.yaml.example /home/keeper/.keeper/ksm-mcp/config.yaml.example

# Set up volumes for persistent data and secrets
VOLUME ["/home/keeper/.keeper/ksm-mcp", "/run/secrets", "/var/log/ksm-mcp"]

# Switch to non-root user
USER keeper
WORKDIR /home/keeper

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["ksm-mcp", "test", "--profile", "docker"] || exit 1

# Labels for metadata
LABEL org.opencontainers.image.title="KSM MCP Server" \
      org.opencontainers.image.description="Keeper Secrets Manager Model Context Protocol Server" \
      org.opencontainers.image.vendor="Keeper Security" \
      org.opencontainers.image.source="https://github.com/keeper-security/ksm-mcp" \
      org.opencontainers.image.documentation="https://github.com/keeper-security/ksm-mcp/blob/main/README.md"

# Default environment variables
ENV KSM_MCP_CONFIG_DIR=/home/keeper/.keeper/ksm-mcp \
    KSM_MCP_LOG_DIR=/var/log/ksm-mcp \
    KSM_MCP_LOG_LEVEL=info \
    KSM_MCP_PROFILE=docker

# Expose MCP server port (stdio mode doesn't need ports, but useful for health checks)
EXPOSE 8080

# Set entrypoint with default command
ENTRYPOINT ["ksm-mcp"]
CMD ["serve"]