# Build Stage
FROM golang:1.24-alpine AS builder
ARG BYPASS_SSL=false
WORKDIR /app

# Install dependencies
RUN apk add --no-cache git make \
     $([ "$BYPASS_SSL" = "true" ] && echo "--allow-untrusted --no-check-certificate")

# Download Go modules early for cache efficiency
COPY go.mod go.sum ./

# Go module download with optional insecure config
RUN GOPROXY=$([ "$BYPASS_SSL" = "true" ] && echo "direct" || echo "") \
    GIT_SSL_NO_VERIFY=$([ "$BYPASS_SSL" = "true" ] && echo "true" || echo "") \
    GOINSECURE=$([ "$BYPASS_SSL" = "true" ] && (grep -E '^\s*[a-zA-Z0-9.-]+\.[^ ]+/' go.mod 2>/dev/null | awk '{print $1}' | cut -d/ -f1 | sort -u | tr '\n' ',' | sed 's/,$//' || echo "*") || echo "") \
    go mod download -x

# Copy source and build
COPY . .

# Build the binary with security flags
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -extldflags '-static' -X main.Version=$(git describe --tags --always --dirty 2>/dev/null || echo 'docker')" \
    -a -installsuffix cgo \
    -o ksm-mcp ./cmd/ksm-mcp

# Set up user and layout
RUN adduser -D ksm && \
    install -d -o ksm -g ksm -m 750 /home/ksm/.keeper/ksm-mcp/logs && \
    mv ksm-mcp configs/config-example.yml LICENSE /home/ksm/ && \
    mkdir -p /home/ksm/.keeper/ksm-mcp && \
    mv /home/ksm/config-example.yml /home/ksm/.keeper/ksm-mcp/config.yaml && \
    chown -R ksm:ksm /home/ksm

# Final Stage
FROM scratch AS final
LABEL org.opencontainers.image.title="KSM MCP Server" \
      org.opencontainers.image.description="Keeper Secrets Manager Model Context Protocol Server" \
      org.opencontainers.image.vendor="Keeper Security" \
      org.opencontainers.image.source="https://github.com/keeper-security/ksm-mcp" \
      org.opencontainers.image.documentation="https://github.com/keeper-security/ksm-mcp/blob/main/README.md"

USER ksm

COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /home/ksm/ /home/ksm/

WORKDIR /home/ksm

ENV PATH="/home/ksm:$PATH"

# Add health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["ksm-mcp", "--help"]

ENTRYPOINT ["ksm-mcp"]
CMD ["serve"]
  
EXPOSE 8080