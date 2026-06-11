# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum* ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o honeypot ./cmd/server

# Runtime stage
FROM alpine:3.18

# Install ca-certificates and curl for healthcheck
RUN apk --no-cache add ca-certificates curl

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/honeypot .

# Run as non-root user
RUN addgroup -g 1000 honeypot && adduser -D -u 1000 -G honeypot honeypot
USER honeypot

# Expose ports
# CHARGEN (UDP)
EXPOSE 19/udp
# DNS (UDP)
EXPOSE 53/udp
# NTP (UDP)
EXPOSE 123/udp
# Coordinator API (TCP)
EXPOSE 8080/tcp

# Health check - verify coordinator API is responding
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8080/experiments || exit 1

# Run the honeypot with environment variable support
# Environment variables can be set via docker-compose or docker run -e
# HONEYPOT_IPS: comma-separated IPs to bind to (e.g., "10.0.0.1,10.0.0.2")
# DNS_PORT: DNS port (default: 53)
# NTP_PORT: NTP port (default: 123)
# COORDINATOR_ADDR: coordinator address (default: 0.0.0.0:8080)
# EVENTS_FILE: path to event log file (optional)
# EXPERIMENTS_FILE: path to experiments YAML file (optional)
ENTRYPOINT ["/app/honeypot"]
