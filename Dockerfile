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

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy binary from builder
COPY --from=builder /build/honeypot .

# Run as non-root user
RUN addgroup -g 1000 honeypot && adduser -D -u 1000 -G honeypot honeypot
USER honeypot

# Expose UDP port
EXPOSE 5353/udp

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD /bin/sh -c 'test -e /proc/$$/fd/0' || exit 1

# Run the honeypot
ENTRYPOINT ["/app/honeypot"]
