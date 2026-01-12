# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o iprotator ./cmd/iprotator

# Runtime stage
FROM alpine:3.19

WORKDIR /app

# Install ca-certificates for HTTPS
RUN apk --no-cache add ca-certificates

# Copy binary from builder
COPY --from=builder /app/iprotator .

# Copy default config
COPY config.yaml .

# Expose proxy port
EXPOSE 8080

# Run the application
ENTRYPOINT ["./iprotator"]
CMD ["-config", "/app/config.yaml"]
