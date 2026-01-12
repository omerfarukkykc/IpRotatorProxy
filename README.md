# IP Rotator Proxy

A Go-based HTTP/HTTPS proxy server that rotates through a pool of static IP addresses for each outgoing request.

## Features

- **HTTP Proxy**: Forward HTTP requests through rotating source IPs
- **HTTPS Tunnel**: Support for CONNECT method (HTTPS tunneling)
- **IP Rotation Strategies**: Round-robin or random IP selection
- **Configurable IP Pool**: Support for single IPs and IP ranges
- **Graceful Shutdown**: Clean shutdown on SIGINT/SIGTERM

## Installation

### Build Locally (Windows)
```bash
go build -o iprotator.exe ./cmd/iprotator
```

### Build Linux Binary via Docker
```bash
# Windows
.\build-linux.bat

# Linux/Mac
./build-linux.sh

# Binary will be at: bin/iprotator-linux-amd64
```

### Run with Docker
```bash
# Build and run
docker-compose up iprotator

# Or build image manually
docker build -t iprotator .
docker run -p 8080:8080 -v ./config.yaml:/app/config.yaml:ro --network host iprotator
```

## Configuration

Create a `config.yaml` file:

```yaml
server:
  listen_port: 8080

ip_pool:
  # Gateway for routing
  gateway: "192.168.1.1"
  
  # Subnet/CIDR notation (recommended)
  subnets:
    - "192.168.1.0/28"  # 14 usable IPs
  
  # Or single IP addresses
  # addresses:
  #   - "192.168.1.10"
  #   - "192.168.1.11"
  
  # Or IP ranges
  # ranges:
  #   - start: "192.168.1.100"
  #     end: "192.168.1.110"

rotation:
  strategy: "round-robin"  # or "random"
```

## Usage

```bash
# Run with default config (config.yaml)
./iprotator

# Run with custom config path
./iprotator -config /path/to/config.yaml
```

## Using the Proxy

Configure your application to use the proxy:

```bash
# Using curl
curl -x http://localhost:8080 http://example.com

# Using environment variables
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
```

## Requirements

- Go 1.21 or later
- Network interfaces configured with the IP addresses specified in the config

## Important Notes

1. **IP Binding**: The source IPs in your pool must be actually assigned to network interfaces on your machine for the proxy to work correctly.

2. **Permissions**: Binding to low-numbered ports (below 1024) may require root/administrator privileges.

3. **IP Range Limit**: IP ranges are limited to 1000 addresses to prevent memory issues.

## License

MIT License
