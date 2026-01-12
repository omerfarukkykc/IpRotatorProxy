#!/bin/bash
# Build Linux binary using Docker and output to ./bin directory

echo "Building Linux AMD64 binary..."

# Create bin directory if it doesn't exist
mkdir -p bin

# Build the Docker image and run it to extract the binary
docker build -t iprotator-builder -f Dockerfile.build .

# Run the container with volume mount to copy the binary out
docker run --rm -v "$(pwd)/bin:/output" iprotator-builder

echo ""
echo "Build complete! Binary available at: bin/iprotator-linux-amd64"
echo ""
