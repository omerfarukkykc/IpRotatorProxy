@echo off
REM Build Linux binary using Docker and output to ./bin directory

echo Building Linux AMD64 binary...

REM Create bin directory if it doesn't exist
if not exist "bin" mkdir bin

REM Build the Docker image
docker build -t iprotator-builder -f Dockerfile.build .
if %errorlevel% neq 0 (
    echo Docker build failed!
    exit /b 1
)

REM Run the container with volume mount to copy the binary out
docker run --rm -v "%cd%\bin:/output" iprotator-builder
if %errorlevel% neq 0 (
    echo Docker run failed!
    exit /b 1
)

echo.
echo Build complete! Binary available at: bin\iprotator-linux-amd64
echo.
