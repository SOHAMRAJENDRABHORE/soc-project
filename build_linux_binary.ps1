# build_linux_binary.ps1
# Builds the Linux SOC-Endpoint-Agent binary using Docker (no Linux machine needed).
#
# Prerequisites:
#   - Docker Desktop installed and running
#   - Linux containers mode (default on Docker Desktop)
#
# Usage:
#   .\build_linux_binary.ps1
#
# Output: dist\SOC-Endpoint-Agent  (Linux ELF binary, copy to any Linux endpoint)

$ErrorActionPreference = "Stop"

$IMAGE = "soc-endpoint-builder"
$CONTAINER = "soc-endpoint-build-run"
$PROJECT = $PSScriptRoot
$DIST = Join-Path $PROJECT "dist"

Write-Host ""
Write-Host "=== SOC Endpoint Agent — Linux Binary Builder ==="
Write-Host "    Uses Docker to compile on Linux from your Windows machine."
Write-Host ""

# Check Docker is available
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker not found. Install Docker Desktop from https://www.docker.com/products/docker-desktop/"
    exit 1
}

# Check Docker daemon is running
$dockerInfo = docker info 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Docker daemon is not running. Start Docker Desktop and try again."
    exit 1
}

Write-Host "[1/4] Building Docker image..."
docker build -f "$PROJECT\Dockerfile.endpoint-builder" -t $IMAGE "$PROJECT"
if ($LASTEXITCODE -ne 0) { Write-Error "Docker image build failed."; exit 1 }

Write-Host ""
Write-Host "[2/4] Running PyInstaller inside Linux container..."

# Remove any stale container from a previous run
docker rm -f $CONTAINER 2>$null | Out-Null

docker run --name $CONTAINER $IMAGE
if ($LASTEXITCODE -ne 0) { Write-Error "PyInstaller build inside container failed."; exit 1 }

Write-Host ""
Write-Host "[3/4] Copying Linux binary out of container..."
New-Item -ItemType Directory -Force -Path $DIST | Out-Null
docker cp "${CONTAINER}:/app/dist/SOC-Endpoint-Agent" "$DIST\SOC-Endpoint-Agent"
if ($LASTEXITCODE -ne 0) { Write-Error "Could not copy binary from container."; exit 1 }

Write-Host ""
Write-Host "[4/4] Cleaning up container..."
docker rm $CONTAINER | Out-Null

Write-Host ""
Write-Host "============================================================"
Write-Host "  Build successful!"
Write-Host "  Output: dist\SOC-Endpoint-Agent  (Linux ELF binary)"
Write-Host ""
Write-Host "  Copy dist\SOC-Endpoint-Agent to any Linux endpoint and run:"
Write-Host "    chmod +x SOC-Endpoint-Agent"
Write-Host "    ./SOC-Endpoint-Agent"
Write-Host ""
Write-Host "  No Python installation required on the Linux endpoint."
Write-Host "============================================================"
