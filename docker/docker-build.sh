#!/bin/bash
# LLDPq Docker Build Script
# Builds Docker image and exports as tar.gz
#
# Usage: ./docker/docker-build.sh
# Run from repo root directory, on any machine with Docker installed
#
# Output: ~/lldpq-<arch>.tar.gz and ~/lldpq-<arch>.tar.gz.sha256

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RED='\033[0;31m'
NC='\033[0m'

IMAGE_NAME="lldpq"
IMAGE_TAG="latest"

# Detect architecture: amd64 or arm64
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH_LABEL="amd64" ;;
    aarch64) ARCH_LABEL="arm64" ;;
    *)       ARCH_LABEL="$ARCH" ;;
esac
OUTPUT_FILE="$HOME/lldpq-${ARCH_LABEL}.tar.gz"

# Find repo root (script is in docker/ subfolder)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERSION=$(cat "$REPO_ROOT/VERSION" 2>/dev/null || echo "dev")
GIT_COMMIT=$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || printf 'unknown')

echo -e "${CYAN}╔══════════════════════════════════════╗${NC}"
echo -e "${CYAN}║    LLDPq Docker Build v${VERSION}         ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════╝${NC}"
echo ""

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: Docker not installed${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/4]${NC} Building Docker image..."
cd "$REPO_ROOT"
sudo docker build \
    -f docker/Dockerfile \
    --build-arg TARGETARCH="${ARCH_LABEL}" \
    --build-arg LLDPQ_VERSION="${VERSION}" \
    --label "org.opencontainers.image.revision=${GIT_COMMIT}" \
    -t "${IMAGE_NAME}:${IMAGE_TAG}" \
    -t "${IMAGE_NAME}:${VERSION}" \
    . 2>&1 | tail -5
echo -e "${GREEN}  ✓ Built${NC}"
echo ""

echo -e "${YELLOW}[2/4]${NC} Image info:"
sudo docker images ${IMAGE_NAME} --format '  {{.Repository}}:{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}'
echo ""

echo -e "${YELLOW}[3/4]${NC} Exporting to ${OUTPUT_FILE}..."
sudo docker save ${IMAGE_NAME}:${IMAGE_TAG} | gzip > "${OUTPUT_FILE}"
chmod 644 "${OUTPUT_FILE}"
SIZE=$(du -h "${OUTPUT_FILE}" | awk 'NR == 1 {print $1}')
echo -e "${GREEN}  ✓ Exported (${SIZE})${NC}"
# SHA-256 next to the archive, named by its bare file name so that
# "sha256sum -c" works wherever both files are downloaded to. The guide tells
# operators to verify one before loading the image.
CHECKSUM_FILE="${OUTPUT_FILE}.sha256"
if (
    cd "$(dirname "${OUTPUT_FILE}")" || exit 1
    if command -v sha256sum > /dev/null 2>&1; then
        sha256sum "$(basename "${OUTPUT_FILE}")"
    else
        shasum -a 256 "$(basename "${OUTPUT_FILE}")"
    fi
) > "${CHECKSUM_FILE}"; then
    chmod 644 "${CHECKSUM_FILE}"
    echo -e "${GREEN}  ✓ SHA-256 written to ${CHECKSUM_FILE}${NC}"
else
    rm -f "${CHECKSUM_FILE}"
    CHECKSUM_FILE=""
    echo -e "${YELLOW}  ⚠ SHA-256 not written (neither sha256sum nor shasum worked)${NC}"
fi
echo ""

echo -e "${YELLOW}[4/4]${NC} Cleaning up old test containers..."
sudo docker rm -f lldpq-test 2>/dev/null || true
echo -e "${GREEN}  ✓ Clean${NC}"
echo ""

echo -e "${GREEN}╔══════════════════════════════════════╗${NC}"
echo -e "${GREEN}║    Build Complete!                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════╝${NC}"
echo ""
echo -e "Image:  ${CYAN}${IMAGE_NAME}:${VERSION}${NC} (${SIZE})"
echo -e "Commit: ${CYAN}${GIT_COMMIT}${NC}"
echo -e "Arch:   ${CYAN}${ARCH_LABEL}${NC}"
echo -e "File:   ${CYAN}${OUTPUT_FILE}${NC}"
[ -z "${CHECKSUM_FILE}" ] || echo -e "SHA256: ${CYAN}${CHECKSUM_FILE}${NC}"
echo ""
if [ -n "${CHECKSUM_FILE}" ]; then
    echo -e "Upload: ${YELLOW}scp ~/lldpq-${ARCH_LABEL}.tar.gz ~/lldpq-${ARCH_LABEL}.tar.gz.sha256 user@host:~/${NC}"
else
    echo -e "Upload: ${YELLOW}scp ~/lldpq-${ARCH_LABEL}.tar.gz user@host:~/${NC}"
fi
echo -e "Load:   ${YELLOW}docker load < lldpq-${ARCH_LABEL}.tar.gz${NC}"
echo -e "Run:    ${YELLOW}see \"Quick start\" in DOCKER.md${NC}"
echo -e "Release: check the image once on a Cumulus switch: ${YELLOW}sudo bash docker/test-mgmt-vrf-switch.sh${NC}"
