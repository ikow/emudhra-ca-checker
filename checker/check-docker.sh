#!/usr/bin/env bash
# Run the emudhra-checker inside a Docker container.
# Usage: ./check-docker.sh [image]
# Default image: ubuntu:24.04

set -euo pipefail

IMAGE="${1:-ubuntu:24.04}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Running emudhra-checker inside: $IMAGE"
echo ""

docker run --rm \
  -v "$SCRIPT_DIR/check.sh:/check.sh:ro" \
  "$IMAGE" \
  bash /check.sh

echo ""
echo "Image tested: $IMAGE"
