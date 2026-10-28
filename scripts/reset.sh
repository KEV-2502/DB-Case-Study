#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "==> Resetting Neo4j Case Study database to baseline state..."
"${PROJECT_DIR}/scripts/seed.sh"
