#!/usr/bin/env bash
set -euo pipefail

CONTAINER_NAME="neo4j-case-study"

if docker ps --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}\$"; then
    echo "Stopping container '${CONTAINER_NAME}'..."
    docker stop "${CONTAINER_NAME}"
else
    echo "Container '${CONTAINER_NAME}' is not running."
fi
