#!/usr/bin/env bash
set -euo pipefail

# Directory of this script and project root (safe with spaces)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CONTAINER_NAME="neo4j-case-study"
NEO4J_USER="neo4j"
NEO4J_PASS="password123"

if ! docker ps --format '{{.Names}}' | grep -Eq "^${CONTAINER_NAME}\$"; then
    echo "Error: Container '${CONTAINER_NAME}' is not running."
    echo "Start it first with: ./scripts/start.sh"
    exit 1
fi

echo "==> Applying Schema Constraints and Indexes..."
docker exec -i "${CONTAINER_NAME}" cypher-shell -u "${NEO4J_USER}" -p "${NEO4J_PASS}" < "${PROJECT_DIR}/cypher/schema.cypher" || true

echo "==> Seeding Graph Data (Applications, Packages, Relationships, Simulated Vulnerabilities)..."
docker exec -i "${CONTAINER_NAME}" cypher-shell -u "${NEO4J_USER}" -p "${NEO4J_PASS}" < "${PROJECT_DIR}/cypher/seed.cypher"

echo "==> Database seeded successfully!"
echo "==> Summary check:"
docker exec -i "${CONTAINER_NAME}" cypher-shell -u "${NEO4J_USER}" -p "${NEO4J_PASS}" \
    "MATCH (a:Application) WITH count(a) AS apps MATCH (p:Package) WITH apps, count(p) AS pkgs MATCH ()-[r:DEPENDS_ON]->() RETURN apps AS Applications, pkgs AS Packages, count(r) AS Dependencies;"
