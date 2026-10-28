#!/usr/bin/env bash
set -euo pipefail

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

run_cypher() {
    local title="$1"
    local query="$2"
    echo "================================================================================"
    echo ">> ${title}"
    echo "--------------------------------------------------------------------------------"
    docker exec -i "${CONTAINER_NAME}" cypher-shell -u "${NEO4J_USER}" -p "${NEO4J_PASS}" "${query}"
    echo ""
}

echo "Executing Essential Demonstration Queries against Neo4j..."
echo ""

run_cypher "QUERY 1: Direct Dependencies of 'App-PaymentGateway'" \
"MATCH (app:Application {name: 'App-PaymentGateway'})-[rel:DEPENDS_ON]->(pkg:Package)
RETURN app.name AS Application, pkg.name AS DirectPackage, pkg.version AS Version, rel.declaredIn AS DeclaredIn
ORDER BY pkg.name;"

run_cypher "QUERY 2: Transitive Dependencies of 'App-PaymentGateway' (All Downstream Libraries)" \
"MATCH path = (app:Application {name: 'App-PaymentGateway'})-[:DEPENDS_ON*1..5]->(pkg:Package)
RETURN DISTINCT app.name AS Application, pkg.name AS Dependency, pkg.version AS Version, pkg.isVulnerable AS IsVulnerable, min(length(path)) AS Depth
ORDER BY Depth, pkg.name;"

run_cypher "QUERY 3: Vulnerability Impact Analysis (Affected Applications)" \
"MATCH (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
RETURN DISTINCT app.name AS AffectedApplication, app.environment AS Environment, vuln.name AS VulnerablePackage, vuln.vulnerabilityId AS SimulatedVulnID, vuln.severity AS Severity
ORDER BY vuln.severity DESC, app.name ASC;"

run_cypher "QUERY 4: Exact Dependency Propagation Paths to Vulnerabilities" \
"MATCH path = (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
RETURN app.name AS Application, vuln.vulnerabilityId AS SimulatedVulnID, vuln.name AS VulnerablePackage, length(path) AS Depth, [n IN nodes(path) | n.name] AS PropagationPath
ORDER BY SimulatedVulnID, app.name, Depth;"

run_cypher "QUERY 5: Blast Radius Summary (Count of Applications Affected per Vulnerability)" \
"MATCH (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
RETURN vuln.vulnerabilityId AS SimulatedVulnID, vuln.name AS VulnerablePackage, vuln.severity AS Severity, count(DISTINCT app) AS AffectedAppsCount, collect(DISTINCT app.name) AS AffectedApplications
ORDER BY AffectedAppsCount DESC;"

run_cypher "QUERY 6: Shortest Path from 'App-PaymentGateway' to Shared Vulnerable 'lib-hash-helper'" \
"MATCH (app:Application {name: 'App-PaymentGateway'}), (target:Package {name: 'lib-hash-helper'})
MATCH p = shortestPath((app)-[:DEPENDS_ON*1..5]->(target))
RETURN app.name AS SourceApplication, target.name AS TargetPackage, length(p) AS ShortestHops, [n IN nodes(p) | n.name] AS ShortestPathNodes;"
