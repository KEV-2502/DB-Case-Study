// ==============================================================================
// Database Schema: Constraints & Indexes
// Case Study: Graph-Based Software Dependency & Vulnerability Impact Analysis
// Target: Neo4j 5.x Community Edition
// ==============================================================================

// Ensure uniqueness of Application names
CREATE CONSTRAINT application_name_unique IF NOT EXISTS
FOR (a:Application)
REQUIRE a.name IS UNIQUE;

// Ensure uniqueness of Package names
CREATE CONSTRAINT package_name_unique IF NOT EXISTS
FOR (p:Package)
REQUIRE p.name IS UNIQUE;

// Index on Package vulnerability status for fast filtering
CREATE INDEX package_vulnerability_index IF NOT EXISTS
FOR (p:Package)
ON (p.isVulnerable);

// Index on simulated vulnerability identifier
CREATE INDEX package_vuln_id_index IF NOT EXISTS
FOR (p:Package)
ON (p.vulnerabilityId);
