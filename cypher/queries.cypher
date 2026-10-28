// ==============================================================================
// Demonstration Cypher Queries
// Case Study: Graph-Based Software Dependency & Vulnerability Impact Analysis
// Target: Neo4j 5.x Community Edition
// ==============================================================================

// ------------------------------------------------------------------------------
// QUERY 1: Display Entire Dependency Graph
// Purpose: Visual overview in Neo4j Browser showing all nodes and directed relationships.
// Demonstrates: Applications (orange), Packages (blue), and directed [:DEPENDS_ON] edges.
// ------------------------------------------------------------------------------
MATCH (n)
OPTIONAL MATCH (n)-[r:DEPENDS_ON]->(m)
RETURN n, r, m;


// ------------------------------------------------------------------------------
// QUERY 2: Direct Dependencies of a Selected Application
// Purpose: Retrieve immediate (1-hop) direct libraries declared by 'App-PaymentGateway'.
// Relational Comparison: Equivalent to a standard single-hop foreign key JOIN in SQL.
// ------------------------------------------------------------------------------
MATCH (app:Application {name: 'App-PaymentGateway'})-[rel:DEPENDS_ON]->(pkg:Package)
RETURN app.name AS Application,
       pkg.name AS DirectPackage,
       pkg.version AS Version,
       pkg.ecosystem AS Ecosystem,
       rel.declaredIn AS DeclaredIn
ORDER BY pkg.name;


// ------------------------------------------------------------------------------
// QUERY 3: Transitive Dependencies of an Application (Variable-Length Path)
// Purpose: Discover all downstream libraries (both direct and indirect) up to depth 5.
// Demonstrates: Cypher's variable-length traversal syntax (:DEPENDS_ON*1..5).
// Relational Comparison: In SQL, this requires a recursive Common Table Expression (CTE)
//                        with iterative self-joins.
// ------------------------------------------------------------------------------
MATCH path = (app:Application {name: 'App-PaymentGateway'})-[:DEPENDS_ON*1..5]->(pkg:Package)
RETURN DISTINCT app.name AS Application,
       pkg.name AS DependencyPackage,
       pkg.version AS Version,
       pkg.isVulnerable AS IsVulnerable,
       pkg.vulnerabilityId AS VulnerabilityID,
       min(length(path)) AS MinHopsFromApp
ORDER BY MinHopsFromApp, pkg.name;


// ------------------------------------------------------------------------------
// QUERY 4: Vulnerability Impact Analysis (Reverse Reachability)
// Purpose: Given all packages with simulated vulnerabilities, traverse backwards
//          along incoming [:DEPENDS_ON] paths to identify all exposed applications.
// Demonstrates: Graph inverted reachability without full-table scans.
// ------------------------------------------------------------------------------
MATCH (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
RETURN DISTINCT app.name AS AffectedApplication,
       app.environment AS Environment,
       app.criticality AS AppCriticality,
       vuln.name AS VulnerablePackage,
       vuln.vulnerabilityId AS SimulatedVulnID,
       vuln.severity AS VulnerabilitySeverity
ORDER BY vuln.severity DESC, app.name ASC;


// ------------------------------------------------------------------------------
// QUERY 5: Dependency Paths from Affected Applications to Vulnerable Packages
// Purpose: Trace and visualize the exact propagation chains from the root application
//          down through intermediate libraries to the vulnerable package.
// Demonstrates: Path extraction and projection functions (nodes(path), length(path)).
// ------------------------------------------------------------------------------
MATCH path = (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
RETURN app.name AS Application,
       vuln.vulnerabilityId AS SimulatedVulnID,
       vuln.name AS VulnerablePackage,
       length(path) AS DependencyDepth,
       [node IN nodes(path) | node.name] AS FullDependencyPath
ORDER BY SimulatedVulnID, app.name, DependencyDepth;


// ------------------------------------------------------------------------------
// QUERY 6: Blast Radius Summary (Affected Applications Count per Vulnerability)
// Purpose: Aggregate metric to quantify security exposure per simulated vulnerability.
// Demonstrates: In-engine graph aggregation (count(DISTINCT ...), collect(...)).
// ------------------------------------------------------------------------------
MATCH (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
RETURN vuln.vulnerabilityId AS SimulatedVulnID,
       vuln.name AS VulnerablePackage,
       vuln.severity AS Severity,
       vuln.simulatedScore AS SimulatedCVSS,
       count(DISTINCT app) AS AffectedApplicationCount,
       collect(DISTINCT app.name) AS AffectedApplications
ORDER BY AffectedApplicationCount DESC;


// ------------------------------------------------------------------------------
// QUERY 7 (Value-Add): Shortest Propagation Path to Shared Vulnerability
// Purpose: Find the most direct route from 'App-PaymentGateway' to 'lib-hash-helper'.
// Demonstrates: Neo4j's native shortestPath() algorithm executing in the graph engine.
// ------------------------------------------------------------------------------
MATCH (app:Application {name: 'App-PaymentGateway'}),
      (target:Package {name: 'lib-hash-helper'})
MATCH p = shortestPath((app)-[:DEPENDS_ON*1..5]->(target))
RETURN app.name AS SourceApplication,
       target.name AS TargetPackage,
       length(p) AS ShortestHopCount,
       [node IN nodes(p) | node.name] AS ShortestPathNodes;
