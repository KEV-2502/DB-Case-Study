# Graph-Based Software Dependency & Vulnerability Impact Analysis Using Neo4j

**Course:** BCSE302 Database Systems  
**Case Study 1:** Exploring Modern Database Technologies  
**Technology:** Neo4j Community Edition (Graph Database Engine) & Cypher Query Language  
**Target Environment:** CachyOS Linux (Fish Shell, Docker)

---

## 1. Project Overview

In modern software engineering, applications rarely stand alone; they depend on third-party libraries, which transitively depend on dozens or hundreds of downstream packages. When a vulnerability is discovered deep in an open-source library, security and engineering teams must rapidly determine:
1. Which applications are directly or indirectly exposed?
2. What exact dependency paths propagate the risk?
3. What is the blast radius (number of affected applications) of each vulnerability?

While relational databases require complex recursive Common Table Expressions (`WITH RECURSIVE`) and multi-table self-joins to model hierarchical or networked relationships, **Graph Databases like Neo4j** treat relationships as first-class citizens with index-free adjacency.

This prototype models a realistic software dependency ecosystem containing **3 applications**, **11 packages**, and **2 simulated vulnerability records** to demonstrate graph traversal, impact propagation, and blast-radius analysis.

> **Academic Disclaimer:** All vulnerability identifiers (`SIM-VULN-001`, `SIM-VULN-002`) and metadata are **explicitly simulated** for educational case study demonstration. This prototype does not connect to live package registries or perform real security scanning.

---

## 2. Graph Data Model

The data model uses Neo4j's **Labeled Property Graph (LPG)** model:

```
(:Application) ──[:DEPENDS_ON {scope: "direct"}]──> (:Package) ──[:DEPENDS_ON {scope: "transitive"}]──> (:Package)
```

### Node Labels & Properties
- **`:Application` Nodes (3 total):**
  - `name`: Unique identifier (e.g., `"App-PaymentGateway"`, `"App-UserPortal"`, `"App-ReportingEngine"`)
  - `environment`: Deployment tier (`"Production"`, `"Internal"`)
  - `criticality`: Business impact level (`"High"`, `"Medium"`, `"Low"`)
  - `ownerTeam`: Engineering squad
- **`:Package` Nodes (11 total):**
  - `name`: Unique library name (e.g., `"lib-auth-client"`, `"lib-crypto-base"`, `"lib-hash-helper"`)
  - `version`: SemVer string (e.g., `"1.0.4"`)
  - `ecosystem`: Package runtime (`"JVM"`)
  - `isVulnerable`: Boolean flag (`true` / `false`)
  - `vulnerabilityId`: Simulated identifier (`"SIM-VULN-001"`, `"SIM-VULN-002"`, or `"NONE"`)
  - `severity`: Simulated risk rating (`"CRITICAL"`, `"HIGH"`, `"NONE"`)
  - `simulatedScore`: CVSS score simulation (e.g., `9.8`)
  - `simulatedData`: Explicit Boolean marker (`true`)

### Relationships
- **`[:DEPENDS_ON]` Directed Edges (13 total):**
  - Directed from consumer to dependency: `(consumer)-[:DEPENDS_ON]->(dependency)`
  - Properties: `scope` (`"direct"` or `"transitive"`), `declaredIn` (`"pom.xml"` or `"transitive"`)

### Sample Topology & Simulated Vulnerabilities
- **Simulated Vulnerability 1 (`SIM-VULN-001`, Critical):** Located in `lib-hash-helper` (Tier 3 leaf). It is a **shared dependency** reached via two distinct paths from `App-PaymentGateway` (hops 3 & 4) and one path from `App-UserPortal` (hop 4).
- **Simulated Vulnerability 2 (`SIM-VULN-002`, High):** Located in `lib-xml-codec`. It is an **isolated dependency** affecting only `App-ReportingEngine` (hop 2).

---

## 3. Directory Structure

```
DB Case Study/
├── cypher/
│   ├── schema.cypher          # Constraints and lookup indexes
│   ├── seed.cypher            # Reproducible graph seed data (14 nodes, 13 edges)
│   └── queries.cypher         # Annotated demonstration Cypher queries
├── docs/
│   └── case_study_report.md   # Official academic case study report (VIT BCSE302 format)
├── scripts/
│   ├── start.sh               # Starts/resumes the Neo4j Docker container
│   ├── stop.sh                # Safely stops the container
│   ├── seed.sh                # Applies schema and seeds data via container cypher-shell
│   ├── reset.sh               # Resets database to known baseline state
│   └── run_queries.sh         # Headless terminal query runner & table formatter
└── README.md                  # Project documentation & demonstration guide
```

---

## 4. Quick Start & Execution (Any Linux / Bash Environment)

All scripts use standard `bash` and will run on any Linux distribution (Ubuntu, Debian, Fedora, Arch, CachyOS), macOS, or WSL.

### Step 1: Start the Neo4j Database
```bash
./scripts/start.sh
```
- Starts container `neo4j-case-study` using `neo4j:5-community`.
- Binds ports `7474` (HTTP / Browser) and `7687` (Bolt).

### Step 2: Seed or Reset the Database
```bash
./scripts/reset.sh
```
- Clears existing graph nodes in this instance.
- Creates unique constraints and indexes.
- Inserts 3 Applications, 11 Packages, 13 Relationships, and 2 simulated CVE records.
- Outputs confirmation: `Applications: 3, Packages: 11, Dependencies: 13`.

### Step 3: Run the Demonstration Queries (Terminal)
```bash
./scripts/run_queries.sh
```
Executes all 6 required queries headlessly via `cypher-shell` and prints clean tabular results.

### Step 4: Stop the Database
```bash
./scripts/stop.sh
```

---

## 5. Interactive Demonstration in Neo4j Browser

1. Open your web browser and navigate to: **[http://localhost:7474](http://localhost:7474)**
2. Connect with credentials:
   - **Host:** `bolt://localhost:7687`
   - **Username:** `neo4j`
   - **Password:** `password123`
3. Enter any of the queries below in the query bar at the top of the interface:

### Query Catalog

#### Query 1: Visual Overview of Full Dependency Graph
```cypher
MATCH (n)
OPTIONAL MATCH (n)-[r:DEPENDS_ON]->(m)
RETURN n, r, m;
```
*Click on nodes to inspect properties; observe orange nodes (`Application`) pointing to blue nodes (`Package`).*

#### Query 2: Direct Dependencies of an Application
```cypher
MATCH (app:Application {name: 'App-PaymentGateway'})-[rel:DEPENDS_ON]->(pkg:Package)
RETURN app.name AS Application,
       pkg.name AS DirectPackage,
       pkg.version AS Version,
       rel.declaredIn AS DeclaredIn
ORDER BY pkg.name;
```

#### Query 3: Transitive Dependencies (Variable-Length Path Traversal)
```cypher
MATCH path = (app:Application {name: 'App-PaymentGateway'})-[:DEPENDS_ON*1..5]->(pkg:Package)
RETURN DISTINCT app.name AS Application,
       pkg.name AS Dependency,
       pkg.version AS Version,
       pkg.isVulnerable AS IsVulnerable,
       min(length(path)) AS Depth
ORDER BY Depth, pkg.name;
```

#### Query 4: Vulnerability Impact Analysis (Reverse Traversal)
```cypher
MATCH (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
RETURN DISTINCT app.name AS AffectedApplication,
       app.environment AS Environment,
       vuln.name AS VulnerablePackage,
       vuln.vulnerabilityId AS SimulatedVulnID,
       vuln.severity AS Severity
ORDER BY vuln.severity DESC, app.name ASC;
```

#### Query 5: Full Propagation Paths to Vulnerabilities
```cypher
MATCH path = (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
RETURN app.name AS Application,
       vuln.vulnerabilityId AS SimulatedVulnID,
       vuln.name AS VulnerablePackage,
       length(path) AS Depth,
       [n IN nodes(path) | n.name] AS PropagationPath
ORDER BY SimulatedVulnID, app.name, Depth;
```

#### Query 6: Blast Radius Summary
```cypher
MATCH (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
RETURN vuln.vulnerabilityId AS SimulatedVulnID,
       vuln.name AS VulnerablePackage,
       vuln.severity AS Severity,
       count(DISTINCT app) AS AffectedAppsCount,
       collect(DISTINCT app.name) AS AffectedApplications
ORDER BY AffectedAppsCount DESC;
```

#### Query 7 (Value-Add): Shortest Propagation Route
```cypher
MATCH (app:Application {name: 'App-PaymentGateway'}), (target:Package {name: 'lib-hash-helper'})
MATCH p = shortestPath((app)-[:DEPENDS_ON*1..5]->(target))
RETURN app.name AS SourceApplication,
       target.name AS TargetPackage,
       length(p) AS ShortestHops,
       [n IN nodes(p) | n.name] AS ShortestPathNodes;
```

---

## 6. Graph vs. Relational Database Summary

| Feature / Dimension | Relational Database (e.g., PostgreSQL) | Graph Database (Neo4j) |
| :--- | :--- | :--- |
| **Data Representation** | Tables with Foreign Keys and Junction Tables (`package_dependencies`) | Nodes, Labeled Edges, and Properties (Property Graph) |
| **Relationship Traversal** | Expensive index joins per hop; requires recursive CTEs (`WITH RECURSIVE`) | Direct pointer chasing (Index-free adjacency) |
| **Multi-Hop Query Syntax** | Multi-line iterative SQL with unioned base and recursive terms | Intuitive ASCII pattern: `(a)-[:DEPENDS_ON*1..5]->(b)` |
| **Schema Flexibility** | Fixed schema; schema migrations required for relationship metadata | Dynamic schema; properties attach directly to nodes or edges |
| **Best Used For** | Structured transactional ledger, financial accounting, OLTP tables | Connected networks, dependency graphs, fraud rings, access control |
