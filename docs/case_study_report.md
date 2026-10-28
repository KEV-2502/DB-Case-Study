# Case Study Report: Graph-Based Software Dependency and Vulnerability Impact Analysis Using Neo4j

**Course:** BCSE302 Database Systems  
**Evaluation Component:** Case Study 1 – Exploring Modern Database Technologies  
**Institution:** School of Computer Science Engineering and Information Systems, Vellore Institute of Technology (VIT)  
**Academic Year:** 2026–2027  

---

## 1. Title
**Graph-Based Software Dependency and Vulnerability Impact Analysis Using Neo4j**

---

## 2. Problem Statement

Modern software architectures rely extensively on open-source ecosystems and multi-tiered software packages. A single production application commonly declares dozens of direct dependencies, each of which brings in its own transitive dependencies, resulting in complex, multi-tiered dependency Directed Acyclic Graphs (DAGs).

When a security vulnerability is identified in an upstream open-source package (such as a remote code execution or cryptographic flaw), security and engineering teams encounter critical data-management challenges:
1. **Hidden Transitive Exposure:** A vulnerable package is rarely an application's direct dependency; it often resides three or four tiers deep in the dependency tree.
2. **Blast Radius Identification:** Identifying every upstream application that directly or indirectly consumes the compromised package requires navigating relationships in reverse.
3. **Impedance Mismatch in Relational Systems:** Conventional Relational Database Management Systems (RDBMS) store entities in normalized tables and represent relationships through foreign keys and join tables. Querying multi-hop, variable-depth transitive relationships in SQL requires iterative self-joins or recursive Common Table Expressions (`WITH RECURSIVE`). As dependency chains deepen, recursive joins become syntactically complex, difficult to maintain, and computationally intensive because they rely on repetitive index lookups rather than direct relationship traversals.

A data management technology is required that treats dependency relationships as first-class citizens, allows variable-length path traversal using concise declarative queries, and models topological software supply chains naturally.

---

## 3. Objective

The primary objectives of this database case study are:
1. **Study and Apply a Modern Database Technology:** Explore the graph database paradigm implemented in Neo4j Community Edition and understand its underlying Labeled Property Graph (LPG) model.
2. **Design and Implement a Graph Database Schema:** Model software applications and packages as graph nodes, and directed dependency linkages as graph edges with property metadata.
3. **Simulate a Realistic Dependency Topology:** Construct a deterministic, 14-node dependency graph containing direct, transitive, converging (shared), and deep dependency chains.
4. **Demonstrate Vulnerability Impact Analysis:** Implement Cypher queries to calculate direct dependencies, transitive closures, reverse reachability (identifying exposed applications from a vulnerable leaf), and blast radius metrics using clearly labelled simulated vulnerability metadata.
5. **Critically Compare Graph and Relational Paradigms:** Conduct a conceptual, structural, and query-level comparison between Neo4j and conventional relational databases (such as PostgreSQL) without unverified performance claims.

---

## 4. Selected Technology

### Neo4j Graph Database (Community Edition 5.x)
Neo4j was selected as the modern database technology for this case study due to its native graph architecture and declarative query language:

- **Native Graph Storage and Processing:** Unlike relational databases that reconstruct relationships at query time via table joins, Neo4j implements **index-free adjacency**. Each node maintains direct physical pointers to its adjacent relationships and neighbor nodes in storage, allowing traversals to navigate edges without querying global index tables.
- **Labeled Property Graph (LPG) Model:**
  - **Nodes:** Represent discrete domain entities (e.g., `:Application`, `:Package`).
  - **Labels:** Group nodes into categories, acting as semantic tags and indexing boundaries.
  - **Relationships:** Directed, typed connections between nodes (e.g., `[:DEPENDS_ON]`). Relationships always possess a start node and an end node.
  - **Properties:** Key-value pairs attached directly to nodes or relationships (e.g., `version`, `isVulnerable`, `severity`).
- **Cypher Query Language:** An expressive, declarative graph query language utilizing visual ASCII-art pattern matching (e.g., `(app)-[:DEPENDS_ON*1..5]->(pkg)`) to define traversal paths.
- **Neo4j Browser:** A built-in web-based interactive interface (`http://localhost:7474`) providing real-time visual graph rendering, interactive node exploration, and query execution.

---

## 5. Proposed Solution

### 5.1 Architecture & Deployment
The prototype is deployed locally using Docker (`neo4j:5-community`) on Linux, managed via standard portable Bash shell scripts. The container isolates the Neo4j instance from host-level Java runtime mismatches (the host runs OpenJDK 26, whereas Neo4j 5.x requires OpenJDK 21), ensuring zero host system pollution and predictable reproducibility across team environments.

```
+-----------------------------------------------------------------------+
|                            User Interface                             |
|       Neo4j Browser (http://localhost:7474) / cypher-shell CLI        |
+-----------------------------------------------------------------------+
                                   | (Bolt / HTTP)
                                   v
+-----------------------------------------------------------------------+
|                   Docker: neo4j:5-community                           |
|  +-----------------------------------------------------------------+  |
|  |                    Cypher Execution Engine                      |  |
|  +-----------------------------------------------------------------+  |
|  |                 Labeled Property Graph (LPG)                    |  |
|  |   Nodes: :Application (3), :Package (11)                        |  |
|  |   Edges: :DEPENDS_ON (13)                                       |  |
|  |   Simulated CVEs: SIM-VULN-001 (Critical), SIM-VULN-002 (High)  |  |
|  +-----------------------------------------------------------------+  |
+-----------------------------------------------------------------------+
```

### 5.2 Database Design & Schema
Constraints and lookup indexes were defined using Cypher:

```cypher
// Uniqueness constraints
CREATE CONSTRAINT application_name_unique IF NOT EXISTS
FOR (a:Application) REQUIRE a.name IS UNIQUE;

CREATE CONSTRAINT package_name_unique IF NOT EXISTS
FOR (p:Package) REQUIRE p.name IS UNIQUE;

// Property indexes
CREATE INDEX package_vulnerability_index IF NOT EXISTS
FOR (p:Package) ON (p.isVulnerable);

CREATE INDEX package_vuln_id_index IF NOT EXISTS
FOR (p:Package) ON (p.vulnerabilityId);
```

### 5.3 Graph Topology & Sample Dataset
The dataset consists of **14 nodes** (3 Applications, 11 Packages) and **13 directed relationships**:

```
[App-PaymentGateway] ──> [lib-auth-client]  ──> [lib-token-codec] ──> [lib-crypto-base] ──> [lib-hash-helper]
        │                                                                   ^                  (SIM-VULN-001)
        └──> [lib-payment-core] ────────────────────────────────────────────┘                    CRITICAL
                                                                                                (Shared Leaf)
[App-UserPortal]      ──> [lib-auth-client] (Shared Direct)
        │
        └──> [lib-web-utils] ──> [lib-string-formatter] ──> [lib-text-parser]

[App-ReportingEngine] ──> [lib-data-exporter] ──> [lib-csv-parser]
                                   │
                                   └──> [lib-xml-codec] (SIM-VULN-002, HIGH, Isolated Leaf)
```

#### Simulated Vulnerability Metadata (Clearly Labelled):
1. **`SIM-VULN-001` (CRITICAL, Score 9.8):**
   - Package: `lib-hash-helper` (v0.9.1)
   - Nature: Shared, deeply nested leaf dependency.
   - Simulation Notice: *ACADEMIC SIMULATION ONLY - NOT A REAL CVE.*
2. **`SIM-VULN-002` (HIGH, Score 7.5):**
   - Package: `lib-xml-codec` (v0.8.2)
   - Nature: Isolated leaf dependency.
   - Simulation Notice: *ACADEMIC SIMULATION ONLY - NOT A REAL CVE.*

---

### 5.4 Representative Cypher Queries & Verified Results

#### Query 1: Direct Dependencies of `App-PaymentGateway`
*Demonstrates 1-hop traversal from consumer to direct dependencies.*
```cypher
MATCH (app:Application {name: 'App-PaymentGateway'})-[rel:DEPENDS_ON]->(pkg:Package)
RETURN app.name AS Application, pkg.name AS DirectPackage, pkg.version AS Version, rel.declaredIn AS DeclaredIn
ORDER BY pkg.name;
```
**Observed Result:**
| Application | DirectPackage | Version | DeclaredIn |
| :--- | :--- | :--- | :--- |
| `App-PaymentGateway` | `lib-auth-client` | `2.1.0` | `pom.xml` |
| `App-PaymentGateway` | `lib-payment-core` | `1.8.0` | `pom.xml` |

---

#### Query 2: Transitive Dependency Traversal (Multi-Hop)
*Demonstrates variable-length traversal (`[:DEPENDS_ON*1..5]`) discovering all downstream dependencies.*
```cypher
MATCH path = (app:Application {name: 'App-PaymentGateway'})-[:DEPENDS_ON*1..5]->(pkg:Package)
RETURN DISTINCT app.name AS Application, pkg.name AS Dependency, pkg.version AS Version, pkg.isVulnerable AS IsVulnerable, min(length(path)) AS Depth
ORDER BY Depth, pkg.name;
```
**Observed Result:**
| Application | Dependency | Version | IsVulnerable | Depth |
| :--- | :--- | :--- | :--- | :--- |
| `App-PaymentGateway` | `lib-auth-client` | `2.1.0` | `FALSE` | `1` |
| `App-PaymentGateway` | `lib-payment-core` | `1.8.0` | `FALSE` | `1` |
| `App-PaymentGateway` | `lib-crypto-base` | `1.0.4` | `FALSE` | `2` |
| `App-PaymentGateway` | `lib-token-codec` | `2.0.0` | `FALSE` | `2` |
| `App-PaymentGateway` | `lib-hash-helper` | `0.9.1` | `TRUE` | `3` |

---

#### Query 3: Reverse Vulnerability Impact Analysis
*Traverses backwards along incoming dependency paths from flagged vulnerable nodes to root applications.*
```cypher
MATCH (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
RETURN DISTINCT app.name AS AffectedApplication, app.environment AS Environment, vuln.name AS VulnerablePackage, vuln.vulnerabilityId AS SimulatedVulnID, vuln.severity AS Severity
ORDER BY vuln.severity DESC, app.name ASC;
```
**Observed Result:**
| AffectedApplication | Environment | VulnerablePackage | SimulatedVulnID | Severity |
| :--- | :--- | :--- | :--- | :--- |
| `App-PaymentGateway` | `Production` | `lib-hash-helper` | `SIM-VULN-001` | `CRITICAL` |
| `App-UserPortal` | `Production` | `lib-hash-helper` | `SIM-VULN-001` | `CRITICAL` |
| `App-ReportingEngine` | `Internal` | `lib-xml-codec` | `SIM-VULN-002` | `HIGH` |

---

#### Query 4: Full Propagation Paths to Vulnerabilities
*Extracts the complete chain of intermediate libraries conveying the vulnerability.*
```cypher
MATCH path = (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
RETURN app.name AS Application, vuln.vulnerabilityId AS SimulatedVulnID, vuln.name AS VulnerablePackage, length(path) AS Depth, [n IN nodes(path) | n.name] AS PropagationPath
ORDER BY SimulatedVulnID, app.name, Depth;
```
**Observed Result:**
| Application | SimulatedVulnID | VulnerablePackage | Depth | PropagationPath |
| :--- | :--- | :--- | :--- | :--- |
| `App-PaymentGateway` | `SIM-VULN-001` | `lib-hash-helper` | `3` | `["App-PaymentGateway", "lib-payment-core", "lib-crypto-base", "lib-hash-helper"]` |
| `App-PaymentGateway` | `SIM-VULN-001` | `lib-hash-helper` | `4` | `["App-PaymentGateway", "lib-auth-client", "lib-token-codec", "lib-crypto-base", "lib-hash-helper"]` |
| `App-UserPortal` | `SIM-VULN-001` | `lib-hash-helper` | `4` | `["App-UserPortal", "lib-auth-client", "lib-token-codec", "lib-crypto-base", "lib-hash-helper"]` |
| `App-ReportingEngine` | `SIM-VULN-002` | `lib-xml-codec` | `2` | `["App-ReportingEngine", "lib-data-exporter", "lib-xml-codec"]` |

---

#### Query 5: Blast Radius Summary
*Aggregates vulnerability exposure across the entire organization.*
```cypher
MATCH (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
RETURN vuln.vulnerabilityId AS SimulatedVulnID, vuln.name AS VulnerablePackage, vuln.severity AS Severity, count(DISTINCT app) AS AffectedAppsCount, collect(DISTINCT app.name) AS AffectedApplications
ORDER BY AffectedAppsCount DESC;
```
**Observed Result:**
| SimulatedVulnID | VulnerablePackage | Severity | AffectedAppsCount | AffectedApplications |
| :--- | :--- | :--- | :--- | :--- |
| `SIM-VULN-001` | `lib-hash-helper` | `CRITICAL` | `2` | `["App-PaymentGateway", "App-UserPortal"]` |
| `SIM-VULN-002` | `lib-xml-codec` | `HIGH` | `1` | `["App-ReportingEngine"]` |

---

#### Query 6: Shortest Path to Vulnerability
*Uses Neo4j's native path-finding engine to determine the most immediate propagation vector.*
```cypher
MATCH (app:Application {name: 'App-PaymentGateway'}), (target:Package {name: 'lib-hash-helper'})
MATCH p = shortestPath((app)-[:DEPENDS_ON*1..5]->(target))
RETURN app.name AS SourceApplication, target.name AS TargetPackage, length(p) AS ShortestHops, [n IN nodes(p) | n.name] AS ShortestPathNodes;
```
**Observed Result:**
`ShortestHops = 3`, Path: `["App-PaymentGateway", "lib-payment-core", "lib-crypto-base", "lib-hash-helper"]`.

---

## 6. Advantages and Limitations: Comparative Analysis

A comprehensive comparison between the Graph Database (Neo4j) and a conventional Relational Database (e.g., PostgreSQL):

### 6.1 Data Modeling and Representation
- **Relational Model (PostgreSQL):**
  Entities are decomposed into relational tables: `applications`, `packages`, and a junction table `package_dependencies (consumer_id, dependency_id, scope)`. Self-referencing many-to-many relationships are normalized.
- **Graph Model (Neo4j):**
  Entities are discrete nodes (`:Application`, `:Package`), and dependencies are explicitly directed labeled edges (`[:DEPENDS_ON]`). The graph model matches the domain whiteboard model directly, eliminating normalization friction.

### 6.2 Relationship Traversal and Query Structure
To retrieve transitive dependencies in SQL, a developer must formulate a recursive Common Table Expression (`WITH RECURSIVE`):

```sql
-- Relational Query (PostgreSQL WITH RECURSIVE)
WITH RECURSIVE dependency_tree AS (
    -- Anchor member: direct dependencies
    SELECT app.name AS application_name, p.id AS package_id, p.name AS package_name, 1 AS depth
    FROM applications app
    JOIN app_dependencies ad ON app.id = ad.application_id
    JOIN packages p ON ad.package_id = p.id
    WHERE app.name = 'App-PaymentGateway'

    UNION ALL

    -- Recursive member: transitive dependencies
    SELECT dt.application_name, p.id, p.name, dt.depth + 1
    FROM dependency_tree dt
    JOIN package_dependencies pd ON dt.package_id = pd.consumer_package_id
    JOIN packages p ON pd.dependency_package_id = p.id
    WHERE dt.depth < 5
)
SELECT DISTINCT application_name, package_name, min(depth)
FROM dependency_tree
GROUP BY application_name, package_name;
```

**Cypher Equivalent:**
```cypher
MATCH (app:Application {name: 'App-PaymentGateway'})-[:DEPENDS_ON*1..5]->(pkg:Package)
RETURN DISTINCT app.name, pkg.name, min(length(path));
```

**Technical Insight:**
The Cypher query replaces ~20 lines of SQL recursive union logic with a 2-line declarative pattern. In Neo4j, path traversal is expressed as an ASCII pattern `()-[]->()`, significantly reducing query complexity and human error.

### 6.3 Algorithmic Traversal Mechanism
- **Relational Databases:** Execute multi-hop traversal by repeatedly scanning foreign key indexes or performing hash joins between intermediate relation sets on each recursive iteration.
- **Graph Databases:** Use **index-free adjacency**, where nodes hold direct memory/disk pointer references to adjacent edge records. Traversal time is proportional to the size of the subgraph traversed rather than the total size of the global database tables.
*(Note: Whether index-free adjacency translates to faster clock execution depends on dataset size, cache residency, hardware, and query design. We do not assert that Neo4j is universally faster without formal microbenchmarks, but emphasize its structural and declarative suitability for variable-length path traversal).*

### 6.4 Advantages of Neo4j for This Case Study
1. **Natural Domain Mapping:** Directed dependency graphs and supply chains naturally form network structures; representing them as nodes and edges avoids relational artificialities.
2. **Concise Transitive Traversal:** Variable-length syntax (`*1..5`) eliminates nested joins and recursive union boilerplate.
3. **Flexible Schema:** Node and relationship properties can evolve (e.g., adding CVSS scores, remediation deadlines) without schema migrations or table locks.
4. **Built-in Visual Feedback:** The Neo4j Browser enables immediate visual validation of network topologies during architecture and security reviews.

### 6.5 Limitations of Neo4j
1. **Unsuited for Tabular Accounting / OLTP:** For traditional tabular workloads (e.g., balance ledgers, bulk batch processing, invoice generation) requiring strict rigid schemas, relational databases remain superior.
2. **Memory Requirements:** Native graph engines rely heavily on keeping the active traversal working set (graph cache / page cache) in RAM.
3. **Ecosystem & Tooling Maturity:** Relational SQL engines benefit from decades of mature tooling, universal ORMs, and standardized SQL dialects, whereas Cypher tooling is more specialized.

### 6.6 Recommended Use Cases
- **Choose Neo4j When:** Data is highly interconnected (e.g., dependency analysis, identity and access management hierarchies, fraud rings, social graphs, network topology routing) and queries frequently involve variable-depth traversals.
- **Choose Relational (PostgreSQL) When:** Data is tabular, uniform, and relational depth is shallow or fixed (e.g., e-commerce orders, payroll systems, accounting books).

---

## 7. Conclusion

This case study successfully demonstrated the applicability of graph database technology to the software dependency and vulnerability impact problem. Using Neo4j Community Edition and Cypher, a concise, 14-node property graph was constructed that faithfully captured direct and transitive dependency relationships across three tiers.

The prototype verified that:
1. Deeply nested dependencies (up to 4 hops) can be discovered and traversed with minimal declarative syntax.
2. Reverse reachability queries accurately identify all upstream applications exposed to simulated vulnerabilities, correctly identifying the shared blast radius of `SIM-VULN-001` (affecting two services) versus the isolated blast radius of `SIM-VULN-002` (affecting one service).
3. Graph databases provide an elegant, expressive alternative to recursive SQL queries when modeling networked data structures.

The solution satisfies all criteria of the BCSE302 Case Study guidelines by delivering a clean, reproducible, and verifiable database prototype without unnecessary software engineering overhead.

---

## 8. References

1. **Neo4j Cypher Query Language Manual (v5.x):**  
   *Patterns and Variable-Length Pattern Matching.*  
   URL: [https://neo4j.com/docs/cypher-manual/current/patterns/reference/#variable-length-patterns](https://neo4j.com/docs/cypher-manual/current/patterns/reference/#variable-length-patterns)

2. **Neo4j Graph Database Concepts Documentation:**  
   *The Labeled Property Graph Model and Index-Free Adjacency.*  
   URL: [https://neo4j.com/docs/getting-started/appendix/graph-database-concepts/](https://neo4j.com/docs/getting-started/appendix/graph-database-concepts/)

3. **Neo4j Operations Manual (Docker Deployment):**  
   *Deploying Neo4j Community Containers.*  
   URL: [https://neo4j.com/docs/operations-manual/current/docker/](https://neo4j.com/docs/operations-manual/current/docker/)

4. **PostgreSQL 16 Documentation:**  
   *Chapter 7. Queries – 7.8. WITH Queries (Common Table Expressions) and Recursive Queries.*  
   URL: [https://www.postgresql.org/docs/current/queries-with.html](https://www.postgresql.org/docs/current/queries-with.html)

5. **Robinson, I., Webber, J., & Eifrem, E.** (2015).  
   *Graph Databases: New Opportunities for Connected Data (2nd ed.).* O'Reilly Media. ISBN: 978-1-491-93089-2.
