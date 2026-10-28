# Team Presentation & Live Demo Guide (3-Person Split)

**Project Title:** Graph-Based Software Dependency and Vulnerability Impact Analysis Using Neo4j  
**Course:** BCSE302 Database Systems — Case Study 1  
**Estimated Presentation Duration:** ~7 to 9 minutes (~2.5 minutes per person) + Viva/Q&A  

---

## 1. Team Role Allocation & Rubric Mapping

This split directly covers all **5 evaluation rubrics** (2 marks each = 10 marks total):

| Presenter | Focus Area | Addressed Evaluation Rubrics | Core Talking Points |
| :--- | :--- | :--- | :--- |
| **Person 1** | **Problem Statement & Technology Overview** | **Rubric 1:** Problem Identification (2M)<br>**Rubric 2:** Understanding Modern DB (2M) | Software supply chain risks, transitive exposure, RDBMS limitations (joins/recursive CTEs), Neo4j architecture, Index-Free Adjacency, Cypher syntax. |
| **Person 2** | **Graph Design, Topology & Basic Queries** | **Rubric 3:** Database Design & Implementation (2M)<br>**Rubric 5:** Demonstration & Setup (1M) | Labeled Property Graph (LPG) design, constraints & indexes, 14-node topology, simulated CVE tagging, live setup, Queries 1 & 2. |
| **Person 3** | **Vulnerability Impact, RDBMS Contrast & Conclusion** | **Rubric 4:** Analysis of Technical Insights (2M)<br>**Rubric 5:** Documentation & Conclusion (1M) | Transitive traversal (`*1..5`), reverse impact reachability, blast radius calculation, SQL vs Cypher comparative analysis, viva defense. |

---

## 2. Pre-Demo Checklist (2 Minutes Before Presenting)

Run these two commands on the demo laptop:
```bash
# 1. Ensure the database is up
./scripts/start.sh

# 2. Reset to the clean baseline state
./scripts/reset.sh
```
- Open your browser to **[http://localhost:7474](http://localhost:7474)**.
- Connect: `bolt://localhost:7687`, User: `neo4j`, Password: `password123`.
- Have the query cheat sheet open on a side tab or phone.

---

## 3. Step-by-Step Presentation Script

```
                                  PRESENTATION FLOW (~8 MINS)
+------------------------+      +------------------------+      +------------------------+
|       PERSON 1         |      |       PERSON 2         |      |       PERSON 3         |
|  Problem & Technology  | ───> |  Schema, Graph & Demo  | ───> | Traversal, Impact, SQL |
|       (~2.5 mins)      |      |       (~2.5 mins)      |      |       (~3.0 mins)      |
+------------------------+      +------------------------+      +------------------------+
```

---

### PERSON 1: Problem Statement & Why Neo4j (~2.5 Minutes)
*(Evaluated on Rubric 1: Problem Identification & Rubric 2: Understanding of Selected Database)*

#### 🎙️ What to Say:
1. **Introduction:**
   > *"Good morning professor. Today our team is presenting our Database Systems case study on **Graph-Based Software Dependency and Vulnerability Impact Analysis Using Neo4j**."*

2. **The Real-World Problem:**
   > *"In modern software engineering, applications rarely exist in isolation. A production application depends on dozens of third-party libraries, and those libraries depend on other libraries transitively, forming complex directed dependency networks."*  
   > *"When a security flaw is discovered in an open-source component, it is rarely in a top-level library—it is usually hidden 3 or 4 layers deep. The challenge for security engineers is: How do we quickly identify which production applications are exposed, what is the exact propagation path, and what is the blast radius?"*

3. **Why Relational Databases (RDBMS) Struggle:**
   > *"If we model this in a relational database like PostgreSQL or MySQL, we have to use junction tables with foreign keys. Finding indirect dependencies requires recursive Common Table Expressions (`WITH RECURSIVE`) and repeated self-joins. At every single hop, the RDBMS must scan index B-trees, which becomes computationally heavy, syntactically complex, and difficult to maintain."*

4. **The Modern Database Solution: Neo4j & Cypher:**
   > *"To solve this, we chose **Neo4j**, a native graph database. Neo4j uses the **Labeled Property Graph** model where entities are Nodes, connections are directed Edges, and attributes are stored as Properties."*  
   > *"Most importantly, Neo4j uses **Index-Free Adjacency**—each node holds direct physical memory pointers to its neighbors. Walking a dependency path does not require searching a table index; it is a direct pointer traversal. To query it, we use **Cypher**, a declarative query language based on intuitive ASCII-art patterns like `(node)-[:DEPENDS_ON]->(neighbor)`."*  
   > *"Now, my teammate will walk you through our database design and show the live graph."*

---

### PERSON 2: Database Schema, Topology & Live Baseline (~2.5 Minutes)
*(Evaluated on Rubric 3: Database Design & Implementation & Rubric 5: Demonstration)*

#### 🖥️ Action:
Share the screen showing **Neo4j Browser** at `http://localhost:7474`.

#### 🎙️ What to Say:
1. **The Graph Data Model:**
   > *"Thank you. For this case study, we designed a minimal, deterministic property graph consisting of **14 nodes** and **13 directed relationships**:"*
   > - *"`:Application` nodes represent our production services: `App-PaymentGateway`, `App-UserPortal`, and `App-ReportingEngine`."*
   > - *"`:Package` nodes represent third-party libraries across three tiers: direct libraries, intermediate utilities, and deep leaf libraries."*
   > - *"`[:DEPENDS_ON]` edges point directly from the consumer to the dependency."*

2. **Integrity & Simulated Vulnerabilities:**
   > *"We enforced uniqueness constraints on application and package names to guarantee database integrity. We also introduced two clearly labelled **simulated vulnerability records** to test impact analysis without claiming real-world scanning:"*
   > - *"**SIM-VULN-001** (Critical, 9.8 score) is in `lib-hash-helper`, a deeply nested library shared by multiple applications."*
   > - *"**SIM-VULN-002** (High, 7.5 score) is in `lib-xml-codec`, an isolated library affecting only reporting."*

3. **Live Demonstration — Query 1: Overview of the Graph:**
   *(Copy and paste Query 1 into the Neo4j Browser and click Run)*
   ```cypher
   MATCH (n) OPTIONAL MATCH (n)-[r]->(m) RETURN n, r, m;
   ```
   > *"Here on the screen is our live dependency network. The orange nodes are Applications, and the blue nodes are Packages. You can see how dependencies branch and converge."*

4. **Live Demonstration — Query 2: Direct Dependencies:**
   *(Paste Query 2 and run)*
   ```cypher
   MATCH (app:Application {name: 'App-PaymentGateway'})-[rel:DEPENDS_ON]->(pkg:Package)
   RETURN app.name AS Application, pkg.name AS DirectPackage, pkg.version AS Version;
   ```
   > *"Query 2 finds the 1-hop direct dependencies for `App-PaymentGateway`. We see it directly declares `lib-auth-client` and `lib-payment-core`. Notice that neither of these direct libraries is vulnerable. Now, my teammate will demonstrate how graph traversal uncovers hidden downstream risks."*

---

### PERSON 3: Transitive Traversal, Vulnerability Impact & RDBMS Comparison (~3.0 Minutes)
*(Evaluated on Rubric 4: Analysis of Technical Insights & Rubric 5: Documentation & Conclusion)*

#### 🖥️ Action:
Take over the query bar in Neo4j Browser.

#### 🎙️ What to Say:
1. **Live Demonstration — Query 3: Multi-Hop Transitive Traversal:**
   *(Paste Query 3 and run)*
   ```cypher
   MATCH path = (app:Application {name: 'App-PaymentGateway'})-[:DEPENDS_ON*1..5]->(pkg:Package)
   RETURN DISTINCT app.name AS Application, pkg.name AS Dependency, pkg.isVulnerable AS IsVulnerable, min(length(path)) AS Depth
   ORDER BY Depth;
   ```
   > *"With Cypher's variable-length syntax `[:DEPENDS_ON*1..5]`, we traverse up to 5 hops deep in a single line. The query instantly reveals that while direct dependencies are safe, at depth 3 lies `lib-hash-helper`, which is marked `isVulnerable: TRUE`."*

2. **Live Demonstration — Query 4 & 5: Impact Analysis & Propagation Paths:**
   *(Paste Query 5 and run)*
   ```cypher
   MATCH path = (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
   RETURN app.name AS Application, vuln.vulnerabilityId AS SimulatedCVE, length(path) AS Depth, [n IN nodes(path) | n.name] AS Path;
   ```
   > *"This is our core technical insight: reverse reachability. By starting from vulnerable nodes and walking incoming edges backward, we identify all affected root applications."*  
   > *"Notice that `App-PaymentGateway` reaches `lib-hash-helper` through TWO separate paths: one via the payment core (3 hops), and one via the auth client (4 hops). `App-UserPortal` also reaches it through the auth client. Meanwhile, `SIM-VULN-002` only affects `App-ReportingEngine`."*

3. **Live Demonstration — Query 6: Blast Radius Summary:**
   *(Paste Query 6 and run)*
   ```cypher
   MATCH (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
   RETURN vuln.vulnerabilityId AS Vulnerability, vuln.severity AS Severity, count(DISTINCT app) AS BlastRadius, collect(DISTINCT app.name) AS ExposedApps;
   ```
   > *"This aggregates the blast radius: `SIM-VULN-001` has a blast radius of 2 critical production services, while `SIM-VULN-002` has a blast radius of 1 internal service. Security teams can instantly prioritize remediation."*

4. **Technical Comparison: Neo4j vs. PostgreSQL / MySQL:**
   > *"To conclude our technical analysis, we compared this with an RDBMS:"*
   > - *"**Query Complexity:** In SQL, doing this requires an iterative 20-line `WITH RECURSIVE` CTE with unioned base and recursive members. In Cypher, it is a declarative 2-line ASCII pattern."*
   > - *"**Architectural Trade-Off:** Relational databases remain the gold standard for tabular, transactional OLTP tasks like accounting and e-commerce checkouts. However, for deeply interconnected, network-oriented data like supply chains, fraud rings, and access control, Graph Databases eliminate join impedance mismatch and model the problem naturally."*
   > - *"Everything is reproducible locally in Docker with standard bash scripts. Thank you, and we are ready for your questions."*

---

## 4. Copy-Paste Cypher Cheat Sheet for the Laptop Operator

Keep this block ready to copy and paste into Neo4j Browser during the demo:

```cypher
// DEMO STEP 1: Full Graph View
MATCH (n) OPTIONAL MATCH (n)-[r]->(m) RETURN n, r, m;

// DEMO STEP 2: Direct Dependencies of Payment Gateway
MATCH (app:Application {name: 'App-PaymentGateway'})-[rel:DEPENDS_ON]->(pkg:Package)
RETURN app.name AS Application, pkg.name AS DirectPackage, pkg.version AS Version;

// DEMO STEP 3: Multi-Hop Transitive Traversal (Depth 1 to 5)
MATCH path = (app:Application {name: 'App-PaymentGateway'})-[:DEPENDS_ON*1..5]->(pkg:Package)
RETURN DISTINCT app.name AS Application, pkg.name AS Dependency, pkg.isVulnerable AS IsVulnerable, min(length(path)) AS Depth
ORDER BY Depth;

// DEMO STEP 4: Exact Propagation Paths to Vulnerabilities
MATCH path = (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
RETURN app.name AS Application, vuln.vulnerabilityId AS SimulatedCVE, length(path) AS Depth, [n IN nodes(path) | n.name] AS Path;

// DEMO STEP 5: Blast Radius Summary
MATCH (app:Application)-[:DEPENDS_ON*1..5]->(vuln:Package {isVulnerable: true})
RETURN vuln.vulnerabilityId AS Vulnerability, vuln.severity AS Severity, count(DISTINCT app) AS BlastRadius, collect(DISTINCT app.name) AS ExposedApps;

// BONUS: Shortest Path Algorithm
MATCH (app:Application {name: 'App-PaymentGateway'}), (target:Package {name: 'lib-hash-helper'})
MATCH p = shortestPath((app)-[:DEPENDS_ON*1..5]->(target))
RETURN app.name AS App, target.name AS Target, length(p) AS ShortestHops, [n IN nodes(p) | n.name] AS Path;
```

---

## 5. "Hot Seat" Viva Defense: Anticipated Professor Questions & Answers

### Q1: "Why use Neo4j instead of just writing a recursive SQL query in PostgreSQL?"
**Who answers:** Person 1 or Person 3  
**Answer:**  
> *"While PostgreSQL supports `WITH RECURSIVE`, recursive SQL is difficult to read, maintain, and optimize. At an architectural level, PostgreSQL must perform repeated index lookups on junction tables at every recursion depth. Neo4j utilizes **index-free adjacency**, where each node directly stores pointers to adjacent relationships in memory. Furthermore, Cypher expresses variable-depth paths natively in 2 lines (`-[:DEPENDS_ON*1..5]->`) instead of 20 lines of recursive union logic."*

---

### Q2: "What is Index-Free Adjacency? Does that mean Neo4j doesn't use indexes?"
**Who answers:** Person 1  
**Answer:**  
> *"Neo4j does use indexes, but only as **entry points** to locate the starting node (for example, finding `App-PaymentGateway` by name). Once that starting node is located, Neo4j uses **index-free adjacency** to navigate relationships: it follows direct physical memory pointers to neighbor nodes without consulting any index tables. In contrast, an RDBMS must re-query indexes at every single join hop."*

---

### Q3: "What happens if there is a circular dependency in the software packages? Will Cypher enter an infinite loop?"
**Who answers:** Person 2 or Person 3  
**Answer:**  
> *"No. In Cypher, relationship traversal follows **relationship uniqueness** semantics by default. A Cypher path will never traverse the exact same relationship edge twice within a single path expansion, naturally preventing infinite loops. In SQL `WITH RECURSIVE`, developers must manually write cycle-detection logic using arrays (`CYCLE id SET is_cycle USING path`) to prevent infinite recursion."*

---

### Q4: "Is Neo4j always better and faster than a relational database?"
**Who answers:** Person 3  
**Answer:**  
> *"No, sir/ma'am. We do not claim Neo4j is universally faster. Graph databases excel specifically when data is densely connected and queries involve deep, variable-length path traversal. For traditional enterprise workloads—such as tabular financial accounting, billing ledgers, or bulk batch updates—relational databases with rigid schemas and mature query optimizers remain significantly more suitable. Choosing the right tool depends on data topology."*

---

### Q5: "What are your ACID guarantees in Neo4j?"
**Who answers:** Person 2  
**Answer:**  
> *"Neo4j is a fully ACID-compliant database. Transactions are atomic and isolated. When our seed script runs `MATCH (n) DETACH DELETE n`, it runs within a transactional boundary ensuring consistent state. Changes are committed to a write-ahead transaction log before being flushed to store files."*
