// ==============================================================================
// Database Seed Script: Software Dependency & Simulated Vulnerability Dataset
// Case Study: Graph-Based Software Dependency & Vulnerability Impact Analysis
// ==============================================================================
// NOTICE: All vulnerability identifiers (e.g., SIM-VULN-001, SIM-VULN-002)
// are explicitly SIMULATED for academic demonstration purposes only.
// They do NOT represent real-world Common Vulnerabilities and Exposures (CVEs).
// ==============================================================================

// 1. Clean existing graph data in this database
MATCH (n) DETACH DELETE n;

// 2. Create Application Nodes (3 total)
CREATE (:Application {
    name: "App-PaymentGateway",
    environment: "Production",
    criticality: "High",
    ownerTeam: "Payments-Core"
});

CREATE (:Application {
    name: "App-UserPortal",
    environment: "Production",
    criticality: "Medium",
    ownerTeam: "Frontend-Services"
});

CREATE (:Application {
    name: "App-ReportingEngine",
    environment: "Internal",
    criticality: "Low",
    ownerTeam: "Analytics-BI"
});

// 3. Create Package Nodes (11 total)
// Tier 1 Direct Packages
CREATE (:Package {
    name: "lib-auth-client",
    version: "2.1.0",
    ecosystem: "JVM",
    isVulnerable: false,
    vulnerabilityId: "NONE",
    severity: "NONE",
    simulatedData: false
});

CREATE (:Package {
    name: "lib-payment-core",
    version: "1.8.0",
    ecosystem: "JVM",
    isVulnerable: false,
    vulnerabilityId: "NONE",
    severity: "NONE",
    simulatedData: false
});

CREATE (:Package {
    name: "lib-web-utils",
    version: "3.0.1",
    ecosystem: "JVM",
    isVulnerable: false,
    vulnerabilityId: "NONE",
    severity: "NONE",
    simulatedData: false
});

CREATE (:Package {
    name: "lib-data-exporter",
    version: "1.2.0",
    ecosystem: "JVM",
    isVulnerable: false,
    vulnerabilityId: "NONE",
    severity: "NONE",
    simulatedData: false
});

// Tier 2 Intermediate Packages
CREATE (:Package {
    name: "lib-token-codec",
    version: "2.0.0",
    ecosystem: "JVM",
    isVulnerable: false,
    vulnerabilityId: "NONE",
    severity: "NONE",
    simulatedData: false
});

CREATE (:Package {
    name: "lib-crypto-base",
    version: "1.0.4",
    ecosystem: "JVM",
    isVulnerable: false,
    vulnerabilityId: "NONE",
    severity: "NONE",
    simulatedData: false
});

CREATE (:Package {
    name: "lib-string-formatter",
    version: "1.1.0",
    ecosystem: "JVM",
    isVulnerable: false,
    vulnerabilityId: "NONE",
    severity: "NONE",
    simulatedData: false
});

CREATE (:Package {
    name: "lib-csv-parser",
    version: "1.5.0",
    ecosystem: "JVM",
    isVulnerable: false,
    vulnerabilityId: "NONE",
    severity: "NONE",
    simulatedData: false
});

// Tier 3 Leaf / Deep Packages & Simulated Vulnerabilities
// Simulated Vulnerability 1: Shared deeply nested package affecting App-PaymentGateway & App-UserPortal
CREATE (:Package {
    name: "lib-hash-helper",
    version: "0.9.1",
    ecosystem: "JVM",
    isVulnerable: true,
    vulnerabilityId: "SIM-VULN-001",
    severity: "CRITICAL",
    simulatedScore: 9.8,
    simulatedDescription: "Simulated memory buffer over-read in cryptographic hashing algorithm",
    simulatedNotice: "ACADEMIC SIMULATION ONLY - NOT A REAL CVE",
    simulatedData: true
});

CREATE (:Package {
    name: "lib-text-parser",
    version: "2.4.0",
    ecosystem: "JVM",
    isVulnerable: false,
    vulnerabilityId: "NONE",
    severity: "NONE",
    simulatedData: false
});

// Simulated Vulnerability 2: Isolated package affecting only App-ReportingEngine
CREATE (:Package {
    name: "lib-xml-codec",
    version: "0.8.2",
    ecosystem: "JVM",
    isVulnerable: true,
    vulnerabilityId: "SIM-VULN-002",
    severity: "HIGH",
    simulatedScore: 7.5,
    simulatedDescription: "Simulated XML entity expansion denial-of-service vulnerability",
    simulatedNotice: "ACADEMIC SIMULATION ONLY - NOT A REAL CVE",
    simulatedData: true
});

// 4. Create Directed Dependency Relationships (13 total)
// Uses UNWIND with MATCH to guarantee edges connect the exact labeled nodes
UNWIND [
  // Direct Application -> Package dependencies
  {from: "App-PaymentGateway", to: "lib-auth-client", scope: "direct", declaredIn: "pom.xml"},
  {from: "App-PaymentGateway", to: "lib-payment-core", scope: "direct", declaredIn: "pom.xml"},
  {from: "App-UserPortal", to: "lib-auth-client", scope: "direct", declaredIn: "pom.xml"},
  {from: "App-UserPortal", to: "lib-web-utils", scope: "direct", declaredIn: "pom.xml"},
  {from: "App-ReportingEngine", to: "lib-data-exporter", scope: "direct", declaredIn: "pom.xml"},

  // Transitive Package -> Package dependencies
  // Converging chains toward shared vulnerable package lib-hash-helper
  {from: "lib-auth-client", to: "lib-token-codec", scope: "transitive", declaredIn: "transitive"},
  {from: "lib-token-codec", to: "lib-crypto-base", scope: "transitive", declaredIn: "transitive"},
  {from: "lib-payment-core", to: "lib-crypto-base", scope: "transitive", declaredIn: "transitive"},
  {from: "lib-crypto-base", to: "lib-hash-helper", scope: "transitive", declaredIn: "transitive"},

  // Web utils transitive chain
  {from: "lib-web-utils", to: "lib-string-formatter", scope: "transitive", declaredIn: "transitive"},
  {from: "lib-string-formatter", to: "lib-text-parser", scope: "transitive", declaredIn: "transitive"},

  // Reporting exporter transitive chain
  {from: "lib-data-exporter", to: "lib-csv-parser", scope: "transitive", declaredIn: "transitive"},
  {from: "lib-data-exporter", to: "lib-xml-codec", scope: "transitive", declaredIn: "transitive"}
] AS link
MATCH (source {name: link.from})
MATCH (target {name: link.to})
CREATE (source)-[:DEPENDS_ON {
    scope: link.scope,
    declaredIn: link.declaredIn
}]->(target);
