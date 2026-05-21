# Database Normalization in SAERA

Normalization is a database design technique used to reduce data redundancy and improve data integrity. SAERA's MySQL database is designed adhering strictly to the **Third Normal Form (3NF)**.

## First Normal Form (1NF)
**Rule:** Each table cell should contain a single value, and each record needs to be unique.
- **Implementation:** In SAERA, there are no comma-separated lists stored in database columns. For instance, rather than storing a list of open ports as a string inside a `ScanTarget` row, each open port is stored as an individual row in the `scanner_portscanresult` table.

## Second Normal Form (2NF)
**Rule:** Must be in 1NF, and all non-key attributes must be fully functionally dependent on the primary key.
- **Implementation:** The `ScanJob` table relies on its own primary key (`id`). The target information (IP address, hostname) is not duplicated in the `ScanJob` table. Instead, `ScanJob` uses a foreign key (`target_id`) to point to the `ScanTarget` table. This prevents update anomalies; if a target's name changes, it only needs to be updated in one place.

## Third Normal Form (3NF)
**Rule:** Must be in 2NF, and there should be no transitive dependencies (non-key attributes relying on other non-key attributes).
- **Implementation:** 
  - **Scan Configurations:** Scan parameters (timeout, port range, scan type) are isolated in the `ScanConfiguration` table. A `ScanJob` simply points to a configuration ID rather than copying all those parameters into the job record.
  - **Remediation Doctrine:** Broad vulnerability knowledge is stored in the `VulnerabilityReference` table. The `Vulnerability` table (which stores active findings) does not duplicate paragraphs of remediation advice; it stores the specific instance data (port, severity, lifecycle state), while analysts can cross-reference the knowledge base for general doctrine.

## The Benefit to Telemetry Analytics
By strictly normalizing the data structure, SAERA's `AnalyticsService` can rapidly aggregate metrics (like risk drift and service concentration) using SQL `JOIN`s and `GROUP BY` clauses without encountering duplicate or conflicting data anomalies.
