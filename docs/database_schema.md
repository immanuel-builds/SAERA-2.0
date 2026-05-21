# Database Schema and Relations (MySQL)

SAERA leverages a **MySQL** relational database (configured in `config/settings.py`) to maintain strict data integrity, foreign key constraints, and relational normalization. Django's ORM maps Python classes to these underlying MySQL tables.

## 1. Core Schema Architecture

The database is divided into three primary domains:
1. **Access Control & Auditing** (`accounts_user`, `accounts_auditlog`)
2. **Telemetry & Execution** (`scanner_scantarget`, `scanner_scanconfiguration`, `scanner_scanjob`, `scanner_scanlog`)
3. **Intelligence & Findings** (`scanner_vulnerability`, `scanner_portscanresult`, `knowledge_vulnerabilityreference`)

## 2. Table Definitions & Functions

### `accounts_user`
- **Function:** Stores authenticated analysts and administrators. Extends Django's base user model.
- **Key Fields:** `username`, `password`, `role` (Admin/Analyst), `department`.

### `accounts_auditlog`
- **Function:** An immutable ledger of system actions (logins, scan initiations) for compliance and tracking.
- **Relations:** 
  - `user_id` (Foreign Key to `accounts_user.id`)

### `scanner_scantarget`
- **Function:** Defines the operational entities (IPs, Domains) being monitored.
- **Relations:** 
  - `created_by_id` (Foreign Key to `accounts_user.id`)

### `scanner_scanconfiguration`
- **Function:** Defines the parameters of a scan (port ranges, OS detection flags).
- **Relations:**
  - `created_by_id` (Foreign Key to `accounts_user.id`)

### `scanner_scanjob`
- **Function:** The central execution record. Represents a single point-in-time assessment of a target.
- **Key Fields:** `status`, `progress`, `aggregate_risk_score`.
- **Relations:**
  - `target_id` (Foreign Key to `scanner_scantarget.id`)
  - `configuration_id` (Foreign Key to `scanner_scanconfiguration.id`)
  - `initiated_by_id` (Foreign Key to `accounts_user.id`)

### `scanner_vulnerability`
- **Function:** Stores individual security exposures discovered during a `ScanJob`. Also tracks lifecycle state (Active, Resolved, Recurring).
- **Relations:**
  - `scan_job_id` (Foreign Key to `scanner_scanjob.id`) - *CASCADE delete*

### `scanner_portscanresult`
- **Function:** Stores raw network port telemetry (Open/Closed/Filtered) per scan job.
- **Relations:**
  - `scan_job_id` (Foreign Key to `scanner_scanjob.id`)

### `knowledge_vulnerabilityreference`
- **Function:** The doctrinal archive. Provides remediation guidance independent of active scans.
- **Relations:** Standalone intelligence table.

## 3. Relational Flow

The core relational hierarchy cascades downwards:
`User` → creates → `ScanTarget` + `ScanConfiguration`
`User` → initiates → `ScanJob` (linking Target & Configuration)
`ScanJob` → generates → `Vulnerability` (1:N) & `PortScanResult` (1:N)

By utilizing MySQL's relational integrity (foreign keys and cascade deletes), SAERA ensures that if a `ScanJob` is deleted, its child vulnerabilities are automatically purged to prevent orphaned telemetry data.
