# ER Diagram Overview

This document provides a concise, tabular representation of the database schema used by **SAERA**. Each table corresponds to a Django model defined in `apps/scanner/models.py`. The columns, their Django field types, and a short description are listed to help visualize the Entity‑Relationship (ER) diagram.

---

## ScanTarget

| Column | Django Field | Type | Description |
|--------|--------------|------|-------------|
| id | AutoField (primary key) | Integer | Unique identifier |
| name | CharField(max_length=255) | String | Human‑readable name for the target |
| target | CharField(max_length=255) | String | IP address, domain, or CIDR range |
| target_type | CharField(max_length=10) | Choice | `ip`, `domain`, `range` |
| description | TextField | Text | Optional description |
| created_by_id | ForeignKey(User) | Integer | Owner of the target |
| created_at | DateTimeField(auto_now_add) | Datetime | Record creation time |
| updated_at | DateTimeField(auto_now) | Datetime | Last update time |

---

## ScanConfiguration

| Column | Django Field | Type | Description |
|--------|--------------|------|-------------|
| id | AutoField | Integer | Primary key |
| name | CharField(max_length=255) | String | Configuration name |
| scan_type | CharField(max_length=20) | Choice | `quick`, `standard`, `deep`, `custom` |
| port_range | CharField(max_length=255) | String | Ports to scan (e.g., `1-1000`)
| enable_service_detection | BooleanField | Boolean | Detect services flag |
| enable_os_detection | BooleanField | Boolean | Detect OS flag |
| enable_vuln_detection | BooleanField | Boolean | Detect vulnerabilities flag |
| timeout | IntegerField | Integer (seconds) |
| created_by_id | ForeignKey(User) | Integer |
| is_default | BooleanField | Boolean |
| created_at | DateTimeField(auto_now_add) | Datetime |

---

## ScanJob

| Column | Django Field | Type | Description |
|--------|--------------|------|-------------|
| id | AutoField | Integer |
| target_id | ForeignKey(ScanTarget) | Integer |
| configuration_id | ForeignKey(ScanConfiguration, nullable) | Integer |
| initiated_by_id | ForeignKey(User) | Integer |
| status | CharField(max_length=20) | Choice (`pending`, `running`, `completed`, `failed`, `cancelled`) |
| progress | IntegerField | Integer (0‑100) |
| current_phase | CharField(max_length=100) | String |
| total_ports_scanned | IntegerField | Integer |
| open_ports_found | IntegerField | Integer |
| vulnerabilities_found | IntegerField | Integer |
| critical_vulns | IntegerField | Integer |
| high_vulns | IntegerField | Integer |
| medium_vulns | IntegerField | Integer |
| low_vulns | IntegerField | Integer |
| aggregate_risk_score | FloatField | Float (0‑10) |
| error_message | TextField | Text |
| started_at | DateTimeField (nullable) |
| completed_at | DateTimeField (nullable) |
| created_at | DateTimeField(auto_now_add) |

---

## Vulnerability

| Column | Django Field | Type | Description |
|--------|--------------|------|-------------|
| id | AutoField | Integer |
| scan_job_id | ForeignKey(ScanJob) |
| title | CharField(max_length=500) |
| vuln_type | CharField(max_length=20) | Choice (`port`, `service`, `config`, `cve`, `protocol`, `auth`, `other`) |
| severity | CharField(max_length=20) | Choice (`critical`, `high`, `medium`, `low`, `info`) |
| cvss_score | FloatField (nullable) |
| epss_score | FloatField (nullable) |
| port | IntegerField (nullable) |
| protocol | CharField(max_length=10) |
| service | CharField(max_length=100) |
| service_version | CharField(max_length=255) |
| description | TextField |
| impact | TextField |
| recommendation | TextField |
| cve_id | CharField(max_length=50) |
| cve_url | URLField |
| risk_score | FloatField (default 0) |
| risk_level | CharField(max_length=20, default `Low`) |
| exploitability | IntegerField (default 0) |
| first_seen | DateTimeField (nullable) |
| last_seen | DateTimeField (nullable) |
| observation_count | IntegerField (default 1) |
| resolved | BooleanField (default False) |
| resolved_at | DateTimeField (nullable) |
| recurring | BooleanField (default False) |
| lifecycle_state | CharField(max_length=20) | Choice (`active`, `recurring`, `escalated`, `resolved`, `suppressed`) |
| investigation_state | CharField(max_length=20) | Choice (`open`, `observed`, `investigating`, `mitigated`, `resolved`) |
| remediation_note | TextField |
| analyst_annotation | TextField |
| priority_score | FloatField (default 0.0) |
| is_suppressed | BooleanField (default False) |
| suppressed_at | DateTimeField (nullable) |
| suppressed_reason | TextField |
| reappeared_count | IntegerField (default 0) |
| is_verified | BooleanField (default False) |
| created_at | DateTimeField(auto_now_add) |

---

## PortScanResult

| Column | Django Field | Type | Description |
|--------|--------------|------|-------------|
| id | AutoField |
| scan_job_id | ForeignKey(ScanJob) |
| port | IntegerField |
| protocol | CharField(max_length=10, default `tcp`) |
| state | CharField(max_length=20) | Choice (`open`, `closed`, `filtered`) |
| service | CharField(max_length=100) |
| service_version | CharField(max_length=255) |
| banner | TextField |
| first_seen | DateTimeField (nullable) |
| last_seen | DateTimeField (nullable) |
| observation_count | IntegerField (default 1) |
| resolved | BooleanField (default False) |
| resolved_at | DateTimeField (nullable) |
| recurring | BooleanField (default False) |
| lifecycle_state | CharField(max_length=20) | Choice (`active`, `recurring`, `resolved`, `suppressed`) |
| priority_score | FloatField (default 0.0) |
| is_suppressed | BooleanField (default False) |
| created_at | DateTimeField(auto_now_add) |

---

## ObservatoryHealthLog

| Column | Django Field | Type | Description |
|--------|--------------|------|-------------|
| id | AutoField |
| metric_name | CharField(max_length=100) |
| duration_ms | FloatField |
| status | CharField(max_length=20, default `success`) |
| message | TextField |
| created_at | DateTimeField(auto_now_add) |

---

## ScanLog

| Column | Django Field | Type | Description |
|--------|--------------|------|-------------|
| id | AutoField |
| scan_job_id | ForeignKey(ScanJob) |
| timestamp | DateTimeField(auto_now_add) |
| message | CharField(max_length=500) |

---

*The relationships (foreign keys) form the ER diagram: `ScanTarget` → `ScanJob` ← `ScanConfiguration`; `ScanJob` → `Vulnerability` and `PortScanResult`; `ScanJob` → `ScanLog`; `Vulnerability` references CVE data and includes risk intelligence fields.*
