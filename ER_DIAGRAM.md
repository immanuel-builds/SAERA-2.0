# Entity‑Relationship Overview

This document provides a quick‑reference **ER diagram** in tabular form for the main Django models used by SAERA. Each table lists the model’s fields (columns), their type, and a short description. Use this to visualise relationships and understand how data is linked.

---

## `ScanTarget`
| Column | Type | Description |
|---|---|---|
| `id` | AutoField (PK) | Primary key |
| `name` | CharField(255) | Human‑readable name of the target |
| `target` | CharField(255) | IP, domain, or CIDR range |
| `target_type` | CharField(10) | `ip`, `domain`, or `range` |
| `description` | TextField | Optional free‑form description |
| `created_by_id` | FK to `auth.User` | Owner of the record |
| `created_at` | DateTimeField | Auto‑added timestamp |
| `updated_at` | DateTimeField | Auto‑updated on change |

---

## `ScanConfiguration`
| Column | Type | Description |
|---|---|---|
| `id` | AutoField (PK) | Primary key |
| `name` | CharField(255) | Configuration name |
| `scan_type` | CharField(20) | `quick`, `standard`, `deep`, `custom` |
| `port_range` | CharField(255) | Port range string, e.g. `1-1000` |
| `enable_service_detection` | BooleanField | Run service detection?
| `enable_os_detection` | BooleanField | Run OS detection?
| `enable_vuln_detection` | BooleanField | Run vulnerability detection?
| `timeout` | IntegerField | Timeout in seconds |
| `created_by_id` | FK to `auth.User` | Owner |
| `is_default` | BooleanField | Default config flag |
| `created_at` | DateTimeField | Auto‑added timestamp |

---

## `ScanJob`
| Column | Type | Description |
|---|---|---|
| `id` | AutoField (PK) | Primary key |
| `target_id` | FK to `ScanTarget` | Target being scanned |
| `configuration_id` | FK to `ScanConfiguration` (nullable) | Scan settings |
| `initiated_by_id` | FK to `auth.User` | Who started it |
| `status` | CharField(20) | `pending`, `running`, `completed`, `failed`, `cancelled` |
| `progress` | IntegerField | 0‑100 percent |
| `current_phase` | CharField(100) | Current scan phase description |
| `total_ports_scanned` | IntegerField | Summary counters |
| `open_ports_found` | IntegerField |
| `vulnerabilities_found` | IntegerField |
| `critical_vulns` | IntegerField |
| `high_vulns` | IntegerField |
| `medium_vulns` | IntegerField |
| `low_vulns` | IntegerField |
| `aggregate_risk_score` | FloatField | 0‑10 aggregated risk |
| `error_message` | TextField | Optional error output |
| `started_at` | DateTimeField (nullable) |
| `completed_at` | DateTimeField (nullable) |
| `created_at` | DateTimeField (auto) |

---

## `Vulnerability`
| Column | Type | Description |
|---|---|---|
| `id` | AutoField (PK) |
| `scan_job_id` | FK to `ScanJob` |
| `title` | CharField(500) |
| `vuln_type` | CharField(20) | `port`, `service`, `config`, `cve`, … |
| `severity` | CharField(20) | `critical`, `high`, `medium`, `low`, `info` |
| `cvss_score` | FloatField (nullable) |
| `epss_score` | FloatField (nullable) |
| `port` | IntegerField (nullable) |
| `protocol` | CharField(10) |
| `service` | CharField(100) |
| `service_version` | CharField(255) |
| `description` | TextField |
| `impact` | TextField (optional) |
| `recommendation` | TextField (optional) |
| `cve_id` | CharField(50) |
| `cve_url` | URLField (optional) |
| `risk_score` | FloatField (default 0) |
| `risk_level` | CharField(20) (default `Low`) |
| `exploitability` | IntegerField (default 0) |
| `first_seen` | DateTimeField (nullable) |
| `last_seen` | DateTimeField (nullable) |
| `observation_count` | IntegerField (default 1) |
| `resolved` | BooleanField (default False) |
| `resolved_at` | DateTimeField (nullable) |
| `recurring` | BooleanField (default False) |
| `lifecycle_state` | CharField(20) | `active`, `recurring`, `escalated`, `resolved`, `suppressed` |
| `investigation_state` | CharField(20) | `open`, `observed`, `investigating`, `mitigated`, `resolved` |
| `remediation_note` | TextField (optional) |
| `analyst_annotation` | TextField (optional) |
| `priority_score` | FloatField (default 0) |
| `is_suppressed` | BooleanField (default False) |
| `suppressed_at` | DateTimeField (nullable) |
| `suppressed_reason` | TextField (optional) |
| `reappeared_count` | IntegerField (default 0) |
| `is_verified` | BooleanField (default False) |
| `created_at` | DateTimeField (auto) |

---

## `PortScanResult`
| Column | Type | Description |
|---|---|---|
| `id` | AutoField (PK) |
| `scan_job_id` | FK to `ScanJob` |
| `port` | IntegerField |
| `protocol` | CharField(10) (default `tcp`) |
| `state` | CharField(20) | `open`, `closed`, `filtered` |
| `service` | CharField(100) (optional) |
| `service_version` | CharField(255) (optional) |
| `banner` | TextField (optional) |
| `first_seen` | DateTimeField (nullable) |
| `last_seen` | DateTimeField (nullable) |
| `observation_count` | IntegerField (default 1) |
| `resolved` | BooleanField (default False) |
| `resolved_at` | DateTimeField (nullable) |
| `recurring` | BooleanField (default False) |
| `lifecycle_state` | CharField(20) | `active`, `recurring`, `resolved`, `suppressed` |
| `priority_score` | FloatField (default 0) |
| `is_suppressed` | BooleanField (default False) |
| `created_at` | DateTimeField (auto) |

---

## `ObservatoryHealthLog`
| Column | Type | Description |
|---|---|---|
| `id` | AutoField (PK) |
| `metric_name` | CharField(100) |
| `duration_ms` | FloatField |
| `status` | CharField(20) | `success`/`failure` |
| `message` | TextField (optional) |
| `created_at` | DateTimeField (auto) |

---

## `ScanLog`
| Column | Type | Description |
|---|---|---|
| `id` | AutoField (PK) |
| `scan_job_id` | FK to `ScanJob` |
| `timestamp` | DateTimeField (auto) |
| `message` | CharField(500) |

---

**Relationships**
- `ScanJob` → `ScanTarget` (many‑to‑one)
- `ScanJob` → `ScanConfiguration` (many‑to‑one, nullable)
- `Vulnerability` → `ScanJob` (many‑to‑one)
- `PortScanResult` → `ScanJob` (many‑to‑one)
- `ScanLog` → `ScanJob` (many‑to‑one)
- `ObservatoryHealthLog` is independent telemetry collected throughout the system.

Use this table‑based view as a quick ER reference when drawing a diagram in your preferred tool (e.g., draw.io, dbdiagram.io).
