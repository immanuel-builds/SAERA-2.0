# System Modules 

SAERA is built using the Django framework, structurally divided into distinct, decoupled applications (modules). This separation of concerns ensures maintainability and logical code organization.

## 1. Scanner Module (`apps.scanner`)
The core operational engine of the system.
- **Responsibilities:** Manages targets, configurations, and initiates asynchronous scan jobs via Celery.
- **Sub-components:**
  - `services/nmap_service.py`: Interfaces with the system's Nmap binary via subprocess.
  - `services/parser_service.py`: Translates raw XML output into canonical database objects (`Vulnerability`, `PortScanResult`).
  - `services/analytics_service.py`: The math engine. Calculates temporal risk drift, severity distribution, and service concentration.
  - `services/aggregation_service.py`: Synthesizes raw data and analytics into "Dossiers" for frontend consumption.

## 2. Dashboard Module (`apps.dashboard`)
The presentation layer for macroscopic intelligence.
- **Responsibilities:** Renders the 3-tier analytical hierarchy (Macro Trend → Current State → Actionable Priority).
- **Sub-components:** Consumes data from the aggregation service to build Chart.js temporal drift graphs and lifecycle flow counters.

## 3. Knowledge Base Module (`apps.knowledge`)
The doctrinal reference library.
- **Responsibilities:** Houses remediation instructions, CVSS breakdowns, and best practices.
- **Sub-components:** Fully searchable archive that allows analysts to contextualize vulnerabilities without muddying the active telemetry data.

## 4. Accounts & Access Module (`apps.accounts`)
The security perimeter.
- **Responsibilities:** Manages user authentication, role-based access control (RBAC), and session timeouts.
- **Sub-components:** Maintains the `AuditLog` to provide an immutable ledger of system logins, logouts, and scan initiations.

## 5. API Module (`apps.api`)
The machine-to-machine interface.
- **Responsibilities:** Exposes SAERA's telemetry and analytics via a RESTful JSON API using Django Rest Framework (DRF).
- **Sub-components:** Allows for potential future integration with external SIEMs or headless CI/CD pipelines.
