# SAERA RESTful API Reference

SAERA exposes a comprehensive RESTful JSON API, allowing external systems (SIEMs, automated testing pipelines) to interact directly with the telemetry acquisition and analysis engines. The API is built using Django Rest Framework (DRF) and is secured via Session/Token authentication.

## Base URL
All API requests are routed through `/api/v1/`.

## Endpoints

### 1. Analytics & Intelligence (`/api/v1/analytics/`)
The core endpoint for retrieving operational intelligence.
- `GET /api/v1/analytics/{target_id}/drift/`
  - **Returns:** Risk drift calculations, comparing the most recent scan against its immediate historical predecessor. Outputs percentage drift, new exposure yield, and remediation counts.
- `GET /api/v1/analytics/{target_id}/tide/`
  - **Returns:** A chronological time-series array of historical aggregate risk scores, utilized for rendering the Risk Evolution chart.
- `GET /api/v1/analytics/{target_id}/concentration/`
  - **Returns:** A service concentration matrix, mapping protocol frequency and severity density.

### 2. Targets (`/api/v1/targets/`)
- `GET /api/v1/targets/` - List all configured scan targets (IPs, domains).
- `POST /api/v1/targets/` - Register a new network target.
- `GET /api/v1/targets/{id}/` - Retrieve detailed target configuration.

### 3. Scan Jobs (`/api/v1/scans/`)
- `GET /api/v1/scans/` - View the ledger of all executed or running scan jobs.
- `POST /api/v1/scans/` - Initiate a new scan job directly within the request thread.
- `GET /api/v1/scans/{id}/` - Retrieve the status (e.g., `running`, `completed`) and progress of a specific scan job.

### 4. Vulnerability Ledger (`/api/v1/vulnerabilities/`)
- `GET /api/v1/vulnerabilities/` - Retrieve all detected exposures across the fleet.
- `PATCH /api/v1/vulnerabilities/{id}/` - Update the lifecycle state of a specific exposure (e.g., transition from `active` to `suppressed`).

## Authentication
By default, the API utilizes `SessionAuthentication`, meaning requests made from the authenticated browser context are inherently trusted. For external scripting, a Django DRF Token must be passed via the HTTP Authorization header:
`Authorization: Token <your_token>`

## Schema Documentation
Interactive Swagger and ReDoc documentation is dynamically generated:
- **Swagger UI:** `/api/schema/swagger-ui/`
- **ReDoc:** `/api/schema/redoc/`
