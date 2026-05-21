# Architectural Design of SAERA

SAERA is engineered as a monolithic web application structured around a strictly decoupled **4-Layer Architecture**. This separation of concerns ensures that raw telemetry parsing is entirely divorced from mathematical analysis and user presentation, ensuring academic explainability and high maintainability.

## The 4-Layer System

### Layer 1: The Scanner (Acquisition) Layer
**App:** `apps.scanner.services.scan_service.py`
- **Responsibility:** Data acquisition. This layer wraps external binary execution (e.g., Nmap via subprocess), capturing raw XML `stdout`. 
- **Constraint:** It performs *no analysis*. It merely triggers the scan, waits for the result, and hands the raw string off to the parser.

### Layer 2: The Parser & Persistence Layer
**App:** `apps.scanner.services.parser_service.py` & Django ORM
- **Responsibility:** Normalization. It consumes the raw XML, identifies nodes, ports, and CVEs, and translates them into canonical database objects (`Vulnerability` and `PortScanResult`).
- **Constraint:** Data is stored adhering strictly to the Third Normal Form (3NF) in the MySQL database. No analytics are derived here.

### Layer 3: The Analytics (Intelligence) Layer
**App:** `apps.scanner.services.analytics_service.py`
- **Responsibility:** The mathematical engine. It queries the normalized MySQL tables and applies deterministic formulas to generate intelligence.
- **Operations:**
  - `get_risk_drift()`: Compares current state vs. historical state.
  - `get_risk_tide_series()`: Generates temporal timelines.
  - `get_service_concentration()`: Maps protocol and severity density matrices.
- **Constraint:** Uses purely deterministic logic; avoids black-box ML/AI to ensure absolute audibility and academic defensibility.

### Layer 4: The Aggregation & Presentation Layer
**App:** `apps.dashboard` & `apps.scanner.services.aggregation_service.py`
- **Responsibility:** Narrative synthesis. The aggregation service consumes the output of the Analytics layer and compiles it into a "Dossier" object. The Django view passes this object to the template engine (`index.html`, `scan_detail.html`).
- **Constraint:** The frontend logic contains *no* math or database queries. It simply renders the pre-compiled Dossier using the "Midnight Observatory" visual constraints (Parchment & Ink aesthetic, Chart.js integrations).

To ensure reliability and simplicity, SAERA executes `ScanJob` tasks synchronously within the Django request thread. The architecture supports async workers (like Celery) as a future enhancement.
