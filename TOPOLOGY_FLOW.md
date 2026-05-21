# Data Topology & Operational Flow

This document maps the journey of raw telemetry as it enters SAERA, is normalized, analyzed, and finally rendered as operational intelligence.

## 1. Target Acquisition & Inception
1. An Analyst submits a target IP or domain via the `/scanner/targets/new` view.
2. The `ScanTarget` object is instantiated in MySQL.
3. The Analyst configures and initiates a `ScanJob`. 
4. The system delegates the execution instruction to the ScanService which runs synchronously.

## 2. Raw Telemetry Generation
1. The `nmap_service.py` executes the underlying Nmap binary via a subprocess shell.
2. Network packets are routed to the physical target.
3. The binary returns raw, unstructured XML data (`stdout`) detailing open ports, services, and script findings.

## 3. The Parsing Pipeline (Normalization)
1. The XML string is piped into `parser_service.py`.
2. The parser iterates through the nodes and ports.
3. Data is broken down into normalized canonical objects:
   - Port findings become `PortScanResult` rows.
   - Script/CVE findings become `Vulnerability` rows.
4. *Lifecycle Interrogation:* The system queries historical `ScanJob` data for this target. If a vulnerability was previously seen, closed, and is now seen again, it is tagged as `recurring=True`. Otherwise, it is tagged `active`.

## 4. The Analytics Pipeline
Once the parsing is complete and the database is updated, the `temporal_service.py` and `analytics_service.py` engage:
1. **Drift Calculation:** The `aggregate_risk_score` for the current scan is calculated. It is then compared against the previous scan's score to generate a delta percentage (Drift).
2. **Concentration:** All `PortScanResult` protocols are grouped and counted to build the Service Concentration matrix.

## 5. Synthesis & Visualization
1. The Analyst requests the Dashboard view (`/`).
2. The `aggregation_service.py` constructs an `IntelligenceDossier` object in memory, containing the drift math, the tide timeline, and the concentration arrays.
3. The Django template engine renders the HTML page.
4. Client-side Javascript (Chart.js) reads the JSON data embedded in the template and paints the Risk Evolution trend line.
5. The final result is a calm, coherent Operational Observatory dashboard.
