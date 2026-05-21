# SAERA Operational Telemetry Mining Architecture

This document outlines the strategy for introducing lightweight, explainable, and deterministic data mining into SAERA's telemetry pipeline, adhering strictly to the "Cyber Telemetry Analysis Platform" framing. We will avoid black-box predictive AI and instead focus on academic, observable pattern discovery.

## Proposed Architecture

We will introduce a new dedicated mining pipeline in the backend: `apps/scanner/services/mining_service.py`. This service will extract canonical intelligence objects from historical `ScanJob`, `Vulnerability`, and `PortScanResult` data, and apply deterministic mining algorithms to generate insights.

### Component Breakdown

#### 1. Recurring Exposure Mining
- **Mechanism:** Query `Vulnerability` objects across all targets where `recurring=True` or `observation_count > 1`.
- **Output:** Ranking of the most persistent vulnerabilities and protocols, persistence ratios, and their contribution to overall posture degradation.

#### 2. Protocol Concentration Mining
- **Mechanism:** Aggregate `Vulnerability` and `PortScanResult` severity contributions grouped by `protocol` and `service`.
- **Output:** Weighted contribution rankings (e.g., "SSH accounts for 40% of Critical exposure density").

#### 3. Temporal Drift & Remediation Mining
- **Mechanism:** Analyze the time delta between `first_seen` and `resolved_at` for mitigated findings across the fleet. Calculate remediation velocity.
- **Output:** Average time-to-remediate per severity, and identification of bottlenecks (e.g., "Recurring SSH exposures show 42% slower remediation velocity").

#### 4. Deterministic Association Analysis (Apriori-lite)
- **Mechanism:** Analyze co-occurrence of services and vulnerabilities on the same `ScanTarget`. If Target A has Service X, how often does it have Vulnerability Y?
- **Output:** Observable dependency patterns and configuration correlations (e.g., "Persistent FTP exposure frequently co-occurs with weak HTTP configurations").

#### 5. Exposure Clustering (Explainable K-Means)
- **Mechanism:** Implement a lightweight, pure-Python K-Means clustering algorithm (no heavy ML dependencies like scikit-learn to maintain auditability). Targets will be clustered based on vectors like: `[critical_vulns, open_ports, recurrence_rate]`.
- **Output:** Deterministic grouping of hosts into Posture Similarity Groups.

#### 6. Analytical Insight Generation
- **Mechanism:** A synthesis engine that takes the outputs of the above mining algorithms and generates structured, academic sentences.
- **Output:** Textual operational intelligence (e.g., "Persistent SMB exposure remains the dominant contributor to unresolved posture degradation.").

## API & Visualization Strategy

- **API:** We will expose these mining outputs via `apps/api/views.py` (e.g., `/api/mining/insights/`, `/api/mining/clusters/`).
- **UI Integration:** We will create a new "Intelligence Mining" view (`mining/index.html`) or integrate these insights into the existing Dashboard as a dedicated "Mining Intelligence" module, preserving the Midnight Observatory UX.

## User Review Required

> [!IMPORTANT]
> **Visualization Location:** Should the new Mining Intelligence visualizations live on a dedicated page (e.g., `/intelligence/`), or should they be integrated into the main Observatory Dashboard as a new tier?

> [!TIP]
> **Clustering Implementation:** To maintain strict academic explainability and avoid "enterprise complexity inflation", I propose writing a lightweight, transparent K-Means algorithm natively in Python rather than importing external ML libraries. Do you agree with this approach?

Once approved, I will begin implementing the `mining_service.py` architecture.
