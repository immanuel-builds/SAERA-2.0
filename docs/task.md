# Task Tracker: SAERA Telemetry Analysis Platform Evolution

- `[x]` **Phase 0: Project Architecture Planning**
  - Define analytical framing (Telemetry Analysis Platform vs Scanner UI).
  - Define temporal, concentration, lifecycle, and comparative analytics strategy.
  - Approve architecture via `implementation_plan.md`.

- `[x]` **Phase 1: Analytical Foundation (Backend)**
  - `[x]` Review existing `AnalyticsViewSet` (`drift`, `tide`, `concentration`, `posture`).
  - `[x]` Verified API implementations are robust: `get_risk_drift`, `get_risk_tide_series`, `get_service_concentration` all implemented in `scanner/services/analytics_service.py`.
  - `[x]` Lifecycle state tracked natively on the `Vulnerability` model (`lifecycle_state` field).
  - `[x]` Comparative Analytics derived via `get_risk_drift` (new_exposures vs resolved_exposures delta).

- `[x]` **Phase 2: Dashboard Reconstruction (Frontend)**
  - `[x]` Overhaul `dashboard/index.html` hierarchy (Macro Trend -> Current Concentration -> Lifecycle Flow -> Actionable Queue).
  - `[x]` Implement "Analytical Storytelling System" in the dashboard.
  - `[x]` Integrate existing temporal/drift APIs into sleek Chart.js visualizations.

- `[x]` **Phase 3: Deep Visualization (Concentration & Lifecycle)**
  - `[x]` Design & implement Concentration Heatmap component on Node Dossier.
  - `[x]` Finalize Lifecycle Sankey or transition flows on Node Dossiers.
  - `[x]` Ensure strict restraint (No radar soup, enforce observatory calmness).

- `[x]` **Phase 4: Academic Polish & Verification**
  - `[x]` Overhaul Knowledge Base (`reference_list.html`) with parchment/ink aesthetic + live search + category filter.
  - `[x]` Overhaul Knowledge Base Detail (`reference_detail.html`) — replaced Bootstrap with full parchment dossier layout.
  - `[x]` Updated `knowledge/views.py` to pass `severity_counts` for sidebar analytics.
  - `[x]` Create `walkthrough.md` to summarize all implementations.
