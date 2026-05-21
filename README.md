# SAERA — System for Analytical Exposure Recognition & Assessment

SAERA is an advanced **Cyber Telemetry Analysis and Operational Intelligence Visualization Platform**. Built as an academic demonstration of analytical systems engineering, SAERA moves beyond traditional vulnerability scanning to provide temporal risk drift analysis, service concentration mapping, and deterministic intelligence generation.

## Core Capabilities

1. **Temporal Drift Analysis**
   SAERA calculates risk degradation or improvement over time. It compares chronological scan intervals to determine if a target's security posture is improving (Remediation Velocity) or deteriorating (Exposure Yield).

2. **Service Concentration Mapping**
   By aggregating telemetry across the operational fleet, SAERA identifies protocol density (e.g., heavy SSH or HTTP concentrations) and correlates them to critical vulnerabilities.

3. **Lifecycle Tracking & Intelligence**
   Exposures are not static. SAERA tracks vulnerabilities through an operational ledger, categorizing them as:
   - **Active:** Newly discovered and unresolved.
   - **Recurring:** Previously resolved, but discovered open again.
   - **Mitigated/Resolved:** Successfully closed.

4. **"Midnight Observatory" Interface**
   SAERA rejects the chaotic "cyberpunk dashboard" aesthetic in favor of a calm, scholarly, parchment-and-ink dossier layout. Every visualization acts as a deliberate decision-support instrument.

## Technical Architecture

SAERA operates on a strictly decoupled 4-layer architecture, relying on deterministic mathematics rather than black-box AI:
- **Scanner Layer:** Executes and parses network telemetry (via subprocess Nmap integration).
- **Analytics Service:** Calculates risk formulas, drift percentages, and protocol matrices.
- **Aggregation Service:** Synthesizes raw data and analytics into coherent "Dossiers".
- **Presentation Layer:** A responsive web interface powered by Django templates and Chart.js.

## Reference Documentation

Extensive documentation is provided to support academic evaluation and Viva defense. The project root contains the following definitive manuals:
- `ARCHITECTURE.md` — Deep dive into the 4-layer system design.
- `TOPOLOGY_FLOW.md` — Explains how data moves from target acquisition to dashboard rendering.
- `API_REFERENCE.md` — Details the RESTful JSON API endpoints.
- `TECHNICAL_THESIS_MANUAL.md` — Comprehensive academic breakdown of the platform.
- `VIVA_DEFENSE_HANDBOOK.md` — Anticipated examiner questions and strategic positioning.

Additionally, fine-grained technical documents (Database Schema, Normalization, Validation, etc.) can be found in the `docs/` directory.

## Installation & Setup
1. Clone the repository and navigate into the directory.
2. Initialize a Python virtual environment: `python -m venv venv`
3. Activate the environment: `venv\Scripts\activate` (Windows)
4. Install dependencies: `pip install -r requirements.txt`
5. Ensure MySQL is running and configured according to `config/settings.py` (Default: `netvuln_db`, user: `root`, no password).
6. Run migrations: `python manage.py migrate`
7. Start the server: `python manage.py runserver`

*Built for academic demonstration of cyber telemetry intelligence architecture.*