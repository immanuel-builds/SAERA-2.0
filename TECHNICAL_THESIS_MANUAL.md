# Technical Thesis Manual: SAERA

This document serves as the formal academic thesis breakdown for SAERA (System for Analytical Exposure Recognition & Assessment).

## 1. Abstract
Modern cybersecurity tooling frequently overwhelms analysts with raw telemetry, relying heavily on black-box artificial intelligence or cluttered dashboard matrices. SAERA proposes a return to **Analytical Systems Engineering**, demonstrating that network reconnaissance data can be transformed into actionable operational intelligence using strictly explainable, deterministic mathematics and constrained user interface design.

## 2. Problem Statement
Commercial network scanners generate immense volumes of raw data (ports, IPs, CVSS scores) but provide minimal *context*. When a scan completes, the analyst must manually compare it to the previous scan to determine if the network's posture has degraded or improved. This reliance on human memory and external spreadsheets creates operational friction and analytical fatigue.

## 3. The Proposed Solution (SAERA)
SAERA solves this by introducing a **Telemetry Analysis Platform** that wraps the raw scanning process. 

### Key Innovations:
- **Temporal Drift Analysis:** Rather than just showing the current state, SAERA calculates the mathematical delta between chronological scan events. This reveals the "Remediation Velocity" (how fast exposures are patched) and the "Exposure Yield" (how many new risks emerged).
- **Lifecycle Tracking:** Vulnerabilities are assigned stateful tags (`Active`, `Recurring`, `Resolved`). The `Recurring` tag is mathematically critical, as it identifies persistent configuration failures that resist remediation.
- **Service Concentration Mapping:** By aggregating all open ports and assigning severity weights, SAERA visually maps where risk is clustered.
- **Defensible Risk Formula:** SAERA abandons arbitrary "magic numbers" in favor of industry standards. The base formula relies on `CVSS * (1 + EPSS)`, capped at 10.0. CVSS (Common Vulnerability Scoring System) dictates static severity, while EPSS (Exploit Prediction Scoring System) provides a real-world probability multiplier representing the likelihood of active exploitation within 30 days. This creates a transparent, intelligence-driven prioritization metric.

## 4. Methodology & Implementation
The system is built on the Django framework using a modular 4-layer architecture (Acquisition → Parser → Analytics → Presentation). 

- **Database Engine:** MySQL (adhering to 3NF normalization) ensures relational integrity.
- **Analytics Engine:** Custom Python services compute risk drift and concentration matrices using standard statistical math, explicitly avoiding neural networks to preserve absolute system explainability.
- **Execution Engine:** The system executes scans synchronously within the request thread to keep the architecture simple and deterministic for academic demonstration.
- **Frontend Design:** The UX adheres to the "Midnight Observatory" philosophy, prioritizing high-contrast, low-noise typography and color palettes to reduce cognitive load.

## 5. Conclusion
SAERA successfully demonstrates that the value of cybersecurity tooling lies not merely in the *collection* of data, but in the rigorous, explainable, and visually restrained *analysis* of that telemetry over time. By elevating data from a raw log into an intelligence dossier, it fundamentally alters the analyst's workflow from reactive investigation to proactive operational management.
