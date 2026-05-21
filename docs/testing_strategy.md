# Testing & Validation Strategy

To ensure operational reliability and analytical accuracy, SAERA relies on a structured testing methodology spanning four distinct phases.

## 1. Unit Testing
**Focus:** Testing isolated pieces of code (functions, methods, classes) independent of the database or external services.
- **Implementation in SAERA:** 
  - Testing the logic within `apps.scanner.services.analytics_service.py`. 
  - Example: Given a mocked list of historical `Vulnerability` objects, does the `calculate_risk_drift()` function return the correct mathematical delta and percentage?
  - Unit tests ensure the fundamental deterministic math of the platform remains unbroken.

## 2. Integration Testing
**Focus:** Testing how different modules interact with each other and with the database.
- **Implementation in SAERA:**
  - **Database Integration:** Ensuring that when a `ScanJob` status updates to `completed`, the `AggregationService` successfully pulls the new data from the MySQL database and updates the `aggregate_risk_score`.
  - **Subprocess Integration:** Verifying that the `nmap_service.py` successfully executes the local Nmap binary, captures the XML stdout, and passes it to the `parser_service.py` without data loss.

## 3. System Testing
**Focus:** Testing the fully integrated application as a complete system to verify that it meets the specified requirements.
- **Implementation in SAERA:**
  - Running a complete end-to-end (E2E) flow: A user logs in, configures a new Scan Target, initiates a scan via the UI, waits for the background worker to finish, and verifies that the Dashboard drift chart updates correctly.
  - This verifies that the UI, API, Database, and Background Task queues (Celery/Async) all operate harmoniously.

## 4. Validation Testing (UAT / Academic Review)
**Focus:** Ensuring the software meets the operational and business (or academic) needs of the end-user.
- **Implementation in SAERA:**
  - Verifying the "Explainable Intelligence" requirement: Does the UI present the data in a way that is understandable to a security analyst?
  - Confirming UX constraints: Does the application adhere strictly to the "Midnight Observatory" aesthetic, avoiding unnecessary dashboard clutter?
  - **Defense Validation:** Can the architectural choices (separation of concerns, deterministic math over ML) be logically defended during an academic viva?
