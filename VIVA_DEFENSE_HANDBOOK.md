# SAERA Viva Defense Handbook (Q&A)

This handbook provides direct answers to anticipated technical and architectural questions that may arise during the academic evaluation (viva) of SAERA.

### Q1: What database are you using, and why?
**A:** SAERA utilizes a MySQL relational database. A relational model was chosen because cybersecurity telemetry is highly structured and relational by nature (A ScanJob *has many* Vulnerabilities). By enforcing Third Normal Form (3NF) and Foreign Key cascade constraints, the database ensures we do not have orphaned telemetry data if an old scan is deleted.

### Q2: How does the "Temporal Drift Analysis" work?
**A:** The Analytics Service queries the database for the current `ScanJob`'s aggregate risk score, and then queries the database for the immediate chronological predecessor for that same `ScanTarget`. It then calculates the mathematical delta between the two scores, identifying not just the net change, but the exact count of *newly emerged* vulnerabilities versus *resolved* vulnerabilities. 

### Q3: Why is the dashboard so text-heavy and chart-light?
**A:** To reduce cognitive load. The dashboard follows a strict 3-tier hierarchy (Macro Trend → Current State → Actionable Priority). Every visual element exists to answer exactly one operational question. A barrage of radar charts and pie charts obfuscates meaning; a single, clear text synthesis (the Analytical Storytelling system) often conveys threat posture faster than a graph.

### Q4: How do you handle background tasks and long-running scans?
**A:** We deliberately chose synchronous execution to keep the project self-contained and demonstrable on any machine without Redis or Celery. The code is structured so that moving to async would be trivial – just move the scan call into a Celery task and configure a broker. But for academic evaluation, we prioritized simplicity and reliability.

### Q5: What is the purpose of the Knowledge Base?
**A:** It functions as the doctrinal archive. In traditional workflows, remediation advice is hopelessly mixed with live alerts, creating massive data bloat. By decoupling the remediation intelligence into a standalone Knowledge Base, analysts can consult the doctrine independent of any active scan, and we save massive amounts of database storage space by not duplicating remediation paragraphs into every single vulnerability row.
