# Data Validation in SAERA

Data validation ensures that only safe, properly formatted, and expected data enters the system. SAERA utilizes Django's multi-layered validation architecture to defend against injection attacks, data corruption, and malformed inputs.

## 1. Client-Side Validation (Frontend)
- **HTML5 Attributes:** Input fields utilize `required`, `type="url"`, `type="email"`, and `pattern` attributes to prevent invalid data submission at the browser level.
- **Immediate Feedback:** Prevents unnecessary network requests by stopping the user from submitting a form (e.g., Target IP) if the format is fundamentally broken.

## 2. Server-Side Form Validation (Django Forms/Serializers)
Even if a user bypasses client-side checks, the server enforces strict validation rules.
- **Scan Targets:** The system validates that a target is either a valid IP address, a valid domain name, or a valid CIDR block. If an analyst enters `192.168.1.999`, the Django forms API raises a `ValidationError`.
- **API Serializers:** The `apps.api` module utilizes Django Rest Framework (DRF) serializers, which automatically validate incoming JSON payloads against strict typing rules (e.g., ensuring `port` is an integer between 1 and 65535).

## 3. Database-Level Validation (Models)
The final line of defense exists at the ORM/Database layer.
- **Field Constraints:** `max_length`, `unique=True`, and `choices` (e.g., `SEVERITY_CHOICES`) are enforced. If application logic attempts to save a severity of `"extreme"` when the choices are `["critical", "high", "medium", "low", "info"]`, the database transaction is rejected.
- **Referential Integrity:** Foreign Key constraints ensure that a `ScanJob` cannot reference a non-existent `ScanTarget`.

## 4. Operational Validation
- **Scan Configuration Safety:** Before passing parameters to the Nmap subprocess, the system validates the `port_range` string. It must conform to expected numeric or range structures (e.g., `80,443` or `1-1000`) to prevent command injection via the subprocess shell.
