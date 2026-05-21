# NetVuln System Flow

## Scan Flow

```text
User submits scan form
        |
Django validates the target
        |
ScanJob is created
        |
ScanService runs the scan directly
        |
Nmap output is parsed
        |
Open ports and findings are saved
        |
User views scan detail
```

## Why This Flow

This flow is intentionally direct. It avoids extra infrastructure and keeps the project easy to install, demonstrate, and defend.

## Important Records

- `ScanTarget`: the IP/domain/range being scanned.
- `ScanConfiguration`: the scan type and options.
- `ScanJob`: one scan execution.
- `PortScanResult`: open ports and detected services.
- `Vulnerability`: findings linked to a scan.
- `AuditLog`: important user and scan actions.