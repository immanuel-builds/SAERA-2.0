# Authentication & Error Handling

SAERA leverages Django's robust built-in authentication framework (`django.contrib.auth`), heavily extended to support role-based access control, strict session management, and comprehensive audit logging.

## 1. Authentication Mechanisms

### Custom User Model
SAERA does not use the default Django user. It implements a custom `User` model (extending `AbstractUser`) to natively support operational roles and departmental separation:
- **Roles:** `admin` (Administrator) and `analyst` (Security Analyst).
- **Properties:** Role checks are handled via `@property` methods (`is_admin`, `is_analyst`) to enforce access boundaries seamlessly across templates and views.

### Session Management
To protect operational telemetry, strict session constraints are enforced in `config/settings.py`:
- **Session Timeout:** Sessions automatically expire after 30 minutes of inactivity (`SESSION_COOKIE_AGE = 30 * 60`).
- **Sliding Sessions:** Activity on the platform resets the 30-minute clock (`SESSION_SAVE_EVERY_REQUEST = True`).
- **Security Flags:** In production, sessions rely on `SESSION_COOKIE_SECURE = True` and `CSRF_COOKIE_SECURE = True` to prevent interception over unencrypted networks.

### Password Security
Passwords are never stored in plaintext. They are hashed using PBKDF2 with a SHA256 hash. The system enforces strict password rules out-of-the-box:
- Minimum length validation.
- Rejection of common passwords (dictionary prevention).
- Rejection of entirely numeric passwords.
- User attribute similarity checks (preventing passwords like the username).

## 2. Authorization (Role-Based Access Control)

Access to specific views and actions is strictly guarded:
- **`@login_required`:** Decorates all operational views. Unauthenticated users are immediately redirected to the login page.
- **API Access:** The `apps.api` module enforces `IsAuthenticated` permissions by default, utilizing `SessionAuthentication` for browser clients.
- **Capability Flags:** The custom user model includes a `can_initiate_scans` boolean, allowing administrators to restrict junior analysts to read-only views without demoting their role.

## 3. Error Handling (Authentication & General)

### Login Failures
- When a user enters incorrect credentials, the Django authentication form throws an `AuthenticationForm` validation error.
- **Feedback:** The UI immediately displays a constrained, generic error message (e.g., "Please enter a correct username and password."). 
- **Security Posture:** Generic errors prevent username enumeration (it does not specify whether the username or the password was incorrect).

### Permission Denied (403 Forbidden)
- If an authenticated analyst attempts to access an administrator-only route, the system raises a `PermissionDenied` exception, serving a standard HTTP 403 response rather than failing silently or causing a 500 server error.

### Auditing & Logging Failures
- The `AuditLog` model acts as the definitive ledger for authentication and error events.
- It records `user_login`, `user_logout`, and most importantly, `security_event` (which captures validation failures or unauthorized access attempts).
- Every log captures the `ip_address` and `user_agent`, ensuring that repeated authentication failures can be traced back to their origin.
