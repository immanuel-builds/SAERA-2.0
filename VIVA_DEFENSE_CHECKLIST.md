# 🎓 SAERA Live Viva Defense Checklist

This is your battle-tested script to flawlessly demonstrate SAERA's capabilities during your thesis defense. **Show, don't tell.**

---

## 🛑 Pre-Flight Check (Do this *before* screen sharing)
- [ ] Ensure the Django server is running (`python manage.py runserver`).
- [ ] Run the command: `python manage.py seed_demo` to generate the exact scenario described below.
- [ ] Clear your browser cache or open an Incognito window to avoid old session conflicts.

---

## ⏱️ Live Demo Walkthrough (5-7 Minutes)

### 1. The Entrance: Authentication & Narrative
* **Action:** Go to `http://localhost:8000/accounts/login/`
* **Credentials:** `Immanuel` / `Observatory2026!`
* **Script:** *"I'm authenticating as an administrator to demonstrate the full lifecycle capabilities of the platform."*

### 2. The Command Center: Dashboard Overview
* **Action:** You are now on the root Dashboard (`/`). Point out the main widgets.
* **Point out:**
  1. The **Operational Storytelling** banner at the top (synthesis).
  2. The **Actionable Priority Queue** (demonstrating how `CVSS * (1 + EPSS)` bubbles the most dangerous vectors to the top).
  3. The **Lifecycle Pipeline** counter (Active, Recurring, Escalated, Resolved).
* **Script:** *"Instead of presenting a wall of data, SAERA uses an analytical storytelling banner to summarize the entire network posture. Notice the 'Recurring' counter in the lifecycle widget — these are critical process failures where a patch was applied, but the vulnerability later returned."*

### 3. The Evidence: Target Drift Analysis
* **Action:** Click **"Internal Active Directory Server"** from the Exposure Concentration Matrix or the Priority Queue.
* **Point out:** Look at the top three metrics (Target Posture Index, Exposure Yield, Remediation Velocity). Point to the "Risk Drift" metric showing a percentage increase/decrease.
* **Script:** *"Here we see chronological intelligence in action. SAERA isn't just showing what's broken right now; it calculates the 'drift' between the last scan and the current one. This target's risk degraded significantly over the last few sweeps — giving us quantifiable remediation velocity."*

### 4. The Action: Analyst Controls (Live State Change)
* **Action:** Scroll down to the **"Exposure Telemetry"** section and expand a Vulnerability card by clicking **"Analyst Controls"**.
* **Live Interactions (Do these slowly):**
  1. **Change State:** Change dropdown to "Investigating" and click Update. *"Analysts can transition state without page reloads, tracking workflow."*
  2. **Annotate:** Type a note like *"Patching window scheduled for Saturday"* and Update. *"Notes are persisted directly to the operational log."*
  3. **Suppress:** Check 'Suppress Finding', type *"Accepted risk in sandbox environment"* and Update. *"If this is a false positive, we suppress it. It immediately drops out of the priority queue and risk aggregations."*

### 5. The "Aha!" Moment: Recurring Intelligence
* **Action:** Navigate to the **Network Map** (`/network-map/`). Find the node colored amber/orange representing a **Recurring** state (This will be the SMBv1 vulnerability).
* **Script:** *"This is the power of the temporal engine. This SMB vulnerability was patched in scan #3, but reappeared in scan #4. SAERA detected the historical match and automatically escalated it to 'Recurring'. Without this lifecycle tracking, an analyst would just treat it as a new ticket, completely missing the fact that the underlying patch process failed."*

### 6. The Developer Backdoor: Admin Access
* **Action:** Navigate to the admin backdoor at `/accounts/backdoor/`.
* **Point out:** The user roles table and stuck-scan override buttons.
* **Script:** *"This is the administrative control panel. Here we can enforce role-based access control and clear any aborted scan jobs. Every action taken on this page is logged immutably."*

### 7. The Ledger: Audit Trails
* **Action:** Navigate to the **Admin Console** (`/accounts/admin-console/`) and scroll to the **Field Journal**.
* **Script:** *"To satisfy strict compliance requirements, SAERA logs every significant action — from logins to scan initiations to state suppressions — in this immutable Field Journal."*

---

## 🛡️ Q&A Defense Strategy

**Q: Why didn't you use Celery for background scanning?**
> *"We designed the system to run synchronously to ensure it remains a self-contained, deterministic academic demonstration that can run on any evaluator's machine without requiring Redis or complex broker setups. The decoupled architecture ensures that moving to an asynchronous task queue in the future is a trivial implementation detail, not an architectural rewrite."*

**Q: How do you justify your Risk Score?**
> *"We abandoned arbitrary 'magic numbers'. The engine utilizes a defensible formula: `CVSS × (1 + EPSS)`, capped at 10.0. CVSS dictates the static severity of the flaw, while EPSS provides the real-time probability of it being exploited in the wild. This ensures our prioritization is rooted in transparent, industry-standard threat intelligence."*

**Q: How does the system know a vulnerability is recurring?**
> *"During the persistence phase of a new scan, the `TemporalService` queries historical scan jobs for the same target, port, and CVE. If it finds a previous instance that was marked 'Resolved', it automatically flags the new finding as 'Recurring' and increments the `observation_count`. It's deterministic state-machine logic."*
