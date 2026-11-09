# Technical Walkthrough & Demo Guide

Use this structured walkthrough to demonstrate the architecture, safety design, and capabilities of AutoOps during technical interviews or demos.

---

### Step 1: Pre-Flight Static Validation (≈45s)
```bash
python -m autoops validate
```
* **What to highlight:**
  * Demonstrates the multi-stage validator: directory structure, YAML schema, Python syntax, and safe-default policies.
  * Shows automated secret scanning (ensuring no private keys, AWS access tokens, or plaintext passwords in repositories).

---

### Step 2: Inventory Safety Check (≈30s)
```bash
python -m autoops inventory-check
```
* **What to highlight:**
  * Validates Ansible inventories across YAML and INI formats.
  * Enforces least-privilege principles by rejecting inline credentials (`ansible_password`).

---

### Step 3: Automated Test Suite (≈30s)
```bash
python -m pytest
```
* **What to highlight:**
  * Runs 66 automated unit tests validating configuration parsing, drift calculation algorithms, compliance rule evaluations, and safeguard gates.

---

### Step 4: Configuration Drift Detection (≈90s)
```bash
python -m autoops drift --previous examples/sample_previous_state.json
```
* **What to highlight:**
  * Explains the 3-way state comparison: Desired State (`config/*.yml`) vs. Current Observed State vs. Historical Snapshot.
  * Demonstrates severity scoring (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and actionable remediation commands.
  * Note on exit code: returns exit code `1` when drift is detected, making it ideal for CI/CD gating and alerting.

---

### Step 5: Continuous Security Compliance Engine (≈90s)
```bash
python -m autoops compliance
```
* **What to highlight:**
  * Shows CIS-style benchmark auditing (SSH configurations, file permissions, firewall status, insecure packages).
  * Emphasizes strict auditing logic: unverifiable sections generate warnings rather than false passes.
  * Shows exact copy-paste remediation commands for every failing check.

---

### Step 6: Infrastructure Health Reporting (≈45s)
```bash
python -m autoops report --demo
```
* **What to highlight:**
  * Shows real-time consolidation of OS facts, memory/disk utilization, critical service health, pending security updates, and compliance score.
  * Supports `--json` export (`--output reports/health.json`) for ingestion into monitoring stacks (Datadog, Prometheus, Grafana).

---

### Step 7: Architecture & Safety Discussion (≈60s)
* Open [`docs/SECURITY.md`](docs/SECURITY.md) and highlight:
  * **Zero-Lockout SSH Hardening:** Drop-in config verified with `sshd -t` prior to reload, with automated rollback.
  * **Firewall Precedence:** Guaranteed SSH rule ordering before UFW activation.
  * **Blast-Radius Mitigation:** Destructive actions require explicit confirmation tokens and dual-gate approval.
