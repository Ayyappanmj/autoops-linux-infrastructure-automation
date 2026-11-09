# AutoOps — Verification & Test Matrix

This document records the automated verification status and test coverage across platforms for AutoOps.

---

## 🧪 Test Suite & Static Analysis Results

| Test Category | Scope / Target | Status | Notes |
|---|---|---|---|
| **Python Unit Tests** | `tests/test_config.py`, `tests/test_drift.py`, `tests/test_reports.py`, `tests/test_backup_script.py` | **66 Passed, 0 Failed, 3 Skipped** | Run under `pytest` 8.3+. 3 tests skipped on Windows (POSIX-specific permissions/signals). |
| **Project Validator** | `python -m autoops validate` | **PASS** | Validated 52 required paths, 49 YAML configurations, 19 Python files, safe defaults, and secret patterns. |
| **Inventory Checker** | `python -m autoops inventory-check` | **PASS** | 3 inventory definitions parsed; zero inline plaintext passwords or invalid formats. |
| **YAML Schema Parsing** | `PyYAML` / `yamllint` | **PASS** | Strict syntax verification across all playbooks, role tasks, and desired-state definitions. |
| **Secret Scanner** | Pre-flight pattern audit | **PASS** | Checked against private keys, cloud access tokens, and unencrypted credentials. |
| **Backup Integrity Script** | `scripts/backup_config.sh` | **PASS** | Verified archive creation, SHA-256 generation, tamper detection, overwrite protection, and dry-run modes. |
| **State Snapshot Formatting** | `examples/sample_observed_state.json` | **PASS** | Verified JSON schema adherence for consumption by the drift and compliance engines. |
| **Report Generation** | CLI JSON & Text Exporters | **PASS** | Verified stdout rendering and file export (`--output`). |

---

## ⚙️ Target Environment Compatibility

| Platform | Supported Roles | Verification Mode |
|---|---|---|
| **Windows / macOS / Linux (Local)** | Python CLI (`validate`, `drift`, `compliance`, `report`, `inventory-check`), test suites | Executed natively via Python 3.11+ |
| **Ubuntu 22.04 LTS / Debian 12 (Target)** | Ansible roles (`baseline`, `users`, `ssh_hardening`, `firewall`, `packages`, `services`, `maintenance`) | Deployable via `ansible-playbook` with `--check` dry-run pre-verification |

---

## 🛡️ Production Deployment Safeguards

1. **Pre-Flight Lockout Gates:** SSH configuration drop-ins must pass `sshd -t` validation before the daemon reloads; failed validations trigger immediate rollback.
2. **Safe Default Policies:** Destructive actions (e.g. purging packages or deleting user accounts) require explicit opt-in flags (`autoops_allow_destructive=true`) and confirmation phrases.
3. **Precedence Rules:** Firewall automation guarantees SSH port availability before enabling UFW rules.
