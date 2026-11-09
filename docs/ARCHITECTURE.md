# Architecture

## Components

| Layer | Files | Role |
|---|---|---|
| Desired state | `config/*.yml` | Single source of truth, loaded by Ansible (`vars_files`) and Python |
| Safety switches | `ansible/inventory/group_vars/all.yml`, `ansible/tasks/guard.yml` | Defaults that block risky actions |
| Automation | `ansible/playbooks/*.yml`, `ansible/roles/*` | Idempotent configuration |
| Observation | `roles/compliance` → `reports/<host>/observed_state.json` | Read-only state collection |
| Analysis | `autoops/drift.py`, `compliance.py`, `report.py` | Pure Python, no Linux needed |
| Validation | `autoops/validate.py`, `inventory.py`, CI | Static checks, secret scan |
| Recovery aid | `scripts/backup_config.sh`, `roles/maintenance` | Backups with checksums |

## Data flow

1. Operator edits `config/*.yml` (modes are quoted strings, ssh values are strings).
2. `python -m autoops validate` checks structure, YAML, schema, inventory, safe defaults, secrets.
3. Ansible `--check`, then real run (opt-in switches), applies the state.
4. `playbooks/compliance.yml` collects packages, services, effective `sshd -T`, UFW status, file modes,
   users/groups into `observed_state.json` (check-mode safe: only reads).
5. `python -m autoops drift|compliance|report --input <snapshot>` evaluates it.
   `--previous <older snapshot>` adds change-over-time findings.

## Snapshot schema (observed state)

`hostname`, `demo` (bool), `system{os,cpu_model,cpu_count,memory_*,disk_percent,updates_available,reboot_required}`,
`packages[]`, `services{name:{state,enabled}}`, `files{path:{exists,mode,owner,group}}`, `groups[]`,
`users{name:{shell,groups[]}}`, `ssh{directive:value}` (case-insensitive), `firewall{status,allowed[]}`.
A **missing section** is reported as *unverified* (drift: `INCOMPLETE`; compliance: warning) — never as a pass.

## Design decisions

* **Static mode vs Linux mode**: Python analysis works anywhere; Ansible needs a Linux control node.
* **Drop-in for SSH** (`sshd_config.d/00-autoops.conf`): original file untouched, trivial rollback, first-match
  semantics make it win over later files.
* **Two gates for destructive actions**, three layers for localhost safety (guard, check-mode, flags).
* **group_vars next to inventory**: Ansible does not load `ansible/group_vars` when inventory is in a subdirectory.
* **No framework**: argparse + PyYAML only, suitable for an 8 GB laptop.
* `desired_state` (what is expected) is separate from `enable` (may automation turn it on) for the firewall.
