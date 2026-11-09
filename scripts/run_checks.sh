#!/usr/bin/env bash
# Run every validation that this environment supports. Skipped steps are reported as SKIPPED,
# never as passed. Usage: scripts/run_checks.sh
set -uo pipefail
cd "$(dirname "$0")/.."
export ANSIBLE_CONFIG="$PWD/ansible/ansible.cfg"   # ignored otherwise on world-writable dirs (e.g. /mnt/d in WSL)
PY="${PYTHON:-python3}"
fail=0
step() { printf '\n== %s ==\n' "$1"; }
run() { "$@" || { echo "FAILED: $*"; fail=1; }; }

step "Project validation (static)"; run "$PY" -m autoops validate
step "Inventory check (static)";    run "$PY" -m autoops inventory-check
step "Unit tests"
if "$PY" -c "import pytest" 2>/dev/null; then run "$PY" -m pytest -q; else echo "SKIPPED: pytest not installed (pip install -r requirements-dev.txt)"; fi

step "yamllint"
if command -v yamllint >/dev/null; then run yamllint -c .yamllint .; else echo "SKIPPED: yamllint not installed"; fi

step "Ansible syntax check"
if command -v ansible-playbook >/dev/null; then
  for pb in ansible/playbooks/*.yml; do run ansible-playbook -i ansible/inventory/localhost.yml --syntax-check "$pb"; done
else echo "SKIPPED: ansible-playbook not installed (Linux/WSL only; see docs/INSTALLATION.md)"; fi

step "ansible-lint"
if command -v ansible-lint >/dev/null; then (cd ansible && run ansible-lint); else echo "SKIPPED: ansible-lint not installed"; fi

echo; [[ $fail -eq 0 ]] && echo "Result: no failures among executed steps (see SKIPPED lines above)" || echo "Result: FAILURES detected"
exit $fail
