# Operations runbook

## 1. Validate (no host contact)
```bash
python -m autoops validate && python -m autoops inventory-check && python -m pytest
cd ansible && ansible-playbook -i inventory/development.yml playbooks/site.yml --syntax-check && ansible-lint
```
## 2. Preview (check mode — still connects)
```bash
ansible-playbook -i inventory/development.yml playbooks/baseline.yml --check --diff
```
Check mode can't predict everything (e.g. tasks depending on earlier changes). Treat it as a hint.

## 3. Execute (disposable target first)
```bash
ansible-playbook -i inventory/development.yml playbooks/baseline.yml
ansible-playbook -i inventory/development.yml playbooks/maintenance.yml --tags backup   # back up before security changes
# SSH/firewall opt-in: edit config/server_baseline.yml (apply_changes / manage / enable) and re-run --check first
ansible-playbook -i inventory/development.yml playbooks/security.yml --check --diff
```
Destructive: `-e autoops_allow_destructive=true -e autoops_destructive_confirm=I_UNDERSTAND_THIS_REMOVES_DATA`.

## 4. Inspect
```bash
ansible-playbook -i inventory/development.yml playbooks/compliance.yml      # read-only snapshot
python -m autoops drift      --input reports/dev-ubuntu-01/observed_state.json --previous reports/old_state.json
python -m autoops compliance --input reports/dev-ubuntu-01/observed_state.json --output reports/dev-compliance.json
python -m autoops report     --input reports/dev-ubuntu-01/observed_state.json
```
Exit codes: 0 clean, 1 findings, 2 input/usage error. Keep an old snapshot to use as `--previous`.

## 5. Roll back
* **SSH**: see SECURITY.md (remove drop-in → `sshd -t` → reload).
* **Config files**: `scripts/backup_config.sh verify <dir>`; follow `<dir>/RESTORE.txt` (manual, reviewed copy with `cp -p`).
* **Firewall**: `sudo ufw disable` (console access!) or `sudo ufw delete allow <port>/tcp`.
* **Packages/users**: no automatic rollback; re-install/recreate via the playbooks.

Back up manually: `sudo bash scripts/backup_config.sh -d /var/backups/autoops` (`-n` = dry run).
Disaster recovery is **not** claimed: only config-file backups with checksums are implemented and the script was tested; restore is manual.
