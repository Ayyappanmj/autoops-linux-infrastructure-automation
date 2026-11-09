# Interview questions (based on this project)

Answers describe what is actually implemented; where something is unverified it says so.

**1. What problem does AutoOps solve?**  
It codifies a Linux server baseline in YAML, applies it with Ansible, and reports whether servers still match it (drift) and which security checks fail (compliance).

**2. What is idempotence and how does the project support it?**  
Running a playbook twice leaves an already-correct system unchanged. The roles use declarative modules (`apt state=present`, `file`, `user`, `ufw`, `template`) instead of imperative shell commands, and read-only tasks explicitly define `changed_when: false` to ensure idempotent execution.

**3. Difference between `--syntax-check`, `--check` and a normal run?**  
Syntax check only parses the playbook and never connects. Check mode connects and predicts changes without making them, with limits. A normal run applies changes.

**4. Why can't Ansible run natively on Windows?**  
The control node relies on POSIX features (fork, SSH tooling). Hence Windows mode runs only Python/static validation, and Ansible runs from WSL2, a VM or another Linux machine.

**5. How are SSH lock-outs prevented?**  
Audit-only default, a drop-in file instead of editing `sshd_config`, `sshd -t -f %s` validation on the template, a full `sshd -t`, reload not restart, `wait_for_connection`, backups, and a `rescue` block that removes the drop-in. Disabling password auth needs two explicit opt-ins.

**6. Why use `sshd_config.d/00-autoops.conf`?**  
Ubuntu includes `sshd_config.d/*.conf` at the top of `sshd_config`; sshd uses the first value it sees, so a `00-` drop-in wins and rollback is deleting one file. The role verifies the Include line exists first.

**7. Why reload instead of restart sshd?**  
Reload re-reads config without killing existing sessions, so a bad-but-parseable change doesn't instantly cut your connection.

**8. How does the firewall role avoid cutting off SSH?**  
It always adds an allow rule for the connection's SSH port, asserts it's present, sets rules before defaults, and only then enables UFW if `firewall_policy.enable` is true.

**9. What are the two gates for destructive actions?**  
`autoops_allow_destructive=true` and `autoops_destructive_confirm=I_UNDERSTAND_THIS_REMOVES_DATA`. `guard.yml` aborts if only one is given; roles run removals only when both hold (`autoops_destructive_ok`).

**10. Why are safe defaults enforced by a test?**  
`check_safe_defaults()` and `validate` fail if committed group_vars enable destructive/lock-out flags, so an accidental commit is caught in CI.

**11. What is configuration drift?**  
Divergence between desired and actual state, e.g. a package removed or `PermitRootLogin yes` reappearing. `autoops drift` compares config vs observed snapshot and optionally an earlier snapshot.

**12. How does drift detection work?**  
Pure functions compare each policy section (packages, services, files, users/groups, ssh, firewall) against the snapshot and emit findings with status, resource, expected, actual, severity and remediation.

**13. What happens when a snapshot lacks a section?**  
The finding is `unknown`; drift status becomes `INCOMPLETE` and compliance checks become warnings, so missing data is never reported as healthy.

**14. How is the compliance percentage calculated?**  
`passed / total * 100`. Warnings (including `on_fail: warn` and unverifiable checks) are not passes. `COMPLIANT` requires zero failures and zero warnings.

**15. Why do the CLI commands exit with code 1 on findings?**  
So scripts and CI can gate on results: 0 clean, 1 findings, 2 usage/input errors.

**16. Why are file modes quoted in YAML?**  
YAML 1.1 parses bare `0644` as an octal integer (420). Quoted strings reach Ansible and Python intact; validation rejects unquoted modes.

**17. Where does group_vars live and why?**  
`ansible/inventory/group_vars/`. Ansible only loads group_vars adjacent to the inventory or playbook, so `ansible/group_vars/` would be ignored.

**18. How are secrets kept out of Git?**  
No secret fields in config (validated), inventory scanner rejects plaintext passwords, repo scanner flags private keys/AWS keys/forbidden filenames, `.gitignore`, and SSH key/Vault *paths* only.

**19. How would you encrypt a secret if you needed one?**  
Ansible Vault (`ansible-vault encrypt_string`), with the vault password in a file outside the repo referenced via `ANSIBLE_VAULT_PASSWORD_FILE`.

**20. How do backups work and what do they not guarantee?**  
`backup_config.sh` creates a timestamped directory, preserves modes with `cp -p`, writes SHA-256 sums and metadata, refuses to overwrite and can `verify`. It is a config-file backup, not disaster recovery; restore is manual and reviewed.

**21. How does the backup script refuse to overwrite?**  
It uses `mkdir` (without `-p`) on the final directory and aborts if it exists; the Ansible backup asserts non-existence first.

**22. Why does AutoOps never reboot servers?**  
Unplanned reboots cause outages. The packages/maintenance roles only detect `/var/run/reboot-required` and report it.

**23. What does the `guard.yml` pre-task do?**  
Validates the environment name, refuses real changes on localhost unless check mode or `autoops_allow_local_apply`, and enforces the destructive double gate.

**24. How does the Python tool relate to Ansible?**  
The `compliance` role writes `observed_state.json`; the Python CLI evaluates it. Both read the same `config/` files so they agree on the baseline.

**25. How does CI avoid falsely reporting Ansible checks as passed?**  
Python tests run on Linux and Windows; Ansible syntax-check/lint are a separate Linux-only job. `run_checks.sh` prints SKIPPED for steps it cannot run.

**26. What was verified vs not verified in this project?**  
Verified: Python code via tests, backup script, Jinja templates with mocked facts, YAML parsing. Not verified: execution of playbooks, `ansible-lint`, `--syntax-check`, GitHub Actions run, Windows run.

**27. How would you test the roles properly?**  
Molecule or a disposable VM: run `--syntax-check`, `ansible-lint`, `--check`, an actual run, then a second run asserting `changed=0` (idempotence), then the compliance playbook and `autoops compliance`.

**28. Why `ansible.builtin.service` + `community.general.ufw` rather than shell?**  
Modules are idempotent, support check mode, and avoid shell-injection and quoting problems.

**29. How would you extend it for many servers?**  
Run `compliance.yml` across the inventory (snapshots land in `reports/<host>/`), loop the CLI per host, and add a roll-up report; schedule via cron/CI.
