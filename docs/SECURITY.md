# Security

## Threat model (what AutoOps defends against / introduces)

| Risk | Mitigation |
|---|---|
| Admin locks self out via SSH change | audit-only default; drop-in validated by `sshd -t -f`; full `sshd -t`; **reload** not restart; `wait_for_connection`; automatic rollback in `rescue`; `PasswordAuthentication no` needs `allow_password_auth_disable: true` **and** `-e autoops_key_access_verified=true`; `PubkeyAuthentication` and `Port` can't be weakened/changed |
| Lock-out via firewall | SSH port always allowed first; rules before enable; enable/disable are separate opt-ins |
| Accidental destructive change | removals need `autoops_allow_destructive=true` **and** `autoops_destructive_confirm=I_UNDERSTAND_THIS_REMOVES_DATA`; mismatch aborts the play |
| Damaging the operator's own computer | real runs against `localhost` refused unless `--check` or `autoops_allow_local_apply=true` |
| Secrets in Git | no password/key fields in config (validated); inventory scanner rejects `ansible_password` etc.; repo scanner flags key blocks/AWS keys/forbidden files; `.gitignore`; Vault/key *paths* only |
| Unwanted reboot | never implemented; only reported |
| Secret leakage in logs | `redact()` on CLI errors; no secrets handled |
| Over-trusting a report | unknown ≠ pass; `COMPLIANT` requires every check to pass; demo data is labelled |

## Secrets management

Use SSH keys (paths only in inventory), Ansible Vault for any secret (`--vault-password-file`), a `.env` that
is git-ignored. Public keys go in `ansible/files/public_keys/` (git-ignored by default).

## Least privilege

Connect as an unprivileged user with sudo; avoid `ansible_user: root` (the inventory check warns). Restrict sudo
to what you need; run compliance (read-only) separately from change playbooks.

## SSH and firewall precautions

Keep a second SSH session open. Test with `--check --diff` first. Prefer a console-accessible VM. Rollback:
`sudo rm /etc/ssh/sshd_config.d/00-autoops.conf && sudo sshd -t && sudo systemctl reload ssh`; originals are in
`/var/backups/autoops/ssh/` (`sshd_config.original` is never overwritten).

## Known limitations

Not a full CIS/DISA-STIG formal audit certification; focused on host configuration rather than intrusion detection; snapshot trust depends on the collection run; currently optimized for Ubuntu/Debian with UFW. Dry-run (`--check --diff`) is strongly recommended prior to initial production deployment.
