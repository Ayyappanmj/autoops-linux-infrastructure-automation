# Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `ansible.cfg` ignored, warning "world writable directory" | Happens on `/mnt/d` in WSL. `export ANSIBLE_CONFIG=$PWD/ansible/ansible.cfg` or work in `~/autoops` |
| group_vars not applied | They must sit next to the inventory (`ansible/inventory/group_vars/`) or playbook |
| `couldn't resolve module/action 'community.general.ufw'` | `ansible-galaxy collection install -r ansible/requirements.yml` |
| `Permission denied (publickey)` | Wrong user/key path in inventory; test `ssh -i <key> user@host`; public key not in `authorized_keys` |
| `Host key verification failed` | First connect: `ssh user@host` once, or (dev only) the inventory's `accept-new` option |
| `sudo: a password is required` | Add `--ask-become-pass` or configure NOPASSWD sudo for the automation user |
| `Refusing to modify localhost` | By design. Use `--check` or a disposable VM; `-e autoops_allow_local_apply=true` only if you mean it |
| `Destructive actions need BOTH ...` | Pass both flags exactly as documented |
| `Include ... no 'Include /etc/ssh/sshd_config.d/*.conf'` | Old sshd_config: add the Include line manually while keeping a session open |
| Service tasks fail on WSL | WSL2 often lacks systemd; use a real VM |
| `mode` shows as integer / validate says "quoted" | Write modes as `"0644"` (YAML octal gotcha) |
| `python -m autoops` → `No module named autoops` | Run from the project root |
| `ModuleNotFoundError: yaml` | `pip install -r requirements.txt` in your venv |
| `error: refusing to overwrite existing file` | Add `--force` or choose a new `--output` |
| Backup: `directory already exists` | Two runs in the same second; wait and retry |
| `drift` exit code 1 on sample data | Expected: sample is deliberately drifted |
