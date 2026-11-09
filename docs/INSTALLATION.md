# Installation

## A. Windows validation mode (works today, ~50 MB)

1. Install Python 3.11+ (python.org) — place the venv on **D:** (`D:\Dev\Projects\autoops\.venv`), not C:.
2. ```powershell
   cd D:\Dev\Projects\autoops
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements-dev.txt
   $env:PIP_CACHE_DIR = "D:\pip-cache"   # optional: keep pip's cache off C:
   ```
3. Run `python -m autoops validate`, `python -m pytest`, or `scripts\windows_validate.ps1`.

If PowerShell blocks scripts: `Set-ExecutionPolicy -Scope Process Bypass`.

## B. Linux execution mode

Ansible's control node must be Linux. Options, cheapest first:

1. **A separate Linux machine / spare VM** (recommended with your C: space limits).
2. **WSL2 Ubuntu** — *check space first*. A minimal Ubuntu distro needs roughly 2–5 GB and defaults to **C:**.
   ```powershell
   Get-PSDrive C | Select-Object Used, Free     # need several GB free; do NOT install if tight
   ```
   If you proceed, install WSL, then **export/import the distro to D:** so it does not live on C:
   (`wsl --export` / `wsl --import Ubuntu D:\WSL\Ubuntu <tar> --version 2`). AutoOps never installs WSL for you.
3. Disposable target: a VirtualBox/Multipass/cloud-free local Ubuntu VM that you can delete.

### Ubuntu setup

```bash
sudo apt update && sudo apt install -y python3 python3-venv python3-pip git
git clone <your-repo> ~/autoops && cd ~/autoops        # prefer ~/ over /mnt/d (see TROUBLESHOOTING)
python3 -m venv ~/.venvs/autoops && source ~/.venvs/autoops/bin/activate
pip install -r requirements-ansible.txt
ansible-galaxy collection install -r ansible/requirements.yml
export ANSIBLE_CONFIG="$PWD/ansible/ansible.cfg"
bash scripts/run_checks.sh          # runs everything available; prints SKIPPED for the rest
```

### Remote target prerequisites

SSH key access for a non-root user with passwordless or password sudo; Ubuntu 22.04/24.04; edit
`ansible/inventory/development.yml` (placeholders use the documentation range 192.0.2.0/24).
Generate a key with `ssh-keygen -t ed25519 -f ~/.ssh/autoops_dev_ed25519` and put the **public** key on the target.
