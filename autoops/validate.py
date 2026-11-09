"""Static project validation. Works on Windows; never executes Ansible."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .config import load_config, validate_config
from .inventory import check_inventory_dir
from .safeguards import check_safe_defaults
from .util import AutoOpsError

REQUIRED_PATHS = [
    "ansible/ansible.cfg", "ansible/inventory/localhost.yml", "ansible/inventory/development.yml",
    "ansible/inventory/example.ini", "ansible/inventory/group_vars/all.yml", "ansible/requirements.yml",
    "ansible/playbooks/site.yml", "ansible/playbooks/baseline.yml", "ansible/playbooks/users.yml",
    "ansible/playbooks/security.yml", "ansible/playbooks/packages.yml", "ansible/playbooks/services.yml",
    "ansible/playbooks/maintenance.yml", "ansible/playbooks/compliance.yml", "ansible/tasks/guard.yml",
    "scripts/validate_project.py", "scripts/check_drift.py", "scripts/generate_report.py",
    "scripts/backup_config.sh", "scripts/run_checks.sh",
    "config/server_baseline.yml", "config/users.yml", "config/packages.yml", "config/services.yml",
    "config/compliance_rules.yml",
    "examples/sample_inventory.yml", "examples/sample_drift_report.json", "examples/sample_compliance_report.json",
    "docs/ARCHITECTURE.md", "docs/INSTALLATION.md", "docs/SECURITY.md", "docs/OPERATIONS_RUNBOOK.md",
    "docs/TROUBLESHOOTING.md", "docs/INTERVIEW_QUESTIONS.md",
    ".github/workflows/ansible-validation.yml", "requirements.txt", "requirements-dev.txt", "Makefile",
    ".gitignore", ".env.example", "README.md", "DEMO.md", "BUILD_STATUS.md", "LICENSE",
]
ROLES = ["baseline", "users", "packages", "ssh_hardening", "firewall", "services", "maintenance", "compliance"]
SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", "node_modules", ".ansible"}
SECRET_PATTERNS = [
    (re.compile(r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"), "private key block"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "AWS access key id"),
    (re.compile(r"(?im)^\s*(?:ansible_(?:ssh_|become_)?pass(?:word)?)\s*[:=]\s*['\"]?(?!\{\{|changeme|<)\S+"),
     "plaintext Ansible password"),
]
FORBIDDEN_FILES = {".env", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}


@dataclass
class Check:
    name: str
    status: str  # pass | fail | warn
    detail: str = ""


def _files(root: Path, patterns: tuple[str, ...]):
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in patterns and not (set(path.relative_to(root).parts) & SKIP_DIRS):
            yield path


def check_structure(root: Path) -> Check:
    missing = [p for p in REQUIRED_PATHS if not (root / p).exists()]
    missing += [f"ansible/roles/{r}/tasks/main.yml" for r in ROLES if not (root / "ansible/roles" / r / "tasks/main.yml").exists()]
    return Check("project structure", "fail" if missing else "pass",
                 f"missing: {', '.join(missing)}" if missing else f"{len(REQUIRED_PATHS) + len(ROLES)} required paths present")


def check_yaml(root: Path) -> Check:
    bad, count = [], 0
    for path in _files(root, (".yml", ".yaml")):
        count += 1
        try:
            list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
        except yaml.YAMLError as exc:
            bad.append(f"{path.relative_to(root)}: {str(exc).splitlines()[0]}")
    return Check("YAML syntax", "fail" if bad else "pass", "; ".join(bad) if bad else f"{count} files parsed")


def check_python(root: Path) -> Check:
    bad, count = [], 0
    for path in _files(root, (".py",)):
        count += 1
        try:
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
        except SyntaxError as exc:
            bad.append(f"{path.relative_to(root)}:{exc.lineno}: {exc.msg}")
    return Check("Python syntax", "fail" if bad else "pass", "; ".join(bad) if bad else f"{count} files compiled")


def check_config(root: Path) -> Check:
    try:
        res = validate_config(load_config(root / "config"))
    except AutoOpsError as exc:
        return Check("configuration schema", "fail", str(exc))
    if res.errors:
        return Check("configuration schema", "fail", "; ".join(res.errors))
    return Check("configuration schema", "warn" if res.warnings else "pass",
                 "; ".join(res.warnings) if res.warnings else "all config files valid")


def check_playbooks(root: Path) -> Check:
    """Structural sanity only (NOT a substitute for ansible-playbook --syntax-check)."""
    problems = []
    pb_dir = root / "ansible/playbooks"
    for pb in sorted(pb_dir.glob("*.yml")) if pb_dir.is_dir() else []:
        try:
            plays: Any = yaml.safe_load(pb.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue  # reported by the YAML check
        if not isinstance(plays, list) or not plays:
            problems.append(f"{pb.name}: must be a non-empty list of plays")
            continue
        for play in plays:
            imp = play.get("import_playbook") or play.get("ansible.builtin.import_playbook")
            if imp:
                if not (pb.parent / imp).is_file():
                    problems.append(f"{pb.name}: imports missing {imp}")
                continue
            if "hosts" not in play:
                problems.append(f"{pb.name}: play without 'hosts'")
            for vf in play.get("vars_files", []):
                if not (pb.parent / vf).is_file():
                    problems.append(f"{pb.name}: vars_files not found: {vf}")
            for role in play.get("roles", []):
                rname = role if isinstance(role, str) else role.get("role")
                if not (root / "ansible/roles" / str(rname)).is_dir():
                    problems.append(f"{pb.name}: unknown role {rname}")
    for task_file in (root / "ansible/roles").glob("*/tasks/*.yml"):
        try:
            tasks = yaml.safe_load(task_file.read_text(encoding="utf-8")) or []
        except yaml.YAMLError:
            continue
        for task in tasks if isinstance(tasks, list) else []:
            if isinstance(task, dict) and "name" not in task:
                problems.append(f"{task_file.relative_to(root)}: task without a name")
    return Check("playbook/role structure", "fail" if problems else "pass",
                 "; ".join(problems) if problems else "plays, roles, vars_files and task names consistent")


def check_safe_default_flags(root: Path) -> Check:
    try:
        problems = check_safe_defaults(root / "ansible/inventory/group_vars/all.yml")
    except AutoOpsError as exc:
        return Check("safe defaults", "fail", str(exc))
    return Check("safe defaults", "fail" if problems else "pass",
                 "; ".join(problems) if problems else "destructive/lockout-prone flags default to false")


def check_inventory(root: Path) -> Check:
    try:
        rep = check_inventory_dir(root / "ansible/inventory")
    except AutoOpsError as exc:
        return Check("inventory", "fail", str(exc))
    if rep.errors:
        return Check("inventory", "fail", "; ".join(rep.errors))
    return Check("inventory", "warn" if rep.warnings else "pass",
                 "; ".join(rep.warnings) if rep.warnings else f"{rep.host_count} host entries across {len(rep.files)} files")


def check_secrets(root: Path) -> Check:
    hits = []
    for path in root.rglob("*"):
        rel = path.relative_to(root)
        if not path.is_file() or set(rel.parts) & SKIP_DIRS:
            continue
        if path.name in FORBIDDEN_FILES or path.suffix in (".pem", ".key", ".pfx"):
            hits.append(f"{rel}: forbidden secret-bearing file")
            continue
        if path.stat().st_size > 1_000_000 or path.suffix in (".zip", ".png", ".jpg"):
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(text):
                hits.append(f"{rel}: {label}")
    return Check("secret scan", "fail" if hits else "pass", "; ".join(hits) if hits else "no secret patterns found")


def validate_project(root: str | Path) -> list[Check]:
    root = Path(root)
    structure = check_structure(root)
    checks = [structure, check_yaml(root), check_python(root)]
    if structure.status == "pass":
        checks += [check_config(root), check_inventory(root), check_playbooks(root),
                   check_safe_default_flags(root)]
    checks.append(check_secrets(root))
    return checks
