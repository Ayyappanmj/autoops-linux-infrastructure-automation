"""Static checks for Ansible inventories (no Ansible required)."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import load_yaml
from .util import InputError

FORBIDDEN_KEYS = {
    "ansible_password", "ansible_ssh_pass", "ansible_become_pass", "ansible_become_password",
    "ansible_ssh_private_key", "ansible_private_key",
}
_INI_FORBIDDEN = re.compile(r"\b(" + "|".join(sorted(FORBIDDEN_KEYS)) + r")\s*=", re.I)
_KEY_CONTENT = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")


@dataclass
class InventoryReport:
    files: dict[str, list[str]] = field(default_factory=dict)  # file -> hosts
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors

    @property
    def host_count(self) -> int:
        return sum(len(h) for h in self.files.values())


def _walk(group: dict, name: str, inherited: dict, out: dict[str, dict]) -> None:
    gvars = {**inherited, **(group.get("vars") or {})}
    for host, hvars in (group.get("hosts") or {}).items():
        out[host] = {**gvars, **(hvars or {})}
    for child, cdef in (group.get("children") or {}).items():
        _walk(cdef or {}, child, gvars, out)


def parse_yaml_inventory(doc: Any) -> dict[str, dict]:
    """Return {host: effective vars}."""
    if not isinstance(doc, dict) or "all" not in doc or not isinstance(doc["all"], dict):
        raise InputError("inventory must be a mapping with a top-level 'all' group")
    hosts: dict[str, dict] = {}
    _walk(doc["all"], "all", {}, hosts)
    return hosts


def check_inventory_dir(inv_dir: str | Path) -> InventoryReport:
    inv = Path(inv_dir)
    if not inv.is_dir():
        raise InputError(f"inventory directory not found: {inv}")
    rep = InventoryReport()
    files = sorted(p for p in inv.iterdir() if p.is_file() and p.suffix in (".yml", ".yaml", ".ini"))
    if not files:
        rep.errors.append(f"no inventory files found in {inv}")
    for path in files:
        name = path.name
        text = path.read_text(encoding="utf-8")
        if _KEY_CONTENT.search(text):
            rep.errors.append(f"{name}: contains private key material")
        if path.suffix == ".ini":
            if _INI_FORBIDDEN.search(text):
                rep.errors.append(f"{name}: contains a plaintext password variable")
            hosts = [ln.split()[0] for ln in text.splitlines()
                     if ln.strip() and not ln.lstrip().startswith(("#", ";", "[")) and "=" not in ln.split()[0]]
            rep.files[name] = hosts
            if not hosts:
                rep.errors.append(f"{name}: no hosts defined")
            continue
        try:
            hosts = parse_yaml_inventory(load_yaml(path))
        except InputError as exc:
            rep.errors.append(f"{name}: {exc}")
            continue
        rep.files[name] = sorted(hosts)
        if not hosts:
            rep.errors.append(f"{name}: no hosts defined")
        for host, hv in hosts.items():
            bad = FORBIDDEN_KEYS & set(hv)
            if bad:
                rep.errors.append(f"{name}: host '{host}' sets {', '.join(sorted(bad))} (use SSH keys / Ansible Vault)")
            key_file = str(hv.get("ansible_ssh_private_key_file", ""))
            if _KEY_CONTENT.search(key_file):
                rep.errors.append(f"{name}: host '{host}' embeds key material instead of a key file path")
            if hv.get("ansible_connection") == "local":
                continue
            for need in ("ansible_host", "ansible_user"):
                if not hv.get(need):
                    rep.errors.append(f"{name}: remote host '{host}' is missing {need}")
            if hv.get("ansible_user") == "root":
                rep.warnings.append(f"{name}: host '{host}' connects as root; prefer an unprivileged user with sudo")
            if "ansible_become" not in hv:
                rep.warnings.append(f"{name}: host '{host}' does not set ansible_become (privilege escalation)")
    return rep
