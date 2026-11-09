"""Load and validate the YAML configuration in config/."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .util import SEVERITIES, InputError

CONFIG_FILES = (
    "server_baseline.yml",
    "users.yml",
    "packages.yml",
    "services.yml",
    "compliance_rules.yml",
)

PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+.\-]*$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
MODE_RE = re.compile(r"^[0-7]{4}$")
SSH_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9]+$")
RULE_TYPES = {
    "ssh_setting": ("key", "expected"),
    "firewall_status": ("expected",),
    "package_installed": ("package",),
    "package_absent": ("package",),
    "file_mode": ("path", "max_mode"),
    "service_state": ("service",),
    "service_not_running": ("service",),
    "group_exists": ("group",),
    "user_exists": ("user",),
    "user_in_group": ("user", "group"),
    "system_threshold": ("key", "max"),
}


@dataclass
class ValidationResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def load_yaml(path: str | Path) -> Any:
    p = Path(path)
    if not p.is_file():
        raise InputError(f"configuration file not found: {p}")
    try:
        with open(p, "r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as exc:
        raise InputError(f"invalid YAML in {p}: {exc}") from exc
    return {} if data is None else data


def load_config(config_dir: str | Path) -> dict[str, Any]:
    """Merge all config files into one dict of top-level policy sections."""
    cfg: dict[str, Any] = {}
    for name in CONFIG_FILES:
        doc = load_yaml(Path(config_dir) / name)
        if not isinstance(doc, dict):
            raise InputError(f"{name} must contain a YAML mapping at the top level")
        cfg.update(doc)
    return cfg


def _is_mode(value: Any) -> bool:
    return isinstance(value, str) and bool(MODE_RE.match(value))


def validate_config(cfg: dict[str, Any]) -> ValidationResult:
    res = ValidationResult()
    err, warn = res.errors.append, res.warnings.append

    for section in ("baseline", "ssh_policy", "firewall_policy", "user_policy",
                    "package_policy", "service_policy"):
        if not isinstance(cfg.get(section), dict):
            err(f"missing or invalid section: {section}")
    rules = cfg.get("rules")
    if not isinstance(rules, list) or not rules:
        err("compliance_rules.yml: 'rules' must be a non-empty list")
    if res.errors:
        return res

    base = cfg["baseline"]
    if not isinstance(base.get("timezone"), str) or not base["timezone"]:
        err("baseline.timezone must be a non-empty string")
    for key in ("set_hostname",):
        if not isinstance(base.get(key, False), bool):
            err(f"baseline.{key} must be true/false")
    if base.get("set_hostname") is True and not base.get("hostname"):
        err("baseline.hostname is required when baseline.set_hostname is true")
    for pkg in base.get("packages", []):
        if not isinstance(pkg, str) or not PKG_RE.match(pkg):
            err(f"baseline.packages: invalid package name {pkg!r}")
    for entry in base.get("directories", []):
        path = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(path, str) or not path.startswith("/"):
            err(f"baseline.directories: path must be absolute: {entry!r}")
        elif not _is_mode(entry.get("mode")):
            err(f"baseline.directories[{path}].mode must be a quoted 4-digit octal string like \"0755\"")
    for entry in base.get("file_permissions", []):
        path = entry.get("path") if isinstance(entry, dict) else None
        if not isinstance(path, str) or not path.startswith("/"):
            err(f"baseline.file_permissions: path must be absolute: {entry!r}")
        elif not _is_mode(entry.get("mode")):
            err(f"baseline.file_permissions[{path}].mode must be a quoted 4-digit octal string like \"0644\"")
    thresholds = base.get("thresholds", {})
    for key, val in thresholds.items():
        if not isinstance(val, (int, float)) or not 0 < val <= 100:
            err(f"baseline.thresholds.{key} must be a number between 1 and 100")

    ssh = cfg["ssh_policy"]
    for flag in ("apply_changes", "allow_password_auth_disable"):
        if not isinstance(ssh.get(flag, False), bool):
            err(f"ssh_policy.{flag} must be true/false")
    settings = ssh.get("settings", {})
    if not isinstance(settings, dict) or not settings:
        err("ssh_policy.settings must be a non-empty mapping")
    else:
        for key, val in settings.items():
            if not SSH_KEY_RE.match(str(key)):
                err(f"ssh_policy.settings: invalid directive name {key!r}")
            if not isinstance(val, str):
                err(f"ssh_policy.settings.{key} must be a quoted string (YAML turns bare yes/no into booleans)")
    if ssh.get("apply_changes") is True:
        warn("ssh_policy.apply_changes is true: SSH changes will be applied (safe default is false)")

    fw = cfg["firewall_policy"]
    for flag in ("manage", "enable", "allow_disable"):
        if not isinstance(fw.get(flag, False), bool):
            err(f"firewall_policy.{flag} must be true/false")
    ports = fw.get("allowed_ports", [])
    for entry in ports:
        port = entry.get("port") if isinstance(entry, dict) else None
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            err(f"firewall_policy.allowed_ports: invalid port {entry!r}")
        elif entry.get("proto", "tcp") not in ("tcp", "udp"):
            err(f"firewall_policy.allowed_ports: proto must be tcp or udp: {entry!r}")
    if fw.get("enable") is True:
        warn("firewall_policy.enable is true: UFW may be enabled (safe default is false)")
    if fw.get("enable") is True and not ports:
        err("firewall_policy.enable is true but allowed_ports is empty: SSH lockout risk")

    up = cfg["user_policy"]
    for grp in up.get("groups", []):
        name = grp.get("name") if isinstance(grp, dict) else grp
        if not isinstance(name, str) or not USER_RE.match(name):
            err(f"user_policy.groups: invalid group name {grp!r}")
    seen: set[str] = set()
    for user in up.get("users", []):
        name = user.get("name") if isinstance(user, dict) else None
        if not isinstance(name, str) or not USER_RE.match(name):
            err(f"user_policy.users: invalid user name {user!r}")
            continue
        if name in seen:
            err(f"user_policy.users: duplicate user {name}")
        seen.add(name)
        if user.get("state", "present") not in ("present", "absent"):
            err(f"user_policy.users[{name}].state must be present or absent")
        if user.get("state") == "absent":
            warn(f"user '{name}' is marked absent: removal only runs when destructive actions are enabled")
        shell = user.get("shell")
        if shell is not None and (not isinstance(shell, str) or not shell.startswith("/")):
            err(f"user_policy.users[{name}].shell must be an absolute path")
        pk = user.get("public_key_file")
        if pk is not None and (not isinstance(pk, str) or not pk.endswith(".pub") or "/" in pk or ".." in pk):
            err(f"user_policy.users[{name}].public_key_file must be a bare *.pub file name")
        if any(k in user for k in ("password", "private_key", "ssh_private_key")):
            err(f"user_policy.users[{name}]: passwords/private keys must never be stored in config")

    pp = cfg["package_policy"]
    for key in ("install", "remove", "security_packages"):
        for pkg in pp.get(key, []):
            if not isinstance(pkg, str) or not PKG_RE.match(pkg):
                err(f"package_policy.{key}: invalid package name {pkg!r}")
    for flag in ("apply_updates",):
        if not isinstance(pp.get(flag, False), bool):
            err(f"package_policy.{flag} must be true/false")
    if pp.get("remove"):
        warn("package_policy.remove is non-empty: removal only runs when destructive actions are enabled")

    sp = cfg["service_policy"]
    for svc in sp.get("services", []):
        name = svc.get("name") if isinstance(svc, dict) else None
        if not isinstance(name, str) or not name:
            err(f"service_policy.services: invalid entry {svc!r}")
            continue
        if svc.get("state", "started") not in ("started", "stopped"):
            err(f"service_policy.services[{name}].state must be started or stopped")
        elif svc.get("state") == "stopped" and not sp.get("allow_stop", False):
            warn(f"service '{name}' is set to stopped but service_policy.allow_stop is false: it will not be stopped")
        if not isinstance(svc.get("enabled", True), bool):
            err(f"service_policy.services[{name}].enabled must be true/false")

    ids: set[str] = set()
    for rule in rules:
        rid = rule.get("id") if isinstance(rule, dict) else None
        if not isinstance(rid, str) or not rid:
            err(f"compliance rule without id: {rule!r}")
            continue
        if rid in ids:
            err(f"compliance rule id duplicated: {rid}")
        ids.add(rid)
        rtype = rule.get("type")
        if rtype not in RULE_TYPES:
            err(f"rule {rid}: unknown type {rtype!r} (known: {', '.join(sorted(RULE_TYPES))})")
            continue
        for req in RULE_TYPES[rtype] + ("title", "severity", "remediation"):
            if req not in rule:
                err(f"rule {rid}: missing required field '{req}'")
        if rule.get("severity") not in SEVERITIES:
            err(f"rule {rid}: severity must be one of {', '.join(SEVERITIES)}")
        if rule.get("on_fail", "fail") not in ("fail", "warn"):
            err(f"rule {rid}: on_fail must be 'fail' or 'warn'")
        if rtype == "file_mode" and "max_mode" in rule and not _is_mode(rule["max_mode"]):
            err(f"rule {rid}: max_mode must be a quoted 4-digit octal string")
    return res
