"""Configuration drift detection.

Compares (1) expected configuration (config/*.yml), (2) an observed state snapshot and
optionally (3) a previous snapshot. Pure functions: no network, no shell, no Linux needed.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from .util import SEVERITY_RANK, SEVERITIES, utc_now_iso

HIGH_SSH = {"permitrootlogin", "passwordauthentication", "pubkeyauthentication", "permitemptypasswords"}


@dataclass
class Finding:
    source: str        # "expected" (config vs observed) or "previous_snapshot"
    category: str      # packages | services | files | users | groups | ssh | firewall
    resource: str
    status: str        # missing | mismatch | unexpected | changed | unknown
    expected: Any
    actual: Any
    severity: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class _Ctx:
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.checks = 0

    def check(self) -> None:
        self.checks += 1

    def add(self, *args: Any, **kwargs: Any) -> None:
        self.findings.append(Finding(*args, **kwargs))


def _norm(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    return str(value).strip().lower()


def _mode(value: Any) -> str | None:
    try:
        return f"{int(str(value), 8):04o}"
    except (TypeError, ValueError):
        return None


def _pkg_names(section: Any) -> set[str]:
    if isinstance(section, dict):
        return set(section)
    return set(section or [])


def _unknown(ctx: _Ctx, category: str, what: str) -> None:
    ctx.check()
    ctx.add("expected", category, what, "unknown", "collected data", "not present in snapshot", "medium",
            f"Collect '{category}' data (run playbooks/compliance.yml) so it can be verified.")


def _packages(ctx: _Ctx, cfg: dict, obs: dict) -> None:
    if "packages" not in obs:
        _unknown(ctx, "packages", "package inventory")
        return
    installed = _pkg_names(obs["packages"])
    required = list(dict.fromkeys(cfg["baseline"].get("packages", []) + cfg["package_policy"].get("install", [])))
    security = set(cfg["package_policy"].get("security_packages", []))
    for pkg in required:
        ctx.check()
        if pkg not in installed:
            ctx.add("expected", "packages", pkg, "missing", "installed", "absent",
                    "high" if pkg in security else "medium",
                    f"apt-get install {pkg} (or run ansible/playbooks/packages.yml)")
    for pkg in cfg["package_policy"].get("remove", []):
        ctx.check()
        if pkg in installed:
            ctx.add("expected", "packages", pkg, "unexpected", "absent", "installed", "high",
                    f"Remove {pkg}; AutoOps only removes packages with explicit destructive confirmation.")


def _services(ctx: _Ctx, cfg: dict, obs: dict) -> None:
    if "services" not in obs:
        _unknown(ctx, "services", "service inventory")
        return
    seen = obs["services"]
    for svc in cfg["service_policy"].get("services", []):
        name = svc["name"]
        want_state = "running" if svc.get("state", "started") == "started" else "stopped"
        want_enabled = svc.get("enabled", True)
        ctx.check()
        if name not in seen:
            ctx.add("expected", "services", name, "missing", f"{want_state}, enabled={want_enabled}", "not found",
                    "high", f"Install/enable {name} (ansible/playbooks/services.yml)")
            continue
        actual = seen[name]
        if _norm(actual.get("state")) != want_state:
            ctx.add("expected", "services", name, "mismatch", want_state, actual.get("state"), "high",
                    f"systemctl {'start' if want_state == 'running' else 'stop'} {name}")
        ctx.check()
        if bool(actual.get("enabled")) != bool(want_enabled):
            ctx.add("expected", "services", f"{name} (boot)", "mismatch", f"enabled={want_enabled}",
                    f"enabled={actual.get('enabled')}", "medium",
                    f"systemctl {'enable' if want_enabled else 'disable'} {name}")
    for name in cfg["service_policy"].get("forbidden", []):
        ctx.check()
        if name in seen and _norm(seen[name].get("state")) == "running":
            ctx.add("expected", "services", name, "unexpected", "not running", "running", "high",
                    f"systemctl disable --now {name}")


def _files(ctx: _Ctx, cfg: dict, obs: dict) -> None:
    if "files" not in obs:
        _unknown(ctx, "files", "file permissions")
        return
    for entry in cfg["baseline"].get("file_permissions", []):
        path, sev = entry["path"], entry.get("severity", "medium")
        actual = obs["files"].get(path)
        ctx.check()
        if not actual or actual.get("exists") is False:
            ctx.add("expected", "files", path, "missing", entry["mode"], "file not found", sev,
                    f"Restore {path} from package or backup")
            continue
        if _mode(actual.get("mode")) != _mode(entry["mode"]):
            ctx.add("expected", "files", f"{path} (mode)", "mismatch", entry["mode"], actual.get("mode"), sev,
                    f"chmod {entry['mode'][1:]} {path}")
        for key, label in (("owner", "owner"), ("group", "group")):
            if key in entry and key in actual and actual[key] != entry[key]:
                ctx.check()
                ctx.add("expected", "files", f"{path} ({label})", "mismatch", entry[key], actual[key], sev,
                        f"chown {entry['owner']}:{entry['group']} {path}")


def _users(ctx: _Ctx, cfg: dict, obs: dict) -> None:
    if "users" not in obs or "groups" not in obs:
        _unknown(ctx, "users", "user/group inventory")
        return
    groups = set(obs["groups"])
    for grp in cfg["user_policy"].get("groups", []):
        name = grp["name"] if isinstance(grp, dict) else grp
        ctx.check()
        if name not in groups:
            ctx.add("expected", "groups", name, "missing", "exists", "absent", "medium",
                    "Run ansible/playbooks/users.yml")
    for user in cfg["user_policy"].get("users", []):
        name = user["name"]
        actual = obs["users"].get(name)
        ctx.check()
        if user.get("state", "present") == "absent":
            if actual:
                ctx.add("expected", "users", name, "unexpected", "absent", "present", "medium",
                        "Remove only after review: users.yml with autoops_allow_destructive=true")
            continue
        if not actual:
            ctx.add("expected", "users", name, "missing", "exists", "absent", "medium",
                    "Run ansible/playbooks/users.yml")
            continue
        if user.get("shell") and actual.get("shell") and actual["shell"] != user["shell"]:
            ctx.check()
            ctx.add("expected", "users", f"{name} (shell)", "mismatch", user["shell"], actual["shell"], "low",
                    f"usermod -s {user['shell']} {name}")
        for grp in user.get("groups", []):
            ctx.check()
            if grp not in actual.get("groups", []):
                ctx.add("expected", "users", f"{name} (group {grp})", "missing", f"member of {grp}",
                        "not a member", "medium", f"usermod -aG {grp} {name}")


def _ssh(ctx: _Ctx, cfg: dict, obs: dict) -> None:
    if "ssh" not in obs:
        _unknown(ctx, "ssh", "effective sshd configuration")
        return
    actual_cfg = {str(k).lower(): v for k, v in obs["ssh"].items()}
    for key, want in cfg["ssh_policy"].get("settings", {}).items():
        ctx.check()
        got = actual_cfg.get(key.lower())
        if got is None:
            ctx.add("expected", "ssh", key, "missing", want, "not set", "medium",
                    f"Set '{key} {want}' in /etc/ssh/sshd_config.d/00-autoops.conf")
        elif _norm(got) != _norm(want):
            ctx.add("expected", "ssh", key, "mismatch", want, got,
                    "high" if key.lower() in HIGH_SSH else "medium",
                    f"Set '{key} {want}' (validate with 'sshd -t' before reload; keep a backup)")


def _firewall(ctx: _Ctx, cfg: dict, obs: dict) -> None:
    fw = cfg["firewall_policy"]
    if "firewall" not in obs:
        _unknown(ctx, "firewall", "firewall state")
        return
    actual = obs["firewall"]
    want = fw.get("desired_state", "active")
    ctx.check()
    if _norm(actual.get("status")) != want:
        ctx.add("expected", "firewall", "ufw status", "mismatch", want, actual.get("status"), "high",
                "Allow SSH first, then enable UFW (security.yml with firewall_policy.enable=true)")
    allowed = actual.get("allowed")
    if allowed is not None:
        for entry in fw.get("allowed_ports", []):
            token = f"{entry['port']}/{entry.get('proto', 'tcp')}"
            ctx.check()
            if token not in allowed:
                ctx.add("expected", "firewall", f"allow {token}", "missing", "rule present", "rule absent",
                        "critical" if entry["port"] == 22 else "medium", f"ufw allow {token}")


def _changes(ctx: _Ctx, prev: dict, obs: dict) -> None:
    def add(cat: str, res: str, status: str, before: Any, after: Any, sev: str) -> None:
        ctx.add("previous_snapshot", cat, res, status, before, after, sev,
                "Confirm the change was authorised; if not, restore the previous value or re-run the playbook.")

    if "packages" in prev and "packages" in obs:
        before, after = _pkg_names(prev["packages"]), _pkg_names(obs["packages"])
        for pkg in sorted(before - after):
            ctx.check()
            add("packages", pkg, "changed", "installed", "removed", "medium")
        for pkg in sorted(after - before):
            ctx.check()
            add("packages", pkg, "changed", "absent", "installed", "low")
    if "services" in prev and "services" in obs:
        for name in sorted(set(prev["services"]) | set(obs["services"])):
            ctx.check()
            b, a = prev["services"].get(name), obs["services"].get(name)
            if b != a:
                add("services", name, "changed", b, a, "medium")
    if "ssh" in prev and "ssh" in obs:
        pb = {k.lower(): v for k, v in prev["ssh"].items()}
        ob = {k.lower(): v for k, v in obs["ssh"].items()}
        for key in sorted(set(pb) | set(ob)):
            ctx.check()
            if _norm(pb.get(key)) != _norm(ob.get(key)):
                add("ssh", key, "changed", pb.get(key), ob.get(key), "high" if key in HIGH_SSH else "medium")
    if "files" in prev and "files" in obs:
        for path in sorted(set(prev["files"]) | set(obs["files"])):
            ctx.check()
            b, a = prev["files"].get(path), obs["files"].get(path)
            if b != a:
                add("files", path, "changed", b, a, "high")
    if "users" in prev and "users" in obs:
        for name in sorted(set(prev["users"]) | set(obs["users"])):
            ctx.check()
            b, a = prev["users"].get(name), obs["users"].get(name)
            if b != a:
                add("users", name, "changed", b, a, "medium")
    if "firewall" in prev and "firewall" in obs:
        ctx.check()
        if prev["firewall"].get("status") != obs["firewall"].get("status"):
            add("firewall", "ufw status", "changed", prev["firewall"].get("status"),
                obs["firewall"].get("status"), "high")


def detect_drift(cfg: dict, observed: dict, previous: dict | None = None,
                 now: datetime | None = None) -> dict:
    """Return a drift report dict. `cfg` comes from config.load_config()."""
    if not isinstance(observed, dict):
        raise ValueError("observed state must be a JSON object")
    ctx = _Ctx()
    for fn in (_packages, _services, _files, _users, _ssh, _firewall):
        fn(ctx, cfg, observed)
    if previous is not None:
        _changes(ctx, previous, observed)

    ctx.findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.category, f.resource))
    drift = [f for f in ctx.findings if f.status != "unknown"]
    unknown = [f for f in ctx.findings if f.status == "unknown"]
    if drift:
        status = "DRIFT_DETECTED"
    elif unknown:
        status = "INCOMPLETE"
    else:
        status = "NO_DRIFT"
    return {
        "report_type": "drift",
        "generated_at": utc_now_iso(now),
        "demo": bool(observed.get("demo", False)),
        "host": observed.get("hostname", "unknown"),
        "compared_with_previous_snapshot": previous is not None,
        "summary": {
            "status": status,
            "checks_evaluated": ctx.checks,
            "drift_findings": len(drift),
            "unverified_sections": len(unknown),
            "by_severity": {s: sum(1 for f in drift if f.severity == s) for s in SEVERITIES},
        },
        "findings": [f.to_dict() for f in ctx.findings],
    }


def render_drift_text(report: dict) -> str:
    s = report["summary"]
    lines = [
        "AutoOps drift report" + ("  [SAMPLE/DEMO DATA]" if report.get("demo") else ""),
        f"Host: {report.get('host')}   Generated: {report.get('generated_at')}",
        f"Status: {s['status']}   Checks evaluated: {s['checks_evaluated']}   "
        f"Drift findings: {s['drift_findings']}   Unverified sections: {s['unverified_sections']}",
        "By severity: " + ", ".join(f"{k}={v}" for k, v in s["by_severity"].items() if v) if s["drift_findings"]
        else "By severity: none",
        "-" * 78,
    ]
    for f in report["findings"]:
        lines.append(f"[{f['severity'].upper():8}] {f['category']}: {f['resource']}  ({f['status']}, {f['source']})")
        lines.append(f"           expected: {f['expected']}   actual: {f['actual']}")
        lines.append(f"           fix: {f['remediation']}")
    if not report["findings"]:
        lines.append("No drift detected in the evaluated sections.")
    return "\n".join(lines)
