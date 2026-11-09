"""Security compliance evaluation against config/compliance_rules.yml."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

from .drift import _mode, _norm, _pkg_names
from .util import SEVERITY_RANK, utc_now_iso

# A check returns (status, actual, message); status is "pass", "fail" or "unknown".
Result = tuple[str, Any, str]


def _ssh_setting(rule: dict, obs: dict) -> Result:
    if "ssh" not in obs:
        return "unknown", None, "SSH configuration not collected"
    actual = {str(k).lower(): v for k, v in obs["ssh"].items()}.get(rule["key"].lower())
    if actual is None:
        return "fail", None, f"{rule['key']} is not set"
    ok = _norm(actual) in [_norm(e) for e in rule["expected"]]
    return ("pass" if ok else "fail"), actual, f"{rule['key']} = {actual}"


def _firewall_status(rule: dict, obs: dict) -> Result:
    if "firewall" not in obs:
        return "unknown", None, "firewall state not collected"
    actual = obs["firewall"].get("status")
    return ("pass" if _norm(actual) == _norm(rule["expected"]) else "fail"), actual, f"firewall is {actual}"


def _package_installed(rule: dict, obs: dict) -> Result:
    if "packages" not in obs:
        return "unknown", None, "package inventory not collected"
    present = rule["package"] in _pkg_names(obs["packages"])
    return ("pass" if present else "fail"), "installed" if present else "absent", rule["package"]


def _package_absent(rule: dict, obs: dict) -> Result:
    status, actual, msg = _package_installed(rule, obs)
    if status == "unknown":
        return status, actual, msg
    return ("pass" if status == "fail" else "fail"), actual, msg


def _file_mode(rule: dict, obs: dict) -> Result:
    if "files" not in obs:
        return "unknown", None, "file permissions not collected"
    entry = obs["files"].get(rule["path"])
    if not entry or entry.get("exists") is False:
        return "fail", "file not found", f"{rule['path']} missing"
    actual, limit = _mode(entry.get("mode")), _mode(rule["max_mode"])
    if actual is None:
        return "unknown", entry.get("mode"), "mode not parseable"
    too_open = int(actual, 8) & ~int(limit, 8)
    return ("fail" if too_open else "pass"), actual, f"mode {actual} (max allowed {limit})"


def _service_state(rule: dict, obs: dict) -> Result:
    if "services" not in obs:
        return "unknown", None, "service inventory not collected"
    svc = obs["services"].get(rule["service"])
    if not svc:
        return "fail", "not found", f"{rule['service']} not found"
    ok = _norm(svc.get("state")) == ("running" if rule.get("running", True) else "stopped")
    if "enabled" in rule:
        ok = ok and bool(svc.get("enabled")) == bool(rule["enabled"])
    return ("pass" if ok else "fail"), f"{svc.get('state')}, enabled={svc.get('enabled')}", rule["service"]


def _service_not_running(rule: dict, obs: dict) -> Result:
    if "services" not in obs:
        return "unknown", None, "service inventory not collected"
    svc = obs["services"].get(rule["service"])
    running = bool(svc) and _norm(svc.get("state")) == "running"
    return ("fail" if running else "pass"), "running" if running else "not running", rule["service"]


def _group_exists(rule: dict, obs: dict) -> Result:
    if "groups" not in obs:
        return "unknown", None, "group inventory not collected"
    ok = rule["group"] in obs["groups"]
    return ("pass" if ok else "fail"), "exists" if ok else "absent", rule["group"]


def _user_exists(rule: dict, obs: dict) -> Result:
    if "users" not in obs:
        return "unknown", None, "user inventory not collected"
    ok = rule["user"] in obs["users"]
    return ("pass" if ok else "fail"), "exists" if ok else "absent", rule["user"]


def _user_in_group(rule: dict, obs: dict) -> Result:
    if "users" not in obs:
        return "unknown", None, "user inventory not collected"
    user = obs["users"].get(rule["user"])
    if not user:
        return "fail", "user absent", rule["user"]
    ok = rule["group"] in user.get("groups", [])
    return ("pass" if ok else "fail"), user.get("groups", []), f"{rule['user']} in {rule['group']}"


def _system_threshold(rule: dict, obs: dict) -> Result:
    value = obs.get("system", {}).get(rule["key"])
    if value is None:
        return "unknown", None, f"{rule['key']} not collected"
    return ("pass" if value <= rule["max"] else "fail"), value, f"{rule['key']}={value} (max {rule['max']})"


HANDLERS: dict[str, Callable[[dict, dict], Result]] = {
    "ssh_setting": _ssh_setting,
    "firewall_status": _firewall_status,
    "package_installed": _package_installed,
    "package_absent": _package_absent,
    "file_mode": _file_mode,
    "service_state": _service_state,
    "service_not_running": _service_not_running,
    "group_exists": _group_exists,
    "user_exists": _user_exists,
    "user_in_group": _user_in_group,
    "system_threshold": _system_threshold,
}


def evaluate_compliance(rules: list[dict], observed: dict, now: datetime | None = None) -> dict:
    """Evaluate rules. Unknown data and on_fail=warn failures count as warnings, never as passes."""
    if not isinstance(observed, dict):
        raise ValueError("observed state must be a JSON object")
    results = []
    for rule in rules:
        handler = HANDLERS.get(rule.get("type"))
        if handler is None:
            raise ValueError(f"rule {rule.get('id')}: unsupported type {rule.get('type')!r}")
        raw, actual, message = handler(rule, observed)
        if raw == "pass":
            status = "pass"
        elif raw == "unknown" or rule.get("on_fail", "fail") == "warn":
            status = "warn"
        else:
            status = "fail"
        results.append({
            "id": rule["id"], "title": rule["title"], "type": rule["type"], "status": status,
            "severity": rule["severity"], "actual": actual, "message": message,
            "verifiable": raw != "unknown",
            "remediation": "" if status == "pass" else rule["remediation"],
        })
    total = len(results)
    passed = sum(r["status"] == "pass" for r in results)
    failed = sum(r["status"] == "fail" for r in results)
    warned = sum(r["status"] == "warn" for r in results)
    if total == 0:
        status = "NO_CHECKS"
    elif failed:
        status = "NON_COMPLIANT"
    elif warned:
        status = "REVIEW_NEEDED"
    else:
        status = "COMPLIANT"
    return {
        "report_type": "compliance",
        "generated_at": utc_now_iso(now),
        "demo": bool(observed.get("demo", False)),
        "host": observed.get("hostname", "unknown"),
        "summary": {
            "status": status, "total_checks": total, "passed": passed, "failed": failed,
            "warnings": warned, "compliance_percent": round(100.0 * passed / total, 1) if total else 0.0,
        },
        "results": sorted(results, key=lambda r: (r["status"] == "pass", SEVERITY_RANK[r["severity"]], r["id"])),
    }


def render_compliance_text(report: dict) -> str:
    s = report["summary"]
    lines = [
        "AutoOps compliance report" + ("  [SAMPLE/DEMO DATA]" if report.get("demo") else ""),
        f"Host: {report.get('host')}   Generated: {report.get('generated_at')}",
        f"Status: {s['status']}   Compliance: {s['compliance_percent']}%",
        f"Total: {s['total_checks']}  Passed: {s['passed']}  Failed: {s['failed']}  Warnings: {s['warnings']}",
        "-" * 78,
    ]
    for r in report["results"]:
        lines.append(f"[{r['status'].upper():4}] {r['id']:8} {r['title']}  (severity: {r['severity']})")
        if r["status"] != "pass":
            lines.append(f"       found: {r['message']}")
            lines.append(f"       fix:   {r['remediation']}")
    lines.append("-" * 78)
    lines.append("Note: unverifiable checks are warnings, not passes. 'COMPLIANT' requires every check to pass.")
    return "\n".join(lines)
