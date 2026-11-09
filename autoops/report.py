"""Infrastructure health report: combines snapshot, drift and compliance results."""
from __future__ import annotations

import os
import platform
import shutil
import socket
from datetime import datetime
from pathlib import Path
from typing import Any

from .util import utc_now_iso


def collect_local_snapshot() -> dict[str, Any]:
    """Best-effort snapshot of the machine running the CLI. Sections not collected are omitted."""
    snap: dict[str, Any] = {"demo": False, "hostname": socket.gethostname(), "data_source": "live local (partial)"}
    system: dict[str, Any] = {"os": platform.platform(), "cpu_count": os.cpu_count()}
    osr = Path("/etc/os-release")
    if osr.is_file():
        for line in osr.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("PRETTY_NAME="):
                system["os"] = line.split("=", 1)[1].strip().strip('"')
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith("model name"):
                system["cpu_model"] = line.split(":", 1)[1].strip()
                break
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        vals = {}
        for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.replace(":", "").split()
            if len(parts) >= 2 and parts[1].isdigit():
                vals[parts[0]] = int(parts[1])
        if "MemTotal" in vals and "MemAvailable" in vals:
            total, used = vals["MemTotal"] // 1024, (vals["MemTotal"] - vals["MemAvailable"]) // 1024
            system.update(memory_total_mb=total, memory_used_mb=used, memory_percent=round(100 * used / total, 1))
    try:
        usage = shutil.disk_usage(Path.cwd().anchor or "/")
        system.update(disk_mount=Path.cwd().anchor or "/", disk_percent=round(100 * usage.used / usage.total, 1))
    except OSError:
        pass
    snap["system"] = system
    return snap


def build_health_report(observed: dict, drift: dict, compliance: dict, cfg: dict,
                        now: datetime | None = None) -> dict:
    system = observed.get("system", {})
    wanted = [s["name"] for s in cfg["service_policy"].get("services", []) if s.get("state", "started") == "started"]
    svc = observed.get("services")
    if svc is None:
        services = {"checked": 0, "unhealthy": [], "note": "service data not collected"}
    else:
        bad = [n for n in wanted if str(svc.get(n, {}).get("state", "missing")).lower() != "running"]
        services = {"checked": len(wanted), "unhealthy": bad}
    thresholds = cfg["baseline"].get("thresholds", {})
    warnings = []
    if system.get("disk_percent") is not None and system["disk_percent"] >= thresholds.get("disk_percent_warn", 80):
        warnings.append(f"disk usage {system['disk_percent']}% >= {thresholds.get('disk_percent_warn', 80)}%")
    if system.get("memory_percent") is not None and system["memory_percent"] >= thresholds.get("memory_percent_warn", 85):
        warnings.append(f"memory usage {system['memory_percent']}% >= {thresholds.get('memory_percent_warn', 85)}%")
    demo = bool(observed.get("demo", False))
    return {
        "report_type": "health",
        "generated_at": utc_now_iso(now),
        "demo": demo,
        "data_source": observed.get("data_source", "SAMPLE/DEMO DATA" if demo else "snapshot file"),
        "host": observed.get("hostname", "unknown"),
        "os": system.get("os", "unknown"),
        "cpu": {"model": system.get("cpu_model", "unknown"), "count": system.get("cpu_count", "unknown")},
        "memory": {k: system.get(k, "unknown") for k in ("memory_total_mb", "memory_used_mb", "memory_percent")},
        "disk": {"mount": system.get("disk_mount", "unknown"), "percent": system.get("disk_percent", "unknown")},
        "services": services,
        "updates": {"available": system.get("updates_available", "unknown"),
                    "reboot_required": system.get("reboot_required", "unknown")},
        "resource_warnings": warnings,
        "drift": drift["summary"],
        "compliance": compliance["summary"],
    }


def render_health_text(r: dict) -> str:
    banner = "  [SAMPLE/DEMO DATA - not a live system]" if r["demo"] else ""
    m, d = r["memory"], r["disk"]
    lines = [
        f"AutoOps infrastructure health report{banner}",
        f"Generated: {r['generated_at']}   Data source: {r['data_source']}",
        "-" * 78,
        f"Hostname : {r['host']}",
        f"OS       : {r['os']}",
        f"CPU      : {r['cpu']['model']} (count: {r['cpu']['count']})",
        f"Memory   : {m['memory_used_mb']} / {m['memory_total_mb']} MB ({m['memory_percent']}%)",
        f"Disk     : {d['mount']} {d['percent']}% used",
        f"Services : {r['services']['checked']} checked, unhealthy: "
        f"{', '.join(r['services']['unhealthy']) or 'none'}" + (f" ({r['services']['note']})" if "note" in r["services"] else ""),
        f"Updates  : {r['updates']['available']} pending, reboot required: {r['updates']['reboot_required']}",
        f"Drift    : {r['drift']['status']} ({r['drift']['drift_findings']} findings, "
        f"{r['drift']['unverified_sections']} unverified sections)",
        f"Compliance: {r['compliance']['status']} {r['compliance']['compliance_percent']}% "
        f"({r['compliance']['passed']}/{r['compliance']['total_checks']} passed, "
        f"{r['compliance']['failed']} failed, {r['compliance']['warnings']} warnings)",
    ]
    for w in r["resource_warnings"]:
        lines.append(f"WARNING  : {w}")
    return "\n".join(lines)
