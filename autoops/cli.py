"""AutoOps command line interface (argparse, no third-party CLI dependency)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .compliance import evaluate_compliance, render_compliance_text
from .config import load_config, validate_config
from .drift import detect_drift, render_drift_text
from .inventory import check_inventory_dir
from .report import build_health_report, collect_local_snapshot, render_health_text
from .util import (EXIT_FINDINGS, EXIT_INPUT_ERROR, EXIT_OK, AutoOpsError, InputError, read_json,
                   redact, write_json)
from .validate import validate_project

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_OBSERVED = "examples/sample_observed_state.json"


def _emit(args: argparse.Namespace, report: dict, text: str) -> None:
    if getattr(args, "output", None):
        path = write_json(args.output, report, overwrite=args.force)
        print(f"JSON report written to {path}", file=sys.stderr)
    print(json.dumps(report, indent=2) if args.json else text)


def _input_path(args: argparse.Namespace, default: str | None = None) -> Path:
    raw = args.input or (str(Path(args.root) / default) if default else None)
    if raw is None:
        raise InputError("--input is required")
    if not args.input:
        print(f"note: no --input given, using bundled SAMPLE data: {raw}", file=sys.stderr)
    return Path(raw)


def cmd_validate(args: argparse.Namespace) -> int:
    checks = validate_project(args.root)
    if args.json:
        print(json.dumps([c.__dict__ for c in checks], indent=2))
    else:
        print(f"AutoOps static validation of {Path(args.root).resolve()}")
        for c in checks:
            print(f"[{c.status.upper():4}] {c.name}: {c.detail}")
        print("\nNOTE: static checks only. Ansible playbooks were NOT executed or syntax-checked by ansible-playbook.")
    return EXIT_FINDINGS if any(c.status == "fail" for c in checks) else EXIT_OK


def _load_valid_config(root: str) -> dict:
    cfg = load_config(Path(root) / "config")
    res = validate_config(cfg)
    if res.errors:
        raise InputError("invalid configuration: " + "; ".join(res.errors))
    return cfg


def cmd_drift(args: argparse.Namespace) -> int:
    doc = read_json(_input_path(args, SAMPLE_OBSERVED))
    if isinstance(doc, dict) and doc.get("report_type") == "drift":
        report = doc  # saved report: just render it
    else:
        cfg = _load_valid_config(args.root)
        previous = read_json(args.previous) if args.previous else None
        report = detect_drift(cfg, doc, previous)
    _emit(args, report, render_drift_text(report))
    return EXIT_OK if report["summary"]["status"] == "NO_DRIFT" else EXIT_FINDINGS


def cmd_compliance(args: argparse.Namespace) -> int:
    doc = read_json(_input_path(args, SAMPLE_OBSERVED))
    if isinstance(doc, dict) and doc.get("report_type") == "compliance":
        report = doc
    else:
        cfg = _load_valid_config(args.root)
        report = evaluate_compliance(cfg["rules"], doc)
    _emit(args, report, render_compliance_text(report))
    return EXIT_OK if report["summary"]["status"] == "COMPLIANT" else EXIT_FINDINGS


def cmd_report(args: argparse.Namespace) -> int:
    cfg = _load_valid_config(args.root)
    if args.demo:
        observed = read_json(Path(args.root) / SAMPLE_OBSERVED)
        previous = read_json(Path(args.root) / "examples/sample_previous_state.json")
    elif args.input:
        observed, previous = read_json(args.input), None
    else:
        observed, previous = collect_local_snapshot(), None
    drift = detect_drift(cfg, observed, previous)
    comp = evaluate_compliance(cfg["rules"], observed)
    report = build_health_report(observed, drift, comp, cfg)
    _emit(args, report, render_health_text(report))
    return EXIT_OK


def cmd_inventory(args: argparse.Namespace) -> int:
    inv_dir = Path(args.inventory_dir) if args.inventory_dir else Path(args.root) / "ansible/inventory"
    rep = check_inventory_dir(inv_dir)
    print(f"Inventory check: {inv_dir}")
    for name, hosts in rep.files.items():
        print(f"  {name}: {len(hosts)} host(s): {', '.join(hosts) or '-'}")
    for w in rep.warnings:
        print(f"  WARN  {w}")
    for e in rep.errors:
        print(f"  ERROR {e}")
    print("Result:", "FAILED" if rep.errors else "OK (static check only; Ansible not run)")
    return EXIT_FINDINGS if rep.errors else EXIT_OK


def _common_output(p: argparse.ArgumentParser) -> None:
    p.add_argument("--json", action="store_true", help="print JSON instead of text")
    p.add_argument("--output", metavar="FILE", help="also write the JSON report to FILE")
    p.add_argument("--force", action="store_true", help="allow --output to overwrite an existing file")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m autoops",
        description="AutoOps: validate config, detect drift, check compliance, report health.",
        epilog="Exit codes: 0 ok | 1 findings (drift, non-compliance, failed validation) | 2 usage or input error. "
               "Run from the project root.")
    p.add_argument("--version", action="version", version=f"autoops {__version__}")
    p.add_argument("--root", default=str(ROOT), help="project root (default: auto-detected)")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("validate", help="static validation of structure, YAML, config, inventory, secrets")
    s.add_argument("--json", action="store_true")
    s.set_defaults(func=cmd_validate)

    s = sub.add_parser("drift", help="compare expected config vs an observed snapshot (or render a saved report)")
    s.add_argument("--input", help="observed-state JSON snapshot or saved drift report")
    s.add_argument("--previous", help="previous snapshot JSON to detect changes over time")
    _common_output(s)
    s.set_defaults(func=cmd_drift)

    s = sub.add_parser("compliance", help="evaluate compliance rules (or render a saved report)")
    s.add_argument("--input", help="observed-state JSON snapshot or saved compliance report")
    _common_output(s)
    s.set_defaults(func=cmd_compliance)

    s = sub.add_parser("report", help="infrastructure health report")
    g = s.add_mutually_exclusive_group()
    g.add_argument("--demo", action="store_true", help="use bundled SAMPLE data")
    g.add_argument("--input", help="observed-state JSON snapshot")
    _common_output(s)
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("inventory-check", help="static check of Ansible inventory files")
    s.add_argument("--inventory-dir", help="directory to check (default: ansible/inventory)")
    s.set_defaults(func=cmd_inventory)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code or 0)
    if not getattr(args, "func", None):
        parser.print_help()
        return EXIT_INPUT_ERROR
    try:
        return args.func(args)
    except AutoOpsError as exc:
        print(f"error: {redact(str(exc))}", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except ValueError as exc:
        print(f"error: {redact(str(exc))}", file=sys.stderr)
        return EXIT_INPUT_ERROR
