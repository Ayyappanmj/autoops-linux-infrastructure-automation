import copy
import json

from autoops.cli import main
from autoops.compliance import evaluate_compliance, render_compliance_text
from autoops.drift import detect_drift
from autoops.report import build_health_report, collect_local_snapshot, render_health_text
from autoops.util import InputError, write_json


def test_compliant_state_is_100_percent(cfg, good_state):
    rep = evaluate_compliance(cfg["rules"], good_state)
    s = rep["summary"]
    assert s["failed"] == 0 and s["warnings"] == 0
    assert s["compliance_percent"] == 100.0
    assert s["status"] == "COMPLIANT"
    assert s["total_checks"] == len(cfg["rules"])


def test_sample_state_counts_add_up(cfg, bad_state):
    s = evaluate_compliance(cfg["rules"], bad_state)["summary"]
    assert s["passed"] + s["failed"] + s["warnings"] == s["total_checks"]
    assert s["failed"] > 0
    assert s["status"] == "NON_COMPLIANT"
    assert s["compliance_percent"] == round(100 * s["passed"] / s["total_checks"], 1)


def test_expected_failures_in_sample(cfg, bad_state):
    res = {r["id"]: r["status"] for r in evaluate_compliance(cfg["rules"], bad_state)["results"]}
    assert res["SSH-001"] == "fail" and res["SSH-002"] == "fail"
    assert res["FW-001"] == "fail" and res["FILE-001"] == "fail"
    assert res["SVC-002"] == "fail" and res["PKG-004"] == "fail"
    assert res["SSH-005"] == "warn"      # on_fail: warn
    assert res["PKG-003"] == "warn"      # fail2ban missing, on_fail: warn
    assert res["SSH-003"] == "pass"


def test_unknown_data_is_warning_never_pass(cfg, good_state):
    state = copy.deepcopy(good_state)
    del state["firewall"]
    rep = evaluate_compliance(cfg["rules"], state)
    fw = [r for r in rep["results"] if r["id"] == "FW-001"][0]
    assert fw["status"] == "warn" and fw["verifiable"] is False
    assert rep["summary"]["status"] == "REVIEW_NEEDED"
    assert rep["summary"]["compliance_percent"] < 100


def test_empty_snapshot_is_never_compliant(cfg):
    rep = evaluate_compliance(cfg["rules"], {"hostname": "x"})
    assert rep["summary"]["passed"] == 0
    assert rep["summary"]["status"] != "COMPLIANT"


def test_no_rules_is_not_compliant():
    rep = evaluate_compliance([], {})
    assert rep["summary"]["status"] == "NO_CHECKS"
    assert rep["summary"]["compliance_percent"] == 0.0


def test_file_mode_rule_allows_stricter_modes(cfg, good_state):
    state = copy.deepcopy(good_state)
    state["files"]["/etc/shadow"]["mode"] = "0600"
    res = {r["id"]: r["status"] for r in evaluate_compliance(cfg["rules"], state)["results"]}
    assert res["FILE-001"] == "pass"
    state["files"]["/etc/shadow"]["mode"] = "0660"
    res = {r["id"]: r["status"] for r in evaluate_compliance(cfg["rules"], state)["results"]}
    assert res["FILE-001"] == "fail"


def test_unsupported_rule_type_raises():
    try:
        evaluate_compliance([{"id": "X", "title": "t", "type": "shell", "severity": "low", "remediation": "r"}], {})
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_passed_results_have_no_remediation(cfg, good_state):
    for r in evaluate_compliance(cfg["rules"], good_state)["results"]:
        assert r["remediation"] == ""


def test_report_contains_timestamp_and_text_render(cfg, bad_state):
    rep = evaluate_compliance(cfg["rules"], bad_state)
    assert rep["generated_at"].endswith("+00:00")
    text = render_compliance_text(rep)
    assert "Compliance:" in text and "SAMPLE/DEMO" in text


def test_health_report_demo_is_labelled(cfg, bad_state):
    drift, comp = detect_drift(cfg, bad_state), evaluate_compliance(cfg["rules"], bad_state)
    rep = build_health_report(bad_state, drift, comp, cfg)
    assert rep["demo"] is True
    text = render_health_text(rep)
    assert "SAMPLE/DEMO DATA" in text
    assert "cron" in rep["services"]["unhealthy"]
    assert any("disk" in w for w in rep["resource_warnings"])


def test_health_report_handles_missing_sections(cfg):
    state = {"hostname": "bare"}
    rep = build_health_report(state, detect_drift(cfg, state), evaluate_compliance(cfg["rules"], state), cfg)
    assert rep["os"] == "unknown"
    assert "not collected" in render_health_text(rep)


def test_collect_local_snapshot_is_marked_not_demo():
    snap = collect_local_snapshot()
    assert snap["demo"] is False and snap["hostname"]


def test_write_json_refuses_overwrite(tmp_path):
    p = tmp_path / "r.json"
    write_json(p, {"a": 1})
    try:
        write_json(p, {"a": 2})
    except InputError:
        pass
    else:
        raise AssertionError("overwrite should be refused")
    write_json(p, {"a": 3}, overwrite=True)
    assert json.loads(p.read_text()) == {"a": 3}


def test_cli_compliance_exit_codes(root, capsys):
    assert main(["compliance", "--input", str(root / "tests/fixtures/observed_compliant.json")]) == 0
    assert main(["compliance", "--input", str(root / "examples/sample_observed_state.json")]) == 1
    capsys.readouterr()


def test_cli_compliance_output_file_not_overwritten_without_force(root, tmp_path, capsys):
    out = tmp_path / "c.json"
    args = ["compliance", "--input", str(root / "examples/sample_observed_state.json"), "--output", str(out)]
    assert main(args) == 1
    assert out.exists()
    assert main(args) == 2
    assert main(args + ["--force"]) == 1
    capsys.readouterr()


def test_cli_report_demo(capsys):
    assert main(["report", "--demo"]) == 0
    assert "SAMPLE/DEMO" in capsys.readouterr().out


def test_cli_report_demo_json(capsys):
    main(["report", "--demo", "--json"])
    assert json.loads(capsys.readouterr().out)["report_type"] == "health"


def test_cli_validate_and_inventory(capsys):
    assert main(["validate"]) == 0
    assert main(["inventory-check"]) == 0
    out = capsys.readouterr().out
    assert "NOT executed" in out or "NOT" in out


def test_shipped_sample_reports_are_consistent(root):
    drift = json.loads((root / "examples/sample_drift_report.json").read_text())
    comp = json.loads((root / "examples/sample_compliance_report.json").read_text())
    assert drift["demo"] is True and comp["demo"] is True
    assert comp["summary"]["total_checks"] == len(comp["results"])
