import copy
import json

from autoops.cli import main
from autoops.drift import detect_drift, render_drift_text


def test_compliant_state_has_no_drift(cfg, good_state):
    rep = detect_drift(cfg, good_state)
    assert rep["summary"]["status"] == "NO_DRIFT"
    assert rep["findings"] == []
    assert rep["summary"]["checks_evaluated"] > 20


def test_sample_state_detects_expected_drift(cfg, bad_state):
    rep = detect_drift(cfg, bad_state)
    found = {(f["category"], f["resource"], f["status"]) for f in rep["findings"]}
    assert ("packages", "fail2ban", "missing") in found
    assert ("packages", "telnetd", "unexpected") in found
    assert ("services", "cron", "mismatch") in found
    assert ("services", "telnet", "unexpected") in found
    assert ("files", "/etc/shadow (mode)", "mismatch") in found
    assert ("ssh", "PermitRootLogin", "mismatch") in found
    assert ("ssh", "PasswordAuthentication", "mismatch") in found
    assert ("firewall", "ufw status", "mismatch") in found
    assert ("users", "opsadmin (group autoops-admins)", "missing") in found
    assert rep["summary"]["status"] == "DRIFT_DETECTED"


def test_finding_has_all_required_fields(cfg, bad_state):
    for f in detect_drift(cfg, bad_state)["findings"]:
        for key in ("status", "resource", "expected", "actual", "severity", "remediation"):
            assert key in f and f[key] != ""


def test_severity_assignment(cfg, bad_state):
    by = {f["resource"]: f["severity"] for f in detect_drift(cfg, bad_state)["findings"] if f["source"] == "expected"}
    assert by["/etc/shadow (mode)"] == "critical"
    assert by["PermitRootLogin"] == "high"
    assert by["X11Forwarding"] == "medium"


def test_findings_sorted_by_severity(cfg, bad_state):
    order = ["critical", "high", "medium", "low", "info"]
    ranks = [order.index(f["severity"]) for f in detect_drift(cfg, bad_state)["findings"]]
    assert ranks == sorted(ranks)


def test_missing_missing_section_is_incomplete_not_clean(cfg, good_state):
    state = copy.deepcopy(good_state)
    del state["ssh"]
    rep = detect_drift(cfg, state)
    assert rep["summary"]["status"] == "INCOMPLETE"
    assert rep["summary"]["unverified_sections"] == 1


def test_missing_required_user_and_group(cfg, good_state):
    state = copy.deepcopy(good_state)
    del state["users"]["opsadmin"]
    state["groups"].remove("autoops-admins")
    found = {(f["category"], f["resource"]) for f in detect_drift(cfg, state)["findings"]}
    assert ("users", "opsadmin") in found
    assert ("groups", "autoops-admins") in found


def test_ssh_keys_compared_case_insensitively(cfg, good_state):
    state = copy.deepcopy(good_state)
    state["ssh"]["permitrootlogin"] = "NO"
    assert detect_drift(cfg, state)["summary"]["status"] == "NO_DRIFT"


def test_file_mode_compared_numerically(cfg, good_state):
    state = copy.deepcopy(good_state)
    state["files"]["/etc/shadow"]["mode"] = "640"
    assert detect_drift(cfg, state)["summary"]["status"] == "NO_DRIFT"


def test_previous_snapshot_changes_detected(cfg, good_state):
    prev = copy.deepcopy(good_state)
    cur = copy.deepcopy(good_state)
    cur["ssh"]["maxauthtries"] = "10"
    cur["packages"].append("netcat")
    prev["packages"].append("htop-old")
    rep = detect_drift(cfg, cur, prev)
    changed = {(f["category"], f["resource"]) for f in rep["findings"] if f["source"] == "previous_snapshot"}
    assert ("ssh", "maxauthtries") in changed
    assert ("packages", "netcat") in changed
    assert ("packages", "htop-old") in changed
    assert rep["compared_with_previous_snapshot"] is True


def test_identical_previous_snapshot_adds_nothing(cfg, good_state):
    rep = detect_drift(cfg, good_state, copy.deepcopy(good_state))
    assert rep["summary"]["status"] == "NO_DRIFT"


def test_demo_flag_propagates(cfg, bad_state):
    assert detect_drift(cfg, bad_state)["demo"] is True


def test_non_object_input_raises(cfg):
    try:
        detect_drift(cfg, ["not", "a", "dict"])
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_text_render_mentions_demo_and_remediation(cfg, bad_state):
    text = render_drift_text(detect_drift(cfg, bad_state))
    assert "SAMPLE/DEMO" in text and "fix:" in text


def test_cli_drift_exit_codes(root, capsys):
    assert main(["drift", "--input", str(root / "tests/fixtures/observed_compliant.json")]) == 0
    assert main(["drift", "--input", str(root / "examples/sample_observed_state.json")]) == 1
    assert main(["drift", "--input", str(root / "nope.json")]) == 2
    capsys.readouterr()


def test_cli_drift_json_output(root, capsys):
    main(["drift", "--json", "--input", str(root / "examples/sample_observed_state.json")])
    data = json.loads(capsys.readouterr().out)
    assert data["report_type"] == "drift"


def test_cli_drift_renders_saved_report(root, capsys):
    code = main(["drift", "--input", str(root / "examples/sample_drift_report.json")])
    assert code == 1
    assert "drift report" in capsys.readouterr().out


def test_cli_invalid_json_input_is_exit_2(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    assert main(["drift", "--input", str(bad)]) == 2
    assert "invalid JSON" in capsys.readouterr().err


def test_cli_no_command_prints_help(capsys):
    assert main([]) == 2
    assert "usage" in capsys.readouterr().out.lower()
