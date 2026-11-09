import shutil

import pytest

from autoops.config import load_config, load_yaml, validate_config
from autoops.inventory import check_inventory_dir
from autoops.safeguards import CONFIRM_PHRASE, check_safe_defaults, destructive_allowed
from autoops.util import InputError, redact
from autoops.validate import validate_project


def test_shipped_config_is_valid(cfg):
    res = validate_config(cfg)
    assert res.errors == []


def test_missing_config_file_raises(tmp_path):
    with pytest.raises(InputError):
        load_config(tmp_path)


def test_invalid_yaml_raises(tmp_path):
    bad = tmp_path / "bad.yml"
    bad.write_text("key: [unclosed\n")
    with pytest.raises(InputError):
        load_yaml(bad)


def test_empty_yaml_is_empty_dict(tmp_path):
    f = tmp_path / "e.yml"
    f.write_text("")
    assert load_yaml(f) == {}


def test_unquoted_octal_mode_is_rejected(cfg):
    cfg["baseline"]["file_permissions"][0]["mode"] = 644  # int, as YAML would parse bare 0644
    res = validate_config(cfg)
    assert any("quoted" in e for e in res.errors)


def test_invalid_package_name_rejected(cfg):
    cfg["baseline"]["packages"].append("bad name; rm -rf /")
    assert any("invalid package name" in e for e in validate_config(cfg).errors)


def test_invalid_username_rejected(cfg):
    cfg["user_policy"]["users"].append({"name": "Bad User!"})
    assert any("invalid user name" in e for e in validate_config(cfg).errors)


def test_password_in_user_config_rejected(cfg):
    cfg["user_policy"]["users"][0]["password"] = "hunter2"
    assert any("never be stored" in e for e in validate_config(cfg).errors)


def test_public_key_path_traversal_rejected(cfg):
    cfg["user_policy"]["users"][0]["public_key_file"] = "../../etc/passwd.pub"
    assert any("bare *.pub" in e for e in validate_config(cfg).errors)


def test_ssh_bool_value_must_be_string(cfg):
    cfg["ssh_policy"]["settings"]["PermitRootLogin"] = False
    assert any("quoted string" in e for e in validate_config(cfg).errors)


def test_firewall_enable_without_ports_is_error(cfg):
    cfg["firewall_policy"]["enable"] = True
    cfg["firewall_policy"]["allowed_ports"] = []
    assert any("lockout" in e for e in validate_config(cfg).errors)


def test_invalid_port_rejected(cfg):
    cfg["firewall_policy"]["allowed_ports"].append({"port": 70000, "proto": "tcp"})
    assert any("invalid port" in e for e in validate_config(cfg).errors)


def test_duplicate_rule_id_rejected(cfg):
    cfg["rules"].append(dict(cfg["rules"][0]))
    assert any("duplicated" in e for e in validate_config(cfg).errors)


def test_unknown_rule_type_rejected(cfg):
    cfg["rules"][0]["type"] = "run_shell"
    assert any("unknown type" in e for e in validate_config(cfg).errors)


def test_rule_missing_field_rejected(cfg):
    del cfg["rules"][0]["remediation"]
    assert any("remediation" in e for e in validate_config(cfg).errors)


def test_destructive_items_produce_warnings(cfg):
    warnings = validate_config(cfg).warnings
    assert any("absent" in w for w in warnings)
    assert any("package_policy.remove" in w for w in warnings)


def test_safe_defaults_pass_for_shipped_group_vars(root):
    assert check_safe_defaults(root / "ansible/inventory/group_vars/all.yml") == []


def test_unsafe_defaults_detected(tmp_path):
    f = tmp_path / "all.yml"
    f.write_text("autoops_allow_destructive: true\nautoops_destructive_confirm: x\n"
                 "autoops_key_access_verified: true\nautoops_allow_local_apply: true\n")
    problems = check_safe_defaults(f)
    assert len(problems) == 4


def test_destructive_requires_both_gates():
    assert not destructive_allowed({})
    assert not destructive_allowed({"autoops_allow_destructive": True})
    assert not destructive_allowed({"autoops_destructive_confirm": CONFIRM_PHRASE})
    assert not destructive_allowed({"autoops_allow_destructive": True, "autoops_destructive_confirm": "yes"})
    assert destructive_allowed({"autoops_allow_destructive": True, "autoops_destructive_confirm": CONFIRM_PHRASE})


def test_redaction_masks_secrets():
    begin, end = "-----BEGIN " + "OPENSSH PRIVATE KEY-----", "-----END " + "OPENSSH PRIVATE KEY-----"
    text = f"password=hunter2 token: abc123 {begin}\nAAAA\n{end}"
    out = redact(text)
    assert "hunter2" not in out and "abc123" not in out and "AAAA" not in out


def test_inventory_shipped_files_ok(root):
    rep = check_inventory_dir(root / "ansible/inventory")
    assert rep.errors == []
    assert rep.host_count >= 3


def test_inventory_rejects_plaintext_password(tmp_path):
    (tmp_path / "bad.yml").write_text(
        "all:\n  hosts:\n    h1:\n      ansible_host: 192.0.2.1\n      ansible_user: u\n      ansible_password: secret\n")
    rep = check_inventory_dir(tmp_path)
    assert any("ansible_password" in e for e in rep.errors)


def test_inventory_remote_host_needs_user(tmp_path):
    (tmp_path / "x.yml").write_text("all:\n  hosts:\n    h1:\n      ansible_host: 192.0.2.1\n")
    rep = check_inventory_dir(tmp_path)
    assert any("ansible_user" in e for e in rep.errors)


def test_inventory_missing_dir_raises(tmp_path):
    with pytest.raises(InputError):
        check_inventory_dir(tmp_path / "nope")


def test_project_validation_passes_on_shipped_tree(root):
    checks = validate_project(root)
    failed = [c for c in checks if c.status == "fail"]
    assert failed == [], failed


def test_project_validation_detects_committed_private_key(root, tmp_path):
    dest = tmp_path / "proj"
    shutil.copytree(root, dest, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    (dest / "leak.txt").write_text("-----BEGIN " + "OPENSSH PRIVATE KEY-----\nabc\n")
    secrets = [c for c in validate_project(dest) if c.name == "secret scan"][0]
    assert secrets.status == "fail"


def test_project_validation_detects_unsafe_default(root, tmp_path):
    dest = tmp_path / "proj"
    shutil.copytree(root, dest, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    gv = dest / "ansible/inventory/group_vars/all.yml"
    gv.write_text(gv.read_text().replace("autoops_allow_destructive: false", "autoops_allow_destructive: true"))
    check = [c for c in validate_project(dest) if c.name == "safe defaults"][0]
    assert check.status == "fail"
