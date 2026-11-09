import os
import shutil
import subprocess

import pytest

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "scripts", "backup_config.sh")


def _need_linux():
    if os.name == "nt" or shutil.which("bash") is None:
        pytest.skip("backup script requires Linux + bash + GNU coreutils")


def _run(*args):
    return subprocess.run(["bash", SCRIPT, *args], capture_output=True, text=True)


def test_backup_creates_checksums_and_refuses_overwrite(tmp_path):
    _need_linux()
    src = tmp_path / "a.conf"
    src.write_text("Port 22\n")
    os.chmod(src, 0o640)
    lst = tmp_path / "list.txt"
    lst.write_text(f"{src}\n{tmp_path}/missing.conf\n")
    out = tmp_path / "out"
    r = _run("-d", str(out), "-f", str(lst))
    assert r.returncode == 0, r.stderr
    (backup,) = list(out.iterdir())
    assert (backup / "SHA256SUMS").is_file() and (backup / "metadata.txt").is_file()
    assert "mode=640" in (backup / "metadata.txt").read_text()
    assert _run("verify", str(backup)).returncode == 0
    copied = next((backup / "files").rglob("a.conf"))
    copied.write_text("tampered\n")
    assert _run("verify", str(backup)).returncode == 1


def test_backup_rejects_relative_paths(tmp_path):
    _need_linux()
    lst = tmp_path / "l.txt"
    lst.write_text("relative/file\n")
    assert _run("-d", str(tmp_path / "o"), "-f", str(lst)).returncode == 2


def test_dry_run_creates_nothing(tmp_path):
    _need_linux()
    lst = tmp_path / "l.txt"
    lst.write_text(f"{tmp_path}/x\n")
    r = _run("-n", "-d", str(tmp_path / "o"), "-f", str(lst))
    assert r.returncode == 0 and not (tmp_path / "o").exists()
