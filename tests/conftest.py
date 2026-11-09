import copy
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from autoops.config import load_config  # noqa: E402


@pytest.fixture
def root():
    return ROOT


@pytest.fixture
def cfg():
    return copy.deepcopy(load_config(ROOT / "config"))


@pytest.fixture
def good_state():
    return json.loads((ROOT / "tests/fixtures/observed_compliant.json").read_text())


@pytest.fixture
def bad_state():
    return json.loads((ROOT / "examples/sample_observed_state.json").read_text())
