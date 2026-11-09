"""Destructive-action safeguards shared by validation and tests.

The Ansible roles use the same rule: destructive tasks run only when BOTH
autoops_allow_destructive is true AND autoops_destructive_confirm equals CONFIRM_PHRASE.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import load_yaml

CONFIRM_PHRASE = "I_UNDERSTAND_THIS_REMOVES_DATA"


def destructive_allowed(variables: dict[str, Any]) -> bool:
    return variables.get("autoops_allow_destructive") is True and \
        variables.get("autoops_destructive_confirm") == CONFIRM_PHRASE


def check_safe_defaults(group_vars_all: str | Path) -> list[str]:
    """Return a list of problems if committed defaults are unsafe."""
    data = load_yaml(group_vars_all)
    problems = []
    if data.get("autoops_allow_destructive") is not False:
        problems.append("autoops_allow_destructive must default to false")
    if data.get("autoops_destructive_confirm", "") != "":
        problems.append("autoops_destructive_confirm must default to an empty string")
    if data.get("autoops_key_access_verified") is not False:
        problems.append("autoops_key_access_verified must default to false")
    if data.get("autoops_allow_local_apply") is not False:
        problems.append("autoops_allow_local_apply must default to false")
    return problems
