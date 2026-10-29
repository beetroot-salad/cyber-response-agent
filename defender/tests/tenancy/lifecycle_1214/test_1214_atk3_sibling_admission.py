"""#1214 attack-3 hole 15 (P3, Flow 4): a sibling run (`--tenant T --episode E --world W`) is admitted like an ordinary
run: only while the tenant is `active`, and with no directory and no database address it refuses.
"""
from __future__ import annotations

import contextlib
import io
from typing import Any

import pytest

from defender.tests.support.tenancy._active1214 import DSN_ENV, active_directory
from defender.tests.tenancy.lifecycle_1214.test_1214_host_entry import (
    NOT_A_REFUSAL_OF_STATE,
    TENANT,
    _Calls,
    _has,
    _tenant_placed,  # noqa: F401 — autouse fixture
)


def _sibling_start(directory: Any = ...) -> str:
    """`run.main` of a sibling up to its first refusal or fault: its text."""
    from defender import run as run_py

    calls = _Calls()
    given = {} if directory is ... else {"directory": directory}
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            run_py.main(["--tenant", TENANT, "--episode", "ep-1214", "--world", "w-1214", "--no-learn"], **given,
                        preflight=calls.hook("preflight", 0), visualize=calls.hook("visualize", None),
                        enqueue=calls.hook("enqueue", False), publish=calls.hook("publish", ""),
                        lifecycle=calls.hook("lifecycle", {"output": "", "requests": 0, "truncated_by": None}))
    except SystemExit as refused:
        return f"{refused.code}\n{err.getvalue()}"
    except Exception as failed:  # noqa: BLE001 — past acceptance, the next real refusal
        return f"{type(failed).__name__}: {failed}\n{err.getvalue()}"
    return err.getvalue()


@pytest.mark.parametrize("state", ["creating", "offboarding", "offboarded"])
def test_a_sibling_run_refuses_a_tenant_that_is_not_active_naming_its_state(data_root, state):
    """`--episode` runs refuse a non-`active` tenant naming its state, before the episode is looked up (Flow 4, P3)."""
    refused = _sibling_start(active_directory(data_root, TENANT, state=state))
    _has(refused, "[run.py]", state)
    admitted = _sibling_start(active_directory(data_root, TENANT))
    assert not any(word in admitted.lower() for word in NOT_A_REFUSAL_OF_STATE), f"control: {admitted}"


def test_a_sibling_run_of_an_unknown_tenant_is_refused(data_root):
    """A directory holding no row for the tenant refuses a sibling like an ordinary run (P3)."""
    from defender.tenancy import InMemoryTenantRepository, TenantDirectory

    twin: Any = InMemoryTenantRepository()
    refused = _sibling_start(TenantDirectory(lambda: twin))
    _has(refused, "[run.py]")
    assert "no such tenant" in refused, refused


def test_a_sibling_run_with_no_directory_and_no_database_address_refuses(data_root, monkeypatch):
    """Fails closed: no directory, no address -> a refusal naming the address (Flow 4)."""
    monkeypatch.delenv(DSN_ENV, raising=False)
    _has(_sibling_start(), "[run.py]", DSN_ENV)
