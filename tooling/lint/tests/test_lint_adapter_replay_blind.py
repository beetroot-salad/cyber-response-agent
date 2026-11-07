"""Tests for the lint_adapter_replay_blind gate (#1385 L1): no adapter, nor the adapter kit's
interface, reads the branch point, the run state (or its call-scoped carrier `CALL_RUN_STATE`) or
the run clock; host-state puts no time stamp in its reply."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_adapter_replay_blind")

#: An adapter as #1385 leaves one: its context's env, and (tacit-knowledge's interim) today's date.
_CLEAN_ADAPTER = ("import datetime as dt\n"
                  "def query(ctx, *, q):\n"
                  "    day = dt.datetime.now(dt.UTC).date()\n"
                  "    return {'q': q, 'base': ctx.env.get('BASE'), 'day': str(day)}\n")
_KIT = ("from typing import Protocol\n"
        "class VerbContext(Protocol):\n"
        "    @property\n"
        "    def env(self): ...\n")


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "defender"
    for rel, text in {"kit/verbs.py": _KIT, **files}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def test_the_real_tree_is_clean():
    """The checkout's adapters and kit carry no replay input (L1)."""
    assert _GATE.main([]) == 0


def test_a_clean_adapter_and_tests_reading_the_cut_have_no_findings(tmp_path):
    """Positive control: a replay-blind adapter, and a test stub reading `as_of`, pass (L1)."""
    stub = "def query(ctx):\n    return getattr(ctx, 'as_of', None)\n"
    files = {"integrations/x_adapter.py": _CLEAN_ADAPTER, "tests/t_adapter.py": stub}
    assert _GATE.scan(_tree(tmp_path, files)) == []


@pytest.mark.parametrize("line", [
    "    at = getattr(ctx, 'as_of', None)",
    "    at = ctx.as_of",
    "    at = getattr(ctx, 'run_state', None)",
    "    at = ctx.run_state.now()",
    "    from defender.systems.verbs import CALL_RUN_STATE",
    "    at = CALL_RUN_STATE.get()",
    "    at = verbs.CALL_RUN_STATE.get().clock",
])
def test_an_adapter_reading_the_branch_point_or_run_state_is_found(tmp_path, line):
    """Each spelling #1385 removed from the adapters, and any reference to `CALL_RUN_STATE`
    under integrations/, is a finding at its line (L1, A5)."""
    src = f"def query(ctx, *, q):\n{line}\n    return {{'q': q}}\n"
    found = _GATE.scan(_tree(tmp_path, {"integrations/x_adapter.py": src}))
    assert found, found
    assert all("integrations/x_adapter.py:2" in f for f in found), found


@pytest.mark.parametrize("name", ["as_of", "run_state"])
def test_the_kit_interface_offering_a_replay_input_is_found(tmp_path, name):
    """The adapter kit's protocol declaring `as_of` or `run_state` is a finding (L1)."""
    kit = f"{_KIT}    @property\n    def {name}(self): ...\n"
    found = _GATE.scan(_tree(tmp_path, {"kit/verbs.py": kit}))
    assert len(found) == 1 and "kit/verbs.py" in found[0] and name in found[0], found


def test_the_platform_and_tests_may_reference_the_run_state_carrier(tmp_path):
    """Positive control: `CALL_RUN_STATE` on the platform side or in a test is no finding (L1)."""
    platform = ("import contextvars\n"
                "CALL_RUN_STATE = contextvars.ContextVar('call_run_state', default=None)\n"
                "def paused(): return CALL_RUN_STATE.get()\n")
    files = {"systems/verbs.py": platform, "tests/t_registry.py": platform,
             "integrations/x_adapter.py": _CLEAN_ADAPTER}
    assert _GATE.scan(_tree(tmp_path, files)) == []


_HOST_STATE = "integrations/host_state_adapter.py"
_STAMPED = [
    "import datetime as dt\ndef query(ctx, *, q):\n    return {'captured_at': 'x'}\n",
    ("import datetime as dt\ndef query(ctx, *, q):\n"
     "    return {'seen': dt.datetime.now(dt.UTC).isoformat()}\n"),
    ("import datetime as dt\ndef query(ctx, *, q):\n    stamp = dt.datetime.now(dt.UTC)\n"
     "    return {'seen': stamp.isoformat()}\n"),
    _CLEAN_ADAPTER,
]


@pytest.mark.parametrize("src", _STAMPED, ids=["field-name", "inline-read", "read-then-output",
                                                "date-in-output"])
def test_host_state_putting_a_time_stamp_in_its_reply_is_found(tmp_path, src):
    """Host-state's `captured_at`, or a datetime read feeding its output, is a finding (L1, A5)."""
    found = _GATE.scan(_tree(tmp_path, {_HOST_STATE: src}))
    assert len(found) == 1 and f"{_HOST_STATE}:3" in found[0], found


@pytest.mark.parametrize("src", [
    ("import time\ndef query(ctx, *, q):\n    deadline = time.monotonic() + 5\n"
     "    while time.monotonic() < deadline and not ctx.env.get('UP'):\n        pass\n"
     "    return {'q': q}\n"),
    ("import datetime as dt\nSTART = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)\n"
     "def query(ctx, *, q):\n    if (dt.datetime.now(dt.UTC) - START).days > 3:\n"
     "        raise RuntimeError('stale')\n    return {'q': q}\n"),
], ids=["monotonic-deadline", "age-check"])
def test_host_state_using_time_for_something_else_is_not_found(tmp_path, src):
    """Positive control: host-state reading a clock without it reaching its reply is clean (L1)."""
    assert _GATE.scan(_tree(tmp_path, {_HOST_STATE: src})) == []


def test_another_adapter_reading_the_date_is_not_found(tmp_path):
    """Positive control: a non-host-state adapter's date in its reply is allowed (L1)."""
    assert _GATE.scan(_tree(tmp_path, {"integrations/x_adapter.py": _CLEAN_ADAPTER})) == []


_PLATFORM_CONTEXT = ("from datetime import datetime\n"
                     "class VerbContext:\n"
                     "    env: dict\n"
                     "    capture: object = None\n"
                     "{extra}")


@pytest.mark.parametrize("field", ["as_of: datetime | None = None",
                                   "run_state: object | None = None"],
                         ids=["as_of", "run_state"])
def test_the_concrete_verb_context_declaring_a_replay_input_is_found(tmp_path, field):
    """`systems.verbs.VerbContext` declaring `as_of` or `run_state` is a finding at its line (L1)."""
    src = _PLATFORM_CONTEXT.format(extra=f"    {field}\n")
    found = _GATE.scan(_tree(tmp_path, {"systems/verbs.py": src}))
    assert len(found) == 1 and "systems/verbs.py:5" in found[0], found


def test_the_concrete_verb_context_without_a_replay_input_is_not_found(tmp_path):
    """Positive control: a context of env and capture, and a non-context class holding
    `run_state` on the platform side, are clean (L1)."""
    src = _PLATFORM_CONTEXT.format(extra="class Holder:\n    run_state: object | None = None\n")
    assert _GATE.scan(_tree(tmp_path, {"systems/verbs.py": src})) == []


@pytest.mark.parametrize("extra", [
    "class RunClock(Protocol):\n    def now(self) -> datetime: ...\n",
    "class Ticker(Protocol):\n    def now(self): ...\n",
    "class Wall(Protocol):\n    def __call__(self) -> datetime: ...\n    def now(self): ...\n",
], ids=["run-clock", "other-name", "callable-with-now"])
def test_the_kit_interface_offering_a_clock_under_any_name_is_found(tmp_path, extra):
    """A protocol in the kit with a `now()` is a finding whatever the protocol is called (L1)."""
    kit = f"from datetime import datetime\n{_KIT}{extra}"
    found = _GATE.scan(_tree(tmp_path, {"kit/verbs.py": kit}))
    assert len(found) == 1 and "kit/verbs.py" in found[0] and "now" in found[0], found


def test_the_kit_interface_with_no_clock_is_not_found(tmp_path):
    """Positive control: a kit protocol with `env` and a non-time field, no `now()`, is clean (L1)."""
    kit = f"from datetime import datetime\n{_KIT}    @property\n    def system(self) -> str: ...\n"
    assert _GATE.scan(_tree(tmp_path, {"kit/verbs.py": kit})) == []


_TEMPLATE = "skills/connect/examples/example_adapter.py"


@pytest.mark.parametrize("line", [
    "    at = getattr(ctx, 'as_of', None)",
    "    at = ctx.as_of",
    "    at = ctx.run_state.now()",
    "    at = CALL_RUN_STATE.get()",
])
def test_the_tenant_adapter_template_reading_the_branch_point_is_found(tmp_path, line):
    """The adapter template under `skills/connect/examples/` is held to the adapters' rule (L1)."""
    src = f"def query(ctx, *, q):\n{line}\n    return {{'q': q}}\n"
    found = _GATE.scan(_tree(tmp_path, {_TEMPLATE: src}))
    assert found and all(f"{_TEMPLATE}:2" in f for f in found), found


def test_a_replay_blind_adapter_template_is_not_found(tmp_path):
    """Positive control: a template reading only `ctx.env` is clean (L1)."""
    assert _GATE.scan(_tree(tmp_path, {_TEMPLATE: _CLEAN_ADAPTER})) == []
