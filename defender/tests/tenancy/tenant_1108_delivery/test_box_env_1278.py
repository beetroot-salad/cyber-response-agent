"""#1278 P2 / compat 55: nothing of the host's database address reaches a learning box. Every box a learning stage
launches is built by a request whose environment is exactly an allowlist, whatever the host process holds."""
from __future__ import annotations

import json
import re
from pathlib import Path

from defender.box import _lifecycle, _oracle
from defender.tests.tenancy.tenant_1108_delivery._support import DEFENDER, LANES, ForgeHTTP, delivery

PLANTED = "postgresql://planted_user:PLANTED-PASSWORD-9f3@db.invalid:5432/defender"
#: What a rendered learning box's environment may hold, by name: the box layer's own (as rendered today) and the drain's one knob.
RENDERED_ALLOWED = {"DEFENDER_DIR", "PYTHONPATH", "PATH", "DEFENDER_AGENT_DIR", "DEFENDER_BOX", "DEFENDER_BOX_MEMORY", "LANG", "TZ"}
#: The product modules that build a box request, and what each request's own `env` mapping may hold.
LAUNCHERS = {"learning/author/version_control/batch.py": {"DEFENDER_AGENT_DIR"}, "box/_oracle.py": set()}


def _rendered(request) -> list[str]:
    create = _lifecycle._render_argv(request, [], "probe-token")
    return [create.argv[i + 1] for i, part in enumerate(create.argv) if part == "--env"]


def test_every_module_that_builds_a_box_request_is_a_known_launcher():
    """A new place that builds a box request must be added to the allowlist here, or this fails. (P2)"""
    found = set()
    for path in DEFENDER.rglob("*.py"):
        rel = path.relative_to(DEFENDER).as_posix()
        if rel.startswith("tests/") or "/.venv/" in f"/{rel}" or rel.startswith(".venv/"):
            continue
        if re.search(r"\bBoxRequest\(\s*name=", path.read_text(encoding="utf-8")):
            found.add(rel)
    assert found == set(LAUNCHERS)


def test_the_drain_box_environment_is_the_allowlist_whatever_the_host_holds(repo, monkeypatch):
    """With a database address planted in the host's environment the drain box's request and rendered env hold no trace of it. (P2)"""
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", PLANTED)
    monkeypatch.setenv("DATABASE_URL", PLANTED)
    d = delivery(repo, ForgeHTTP())
    request = d.start_batch("env", lanes=LANES).box_request()

    assert set(request.env) == LAUNCHERS["learning/author/version_control/batch.py"]
    rendered = _rendered(request)
    assert {e.partition("=")[0] for e in rendered} == RENDERED_ALLOWED, rendered
    blob = json.dumps(_lifecycle._render_argv(request, [], "probe-token").argv)
    assert "PLANTED-PASSWORD" not in blob
    assert "DATABASE" not in blob


def test_the_oracle_box_environment_is_the_allowlist_whatever_the_host_holds(tmp_path, monkeypatch):
    """The oracle box is handed the process environment only to size itself; none of it, a database address least, enters the box. (P2)"""
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", PLANTED)
    runner, scratch = Path(tmp_path / "runner"), Path(tmp_path / "scratch")
    runner.mkdir()
    scratch.mkdir()
    request = _oracle.oracle_box_request(scratch, runner, env={"DEFENDER_DATABASE_DSN": PLANTED, "PATH": "/usr/bin"},
                                         tenant_id="t")
    assert set(request.env) == LAUNCHERS["box/_oracle.py"]
    assert not {e for e in _rendered(request) if "DATABASE" in e or "PLANTED" in e}
    assert "PLANTED-PASSWORD" not in repr(request)
