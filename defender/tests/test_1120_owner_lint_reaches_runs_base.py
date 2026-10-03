"""#1120 piece 1 — the run-records lint sees the joins under a tenant's runs base (code review,
max).

The PR first read the runs base through `_tenant.runs_base_for(tenant)`, a helper returning a
bare `Path`, so the owner lint no longer knew the value came from the tenant: an unchecked
`runs_base / <name>` planted in `run_common.materialize_run` went unreported. Production code
now reads `tenant.runs`, which the lint tags where it knows the tenant (#1160 covers the
sites whose tenant comes from a local factory).
"""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from defender.tests import _spec1077 as S
from defender.tests._by_path import load_lint_gate

_DEFENDER = Path(__file__).resolve().parents[1]

#: (the module, the line its runs base is bound on, the name the planted join appends).
#: `materialize_run`'s `tenant` is an annotated parameter, which the lint tags. The launcher's
#: tenant comes from a local factory it does not follow yet (#1160).
_SITES = [
    ("run_common.py", "        runs_base = tenant.runs\n", "run_id"),
]


@pytest.mark.parametrize(("rel", "anchor", "name"), _SITES, ids=[s[0] for s in _SITES])
def test_a_join_planted_under_the_runs_base_is_flagged(
        tmp_path: Path, rel: str, anchor: str, name: str) -> None:
    """The real module, with one unchecked join planted right after its runs base is bound:
    the lint reports a finding on the planted line. Control: the unplanted module adds none
    on that line."""
    source = (_DEFENDER / rel).read_text(encoding="utf-8")
    assert anchor in source, f"precondition: {rel} no longer binds its runs base as {anchor!r}"
    base = anchor.split("=")[0].strip()
    indent = anchor[: len(anchor) - len(anchor.lstrip())]
    planted = source.replace(anchor, f"{anchor}{indent}_planted = {base} / {name}\n", 1)
    line = planted[: planted.index("_planted =")].count("\n") + 1
    lint = load_lint_gate("lint_run_records", name=f"lint_run_records_1120_{uuid.uuid4().hex}")

    S.plant(tmp_path / "planted", rel, planted)
    hits = [f.display for f in lint.scan(tmp_path / "planted") if f"{rel}:{line} " in f.display]
    assert hits, f"the lint did not flag the join planted at {rel}:{line}"

    S.plant(tmp_path / "clean", rel, source)
    assert not [f.display for f in lint.scan(tmp_path / "clean") if f"{rel}:{line} " in f.display]
