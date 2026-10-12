"""#1120 piece 1 — the run-records lint sees the joins under a tenant's runs base (code review,
max).

The PR first read the runs base through `_tenant.runs_base_for(tenant)`, a helper returning a
bare `Path`, so the owner lint no longer knew the value came from the tenant: an unchecked
`runs_base / <name>` planted in `run_common.materialize_run` went unreported. Production code
now reads `tenant.runs`, which the lint tags where it knows the tenant — and, since #1160,
where the tenant comes from a call to an entry of `_astlib._TENANT_FACTORIES` (the one table of
functions returning a `Tenant` or `RunTenant`, same-module ones included).
"""
from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from defender.tests import _spec1077 as S
from defender.tests._by_path import load_lint_gate

_DEFENDER = Path(__file__).resolve().parents[1]

#: (the module, the line after which the join is planted, the tenant's runs base the join
#: reads, the name it appends). `materialize_run`'s `tenant` is an annotated parameter, which
#: the lint tags. The branch launcher's tenant is `_episode_tenant(...)`, which the lint
#: follows since #1160 because `defender.learning.branch.cli._episode_tenant` is an entry of
#: `_astlib._TENANT_FACTORIES`.
#: #1105 PR 2 (D7″, #1210): neither module binds `tenant.runs` any more — each takes the
#: tenant's runs repository on the anchor line — so the planted join reads the tenant's runs
#: base itself, right where the module now holds the tenant.
_SITES = [
    ("run_common.py", "            runs = tenant.runs_repository()\n", "tenant.runs", "run_id"),
    ("learning/branch/cli.py", "    runs = tenant.tenant.runs_repository()\n", "tenant.tenant.runs",
     "run_id"),
]


def _lint():
    return load_lint_gate("lint_run_records", name=f"lint_run_records_1120_{uuid.uuid4().hex}")


def _planted_join(rel: str, anchor: str, base: str, name: str) -> tuple[str, str, int]:
    """`(the real module's source, that source with one unchecked join under the tenant's runs
    base `base` planted right after `anchor`, the planted line's number)`."""
    source = (_DEFENDER / rel).read_text(encoding="utf-8")
    assert anchor in source, f"precondition: {rel} no longer holds its tenant as {anchor!r}"
    indent = anchor[: len(anchor) - len(anchor.lstrip())]
    planted = source.replace(anchor, f"{anchor}{indent}_planted = {base} / {name}\n", 1)
    return source, planted, planted[: planted.index("_planted =")].count("\n") + 1


@pytest.mark.parametrize(("rel", "anchor", "base", "name"), _SITES, ids=[s[0] for s in _SITES])
def test_a_join_planted_under_the_runs_base_is_flagged(
        tmp_path: Path, rel: str, anchor: str, base: str, name: str) -> None:
    """The real module, with one unchecked join planted right after it holds its tenant (#1105 PR 2):
    the lint reports a finding on the planted line. Control: the unplanted module adds none
    on that line."""
    source, planted, line = _planted_join(rel, anchor, base, name)
    lint = _lint()

    S.plant(tmp_path / "planted", rel, planted)
    hits = [f.display for f in lint.scan(tmp_path / "planted") if f"{rel}:{line} " in f.display]
    assert hits, f"the lint did not flag the join planted at {rel}:{line}"

    S.plant(tmp_path / "clean", rel, source)
    assert not [f.display for f in lint.scan(tmp_path / "clean") if f"{rel}:{line} " in f.display]


#: The branch launcher's source planted in another package under the same file name: another
#: module (`defender.learning.relocated_1160.cli`), whose `_episode_tenant` is no table entry.
_RELOCATED = "learning/relocated_1160/cli.py"


def test_the_branch_launchers_tenant_is_followed_through_its_table_entry(tmp_path: Path) -> None:
    """#1160 D1 / D2: the lint follows `_episode_tenant(...)` because its origin — the gate
    names each scanned module `defender.` + its path — is an entry of `_TENANT_FACTORIES`, not
    because the def is annotated `-> RunTenant`. The same planted source in one tree at the
    real path and at `_RELOCATED`: the join at the real path is flagged, the one at the
    relocated path is not."""
    rel, anchor, base, name = _SITES[1]
    _, planted, line = _planted_join(rel, anchor, base, name)
    S.plant(tmp_path, rel, planted)
    S.plant(tmp_path, _RELOCATED, planted)
    displays = [f.display for f in _lint().scan(tmp_path)]
    assert [d for d in displays if d.startswith(f"{rel}:{line} ")], (
        f"the lint did not flag the join planted at {rel}:{line}")
    relocated = [d for d in displays if d.startswith(f"{_RELOCATED}:{line} ")]
    assert relocated == [], (
        "a same-named def in another module is followed as the tabled `_episode_tenant`: "
        f"{relocated}")
