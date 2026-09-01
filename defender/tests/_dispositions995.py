"""Fixtures and the pre-implementation import shim for #995's verb-disposition table.

Pre-implementation. `defender.runtime.verb_dispositions` does NOT exist at the base commit,
so every symbol below resolves to a stub that raises on CALL rather than on IMPORT — the
suite collects, and each test fails with the name it wanted instead of the whole file
erroring at collection and hiding how many demands there are.

WHAT #995 ADDS

* `defender/runtime/verb_dispositions.py` — NEW. The one authored table of who may call
  what, loaded from a per-deployment YAML file. Owns three things and nothing else:

  - `load_dispositions(path) -> tuple[Disposition, ...]` — parse + VALIDATE. Every
    malformed shape raises `DispositionError`; nothing degrades to a partial table, and
    nothing degrades to an empty one (an empty table is the deny-all that #995 exists to
    stop happening by accident).
  - `grant_for(role, dispositions) -> VerbGrant` — the per-role projection. The returned
    type is the UNCHANGED `VerbGrant`, so everything downstream of it is untouched.
  - `census_gaps(walked, dispositions) -> CensusGaps` — PURE. Takes the walked census as an
    argument rather than resolving it, because resolving it reads the committed tree through
    git and this module is imported at runtime startup, where git must not run.

* `defender/knowledge/environment/verb-grants.yaml` — NEW. The table itself, per-deployment
  config rather than a Python literal in the shipped runtime.

* `scripts/lint/lint_verb_disposition_census.py` — NEW. Wires the resolver's walk to
  `census_gaps` and fails CI on residue in either direction.

THE ORACLE THIS SUITE IS BUILT AGAINST

The defect being closed is that a system can be connected and silently ungranted, and that
the thing which LOOKS like it guards the grant compares two hand-written copies and so
cannot see the case. So the discriminating tests here are the ones that PLANT a system the
table does not mention and demand the gate go red. A test that only reads the shipped tree
would pass against the broken world too — the shipped tree is currently complete by luck,
not by construction.

Assertions are made against what the test PLANTED, never against a second reading of the
tree with the same walker the code uses (`scripts/lint/lint_shared_oracle.py` refuses that
shape at the gate, and #869 shipped three misreads behind it).
"""
from __future__ import annotations

import textwrap
from pathlib import Path
from typing import Any

from defender.tests._repo import seed_repo

try:
    from defender.runtime.verb_dispositions import (  # type: ignore[import-not-found]
        CensusGaps,
        Disposition,
        DispositionError,
        census_gaps,
        dispositions_path,
        grant_for,
        load_dispositions,
    )
except ImportError:  # pragma: no cover — the pre-implementation path

    class DispositionError(Exception):  # type: ignore[no-redef]
        """Placeholder so `pytest.raises(DispositionError)` is expressible before the real
        exception exists. Nothing raises it, so every such test fails rather than passing
        vacuously on a stub that happens to raise."""

    def _not_yet_written(symbol: str):
        def _stub(*_a: Any, **_k: Any):
            raise AssertionError(
                f"defender.runtime.verb_dispositions.{symbol} does not exist yet — "
                "#995 is unimplemented at this commit."
            )
        return _stub

    CensusGaps = _not_yet_written("CensusGaps")  # type: ignore[assignment]
    Disposition = _not_yet_written("Disposition")  # type: ignore[assignment]
    census_gaps = _not_yet_written("census_gaps")  # type: ignore[assignment]
    dispositions_path = _not_yet_written("dispositions_path")  # type: ignore[assignment]
    grant_for = _not_yet_written("grant_for")  # type: ignore[assignment]
    load_dispositions = _not_yet_written("load_dispositions")  # type: ignore[assignment]


__all__ = [
    "CensusGaps",
    "Disposition",
    "DispositionError",
    "GATHER_CENSUS",
    "JUDGE_CENSUS",
    "WITHHELD_CENSUS",
    "census_gaps",
    "dispositions_path",
    "grant_for",
    "load_dispositions",
    "plant_system",
    "write_table",
]


# ---------------------------------------------------------------------------------------
# The census, written INDEPENDENTLY of the shipped table.
#
# These three tuples are transcribed from the grants as they stood BEFORE #995 moved them
# out of code (`driver/_build.py:GATHER_PAIRS` plus its per-system health-check, and
# the judge's inline `JUDGE_TICKET_PAIRS` tuple, since retired), so the suite can assert
# that moving the table to config changed WHO MAY CALL WHAT not at all. Held as literals for
# the same reason `_verb_authorization_632.py` holds its copy: an expected value re-derived
# from the file under test cannot disagree with it.
#
# `health-check` is enumerated per system here rather than granted uniformly in code. That is
# a real change and it is deliberate — a table that is total over the walked census cannot
# have a verb class that lives outside it, and the uniform grant was the one pair the old
# code decided for itself.
# ---------------------------------------------------------------------------------------

_GATHER_READ: tuple[tuple[str, str], ...] = (
    ("change-mgmt", "active-changes"), ("change-mgmt", "get-change"),
    ("change-mgmt", "list-changes"),
    ("cmdb", "get-host"), ("cmdb", "list-hosts"),
    ("elastic", "alerts"), ("elastic", "esql"), ("elastic", "query"),
    ("host-state", "authorized-keys"), ("host-state", "container-inspect"),
    ("host-state", "fim-checksum"), ("host-state", "package-list"),
    ("host-state", "passwd"), ("host-state", "proc-tree"),
    ("identity", "can-access"), ("identity", "get-user"), ("identity", "list-roles"),
    ("identity", "list-users"),
    ("tacit-knowledge", "lookup"),
    ("threat-intel", "list-indicators"), ("threat-intel", "lookup"),
    ("ticket", "list-tickets"),
)

#: The eight systems gather reaches, and so the eight `health-check` pairs it holds.
_GATHER_SYSTEMS: tuple[str, ...] = tuple(sorted({s for s, _ in _GATHER_READ}))

GATHER_CENSUS: frozenset[tuple[str, str]] = frozenset(
    (*_GATHER_READ, *((s, "health-check") for s in _GATHER_SYSTEMS))
)

JUDGE_CENSUS: frozenset[tuple[str, str]] = frozenset((
    ("ticket", "get-ticket"), ("ticket", "key-pattern"), ("ticket", "list-tickets"),
))

#: Declared by an adapter and granted to NOBODY. Each needs a written reason in the table;
#: `ticket.case-opened-at` is the one the old code never named at all — it was ungranted by
#: omission, which is precisely the state #995 makes unrepresentable.
WITHHELD_CENSUS: frozenset[tuple[str, str]] = frozenset((
    ("cmdb", "list-roles"),
    ("identity", "list-authorized-hosts"),
    ("ticket", "case-opened-at"),
))


# ---------------------------------------------------------------------------------------
# Planting helpers. Everything a gate test asserts on is planted by these and returned, so
# the expected value is the input rather than a re-read.
# ---------------------------------------------------------------------------------------

_STUB_ADAPTER = '''\
from __future__ import annotations

from defender.runtime.verbs import VerbContext, verb


@verb()
def {body}(ctx: VerbContext) -> dict:
    return {{"ok": True}}


@verb()
def health_check(ctx: VerbContext) -> dict:
    return {{"ok": True}}


VERBS = {{"{name}": {body}, "health-check": health_check}}
'''


def plant_system(defender_dir: Path, system: str, verb_name: str = "lookup") -> tuple[str, str]:
    """Declare `system` in `defender_dir` by BOTH halves the resolver reads — an adapter
    module and a committed `execution.md` marker — and return the `(system, verb)` pair the
    caller will assert on.

    Both halves, not one: the resolver unions them, so a fixture that plants only an adapter
    would still exercise the gate but would not resemble what `/connect` actually produces,
    and a fixture that plants only a marker declares nothing until it is committed.
    """
    adapters = defender_dir / "scripts" / "adapters"
    adapters.mkdir(parents=True, exist_ok=True)
    (adapters / f"{system.replace('-', '_')}_adapter.py").write_text(
        _STUB_ADAPTER.format(name=verb_name, body=verb_name.replace("-", "_")),
        encoding="utf-8",
    )
    skill = defender_dir / "skills" / system
    skill.mkdir(parents=True, exist_ok=True)
    (skill / "execution.md").write_text(f"# {system}\n", encoding="utf-8")
    return (system, verb_name)


def write_table(path: Path, rows: dict[tuple[str, str], dict[str, Any]]) -> Path:
    """Write a disposition table holding exactly `rows`, keyed `(system, verb)`.

    Values are the row body verbatim (`{"roles": [...], "reason": ...}`), so a test can build
    a malformed row — a missing `roles`, an unknown role, a reasonless withholding — without
    the helper quietly repairing it. A helper that normalized its input could not express the
    inputs half this suite is about.
    """
    by_system: dict[str, dict[str, dict[str, Any]]] = {}
    for (system, verb_name), body in rows.items():
        by_system.setdefault(system, {})[verb_name] = body
    lines = ["dispositions:"]
    for system in sorted(by_system):
        lines.append(f"  {system}:")
        for verb_name in sorted(by_system[system]):
            body = by_system[system][verb_name]
            parts = []
            if "roles" in body:
                roles = body["roles"]
                rendered = (
                    "[" + ", ".join(str(r) for r in roles) + "]"
                    if isinstance(roles, list) else str(roles)
                )
                parts.append(f"roles: {rendered}")
            if "reason" in body:
                parts.append(f'reason: "{body["reason"]}"')
            lines.append(f"    {verb_name}: {{{', '.join(parts)}}}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def planted_tree(tmp_path: Path, systems: dict[str, str]) -> Path:
    """A committed synthetic repo whose defender tree declares exactly `systems`
    (name -> verb). Returns the repo root."""
    repo = tmp_path / "repo"
    defender_dir = repo / "defender"
    defender_dir.mkdir(parents=True, exist_ok=True)
    for system, verb_name in systems.items():
        plant_system(defender_dir, system, verb_name)
    seed_repo(repo)
    return repo


def table_text(body: str) -> str:
    """Dedent a literal table written inline in a test."""
    return textwrap.dedent(body)
