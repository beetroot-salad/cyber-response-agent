"""Fixtures and the independent census for #995's verb-disposition table."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from defender._paths import adapters_under
from defender.tests.support.shared.contracts._repo import seed_repo

try:
    from defender.systems.verb_dispositions import (  # type: ignore[import-not-found]
        CensusGaps,
        Disposition,
        DispositionError,
        DispositionWarning,
        census_gaps,
        dispositions_path,
        grant_for,
        load_dispositions,
    )
except ImportError:  # pragma: no cover — the pre-implementation path

    class DispositionError(Exception):  # type: ignore[no-redef]
        """Placeholder nothing raises, so a test using it fails rather than passing vacuously."""

    class DispositionWarning(UserWarning):  # type: ignore[no-redef]
        """Placeholder nothing emits, for the same reason."""

    def _not_yet_written(symbol: str):
        def _stub(*_a: Any, **_k: Any):
            raise AssertionError(
                f"defender.systems.verb_dispositions.{symbol} does not exist yet — "
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
    "DispositionWarning",
    "CORRELATION_CENSUS",
    "GATHER_CENSUS",
    "JUDGE_CENSUS",
    "WITHHELD_CENSUS",
    "census_gaps",
    "dispositions_path",
    "grant_for",
    "load_dispositions",
    "plant_system",
    "planted_tree",
    "write_table",
]


# ---------------------------------------------------------------------------------------
# The census, written INDEPENDENTLY of the shipped table: the grants as they stood in code
# before #995/#999 moved them into it, so the suite can assert the move changed WHO MAY CALL
# WHAT not at all. Literals, because an expected value re-derived from the file under test
# cannot disagree with it. `health-check` is listed per system: a table total over the census
# has no verb class outside it.
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

#: Empty since the judge role was retired (#922): the verbs one role holds alone.
JUDGE_CENSUS: frozenset[tuple[str, str]] = frozenset()

#: The turn-zero correlation lead's grant as `lead_zero/_spec.py` held it before #999: two
#: pairs on one system, the whole safety case for a lead the harness dispatches on its own.
CORRELATION_CENSUS: frozenset[tuple[str, str]] = frozenset((
    ("elastic", "alerts"), ("elastic", "health-check"),
))

#: Declared by an adapter and granted to NOBODY; each needs a written reason in the table.
#: `get-ticket` and `key-pattern` were the retired judge's (#922): their rows stay with
#: `roles: []`, a recorded decision rather than ungranted by omission.
WITHHELD_CENSUS: frozenset[tuple[str, str]] = frozenset((
    ("cmdb", "list-roles"),
    ("identity", "list-authorized-hosts"),
    ("ticket", "case-opened-at"),
    ("ticket", "get-ticket"),
    ("ticket", "key-pattern"),
))


# ---------------------------------------------------------------------------------------
# Planting helpers. Everything a gate test asserts on is planted by these and returned, so
# the expected value is the input rather than a re-read.
# ---------------------------------------------------------------------------------------

_STUB_ADAPTER = '''\
from __future__ import annotations

from defender.kit.verbs import VerbContext, verb


@verb()
def {body}(ctx: VerbContext) -> dict:
    return {{"ok": True}}


@verb()
def health_check(ctx: VerbContext) -> dict:
    return {{"ok": True}}


VERBS = {{"{name}": {body}, "health-check": health_check}}
'''


def plant_system(defender_dir: Path, system: str, verb_name: str = "lookup") -> tuple[str, str]:
    """Declare `system` in `defender_dir` by BOTH halves the resolver unions — an adapter
    module and an `execution.md` marker, as `/connect` produces them — and return the
    `(system, verb)` pair the caller will assert on."""
    adapters = adapters_under(defender_dir)
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

    Row bodies are written verbatim, so a test can build a malformed row (a missing `roles`,
    an unknown role, a reasonless withholding) without the helper repairing it.
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
                # A JSON string is a valid YAML double-quoted scalar, so a reason holding `"`
                # or `\\` reaches the loader as the test wrote it.
                parts.append(f"reason: {json.dumps(body['reason'])}")
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
