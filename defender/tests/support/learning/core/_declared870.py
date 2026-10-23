"""Substrate for the issue-870 executable spec (`docs/archive/spec-graphs/spec_graph_870.yaml`)."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

from pathlib import Path
from typing import Any

from defender.learning.core.state import PITFALLS
from defender.learning.leads.lead_extraction import ExecutedLead
from defender.knowledge._query_rules import BASH_SHIM_QUERY_ID
from defender.tests.support.runtime.engine._declared869 import (  # noqa: F401 — re-exported substrate
    ADAPTERS_REL,
    CATALOG_REL,
    SKILLS_REL,
    Spawn,
    commit_all,
    git,
    head_files,
    log_lines_naming,
    loop_log,
    marker_file,
    pitfall_row,
    read_rows,
    seed_tree,
    skill_md,
    write,
    write_marker,
)

# THE ONE LITERAL THIS ROUND ADDS, and the shape of the document behind it.
#
# Spelled HERE rather than imported from the target: an oracle a test reads out of the code
# it is judging cannot disagree with it (`tests/_repo.plant_named_dirs`' rule). Every
# assertion below is against these literals, and `test_870_handoff.py` asserts the REAL
# committed file still matches them — so a drift in production is a red test, not a silently
# agreeing one.

#: The reducer surface — `defender/skills/gather/defender-sql.md`, repo-relative, the exact
#: spelling `_pitfalls_path_rule` compares and `commit_corpus` stages.
REDUCER_REL = "defender/skills/gather/defender-sql.md"

#: The three `##` sections the committed file carries at this base (FF-12), verbatim. FK-2's
#: content rule keeps all three across a curator edit.
REDUCER_HEADINGS: tuple[str, ...] = (
    "## The payload becomes the table",
    "## The binding each shape needs",
    "## Results that lie",
)

#: The file's YAML frontmatter keys. The file has one today and no scaffold rule anywhere
#: requires it (FF-12) — FK-2's content rule is the first thing that does.
REDUCER_FRONTMATTER_KEYS: tuple[str, ...] = ("name", "description")

#: The section curator additions land in — created if absent, which it is today.
PITFALLS_SECTION = "## Common pitfalls"

#: The two-character `git status --porcelain` shapes FK-1 closes the round over. `_git.
#: git_status` hands the rule whatever it emits, and M7's own text enumerates none of them.
STATUS_SHAPES: tuple[str, ...] = ("M ", " M", "MM", "D ", " D", "R ", "RM", "??")

#: The shapes that carry a `D`, i.e. the ones the delete branch must still refuse ON THE NEW
#: PATH. That it is a subset of STATUS_SHAPES rather than a second list is the point: the
#: rule's verdict over the WHOLE alphabet is the demand, not two hand-picked members.
DELETING_SHAPES: tuple[str, ...] = ("D ", " D")

#: l-003's real diagnosis in `reviewer-measure-0807-b` — one unchanging `Binder Error` under
#: eight varied attempts. The round's motivating incident, and the digest that makes N rows
#: ONE record with `occurrences: N` (C8/C17, executed).
BINDER = "exit=1; Binder Error: No function matches unnest(JSON) - candidates: unnest(LIST)"


def reducer_surface_text(*, bullets: tuple[str, ...] = ()) -> str:
    """The reducer surface as it stands at this base, optionally curated.

    A WRITER, never an oracle: the frontmatter block and the three sections are the shape the
    content rule protects, and `bullets` is what a compliant curator adds — appended under
    `## Common pitfalls`, which the file does not have until the first one lands.
    """
    body = (
        "---\n"
        "name: defender-gather-sql\n"
        "description: The defender-sql quirks that cost a query.\n"
        "---\n\n"
        "# defender-sql\n\n"
        f"{REDUCER_HEADINGS[0]}\n\nThe payload arrives as `data`.\n\n"
        f"{REDUCER_HEADINGS[1]}\n\nUnnest takes a LIST.\n\n"
        f"{REDUCER_HEADINGS[2]}\n\nA count over a truncated payload lies.\n"
    )
    if bullets:
        body += f"\n{PITFALLS_SECTION}\n\n" + "".join(f"- {b}\n" for b in bullets)
    return body


def write_reducer_surface(repo: Path, *, bullets: tuple[str, ...] = ()) -> Path:
    """Plant the reducer surface in a seeded tree. Returns the absolute path."""
    return write(repo / REDUCER_REL, reducer_surface_text(bullets=bullets))


def curate_reducer_surface(bullet: str = "keep the unnest argument a LIST"):
    """The edit a COMPLIANT curator makes: one bullet appended under `## Common pitfalls`.

    Returned as a `Spawn` edit callable, so a test hands it to the entry point's own `invoke=`
    seam and the real file is really written into the real worktree before the real gate runs.
    """

    def _edit(root: Path) -> None:
        path = root / REDUCER_REL
        text = path.read_text(encoding="utf-8") if path.is_file() else reducer_surface_text()
        if PITFALLS_SECTION not in text:
            text = text.rstrip("\n") + f"\n\n{PITFALLS_SECTION}\n\n"
        write(path, text.rstrip("\n") + f"\n- {bullet}\n")

    return _edit


def curate_execution_md(system: str, bullet: str = "use the key, not the id"):
    """The system-lane edit, for the mixed batches: one bullet in `<system>/execution.md`."""

    def _edit(root: Path) -> None:
        write_marker(
            root, system,
            body=f"# {system}\n\n{PITFALLS_SECTION}\n\n- {bullet}\n",
        )

    return _edit


def edits(*fns):
    """Compose curator edits, so one spawn can teach both surfaces on one tick."""

    def _edit(root: Path) -> None:
        for fn in fns:
            fn(root)

    return _edit


# The two row shapes the lane routes on.


def shim_lead(
    *,
    sql: str = "SELECT unnest(data)",
    system: str = "elastic",
    digest: str = BINDER,
    query_index: int = 0,
    lead_id: str = "l-003",
    error_class: str | None = "agent-fixable",
    query_id: str = BASH_SHIM_QUERY_ID,
) -> ExecutedLead:
    """One failing terminal reduce, as the offline extraction sees it.

    `query_id` defaults to the sentinel and is a parameter because the whole of U3 is that the
    routing key is EQUALITY with that value — the near-miss and the other two sentinels are
    driven through this same builder so they differ from the positive case in one field.
    """
    return ExecutedLead(
        lead_id=lead_id, query_index=query_index, is_multi_query=True, entry_index=0,
        query_id=query_id, system=system, verb="bash",
        params={"command": f"cat gather_raw/{lead_id}/0.json | defender-sql '{sql}'"},
        raw_command=f"defender-sql '{sql}'", goal_text="reduce the elastic envelope",
        what_to_summarize=("auth events",), raw_ref=None, payload_status="error",
        payload_digest=digest, error_class=error_class,
        is_sentinel=query_id.startswith("∅."),
    )


def shim_row(pid: str, *, digest: str = BINDER, system: str = "", **extra: Any) -> dict:
    """One QUEUED reducer row — post-M5′, so its `system` is `""` and its `query_id` is the
    sentinel. The queue is a real file and these go into it through `append_pitfalls`."""
    return {
        "schema_version": 1,
        "pitfall_id": pid,
        "source_run": pid.split(":")[0],
        "system": system,
        "query_id": BASH_SHIM_QUERY_ID,
        "goal": "reduce the elastic envelope",
        "executed_query": "verb: bash\nparams:\n  command: cat 0.json | defender-sql 'SELECT 1'",
        "stderr_digest": digest,
        "error_class": "agent-fixable",
        **extra,
    }


def silent_shim_row(pid: str, **extra: Any) -> dict:
    """A CONTENT-LESS reducer row: the adapter's `exit=N; ` envelope and nothing else.

    PO-R2 (executed) established what this is worth — `pitfall_key` sends it to
    `(system, "\\x00" + pitfall_id)`, unique per row, so it merges with nothing and can never
    carry `occurrences > 1`. It is the negative arm of FK-3's new gate.
    """
    return shim_row(pid, digest="exit=1; ", **extra)


def by_surface(handoffs: list[dict]) -> dict[str, list[dict]]:
    """The handoff list, indexed by its discriminator.

    Both legal values are seeded and `surface` is read with `.get`, so a build that never grew
    the key fails on the assertion the demand actually makes — "there is no reducer entry" —
    rather than on a `KeyError` in the helper, which reads as a broken test rather than as an
    unmet demand.
    """
    out: dict[str, list[dict]] = {"system": [], "reducer": []}
    for entry in handoffs:
        out.setdefault(str(entry.get("surface")), []).append(entry)
    return out


def queue_ids(paths) -> list[str]:
    """The ids still pending, in file order — the observable FK-7's held rows live in."""
    from defender.learning.core import persist
    from defender.tests.support.learning.core import _state1135

    return [str(r["pitfall_id"]) for r in persist.read_pitfalls(_state1135.state_for_paths(paths))]


def consumed_by_id(paths) -> dict[str, dict]:
    return {str(r["pitfall_id"]): r for r in read_rows(location_path(paths.state_root) / PITFALLS.consumed)}


def graveyard_by_id(paths) -> dict[str, dict]:
    return {
        str(r["pitfall_id"]): r
        for r in read_rows(location_path(paths.state_root) / PITFALLS.deadletter)
    }
