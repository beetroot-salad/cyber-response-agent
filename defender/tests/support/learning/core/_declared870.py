"""Shared literals and builders for the #870 pitfalls-lane tests (no tests here)."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from defender.learning.leads.lead_extraction import ExecutedLead
from defender.knowledge._query_rules import BASH_SHIM_QUERY_ID
from defender.learning.core.state import PITFALLS
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.runtime.engine._declared869 import (  # noqa: F401 — re-exported substrate
    Spawn,
    seed_agent_files,
    seed_product,
    write_agent_marker,
    commit_all,
    pitfall_row,
    read_rows,
    seed_tree,
    write,
    write_marker,
)

# The literals the tests assert against, spelled HERE rather than imported from the target: an
# oracle read out of the code it judges cannot disagree with it. `test_reducer_queue.py` asserts
# the real committed file still matches them.

#: The reducer surface the pitfalls lane writes: the tenant's add-on page, repo-relative in the
#: tenant repo, as `_pitfalls_path_rule` compares it and the batch's change set carries (#1108 P4).
REDUCER_REL = "agent/skills/gather/defender-sql.pitfalls.md"

#: The product reducer page. No tenant write touches it: the lane's path rule refuses it, and it
#: carries no `## Common pitfalls`.
PRODUCT_REDUCER_REL = "defender/skills/gather/defender-sql.md"

#: Three `##` sections a human wrote in the add-on, verbatim; the content rule keeps all three
#: across an edit.
REDUCER_HEADINGS: tuple[str, ...] = (
    "## The payload becomes the table",
    "## The binding each shape needs",
    "## Results that lie",
)

#: The file's YAML frontmatter keys, which only the content rule requires.
REDUCER_FRONTMATTER_KEYS: tuple[str, ...] = ("name", "description")

#: The section curator additions land in, created if absent (as in the planted file).
PITFALLS_SECTION = "## Common pitfalls"

#: The two-character `git status --porcelain` shapes the path rule is checked over
#: (`git_status` hands it whatever git emits).
STATUS_SHAPES: tuple[str, ...] = ("M ", " M", "MM", "D ", " D", "R ", "RM", "??")

#: The shapes carrying a `D`, which the delete branch must refuse ON THE NEW PATH. A subset of
#: `STATUS_SHAPES`, not a second list: the demand is the verdict over the WHOLE alphabet.
DELETING_SHAPES: tuple[str, ...] = ("D ", " D")

#: A real diagnosis (one unchanging `Binder Error` under eight varied attempts): the digest that
#: makes N rows ONE record with `occurrences: N`.
BINDER = "exit=1; Binder Error: No function matches unnest(JSON) - candidates: unnest(LIST)"


def reducer_surface_text(*, bullets: tuple[str, ...] = ()) -> str:
    """The reducer surface as planted, optionally curated. A WRITER, never an oracle: `bullets`
    are what a compliant curator appends under `## Common pitfalls`.
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
    """The edit a COMPLIANT curator makes: one bullet appended under `## Common pitfalls`, as a
    `Spawn` edit callable for the entry point's `invoke=` seam, so the real file is written into
    the real worktree before the real gate runs.
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


def curate_agent_execution_md(system: str, bullet: str = "use the key, not the id"):
    """`curate_execution_md` in a tenant repo or draft: `agent/skills/<system>/execution.md`."""

    def _edit(root: Path) -> None:
        write_agent_marker(
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

    `query_id` is a parameter because routing is EQUALITY with the sentinel: the near-miss and
    the other sentinels differ from the positive case in this one field.
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
    """One QUEUED reducer row: `system` is `""` and `query_id` is the sentinel. Tests append it
    to the real queue file through `append_pitfalls`."""
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
    `pitfall_key` keys it per row, so it merges with nothing and never reaches `occurrences > 1`.
    """
    return shim_row(pid, digest="exit=1; ", **extra)


def by_surface(handoffs: list[dict]) -> dict[str, list[dict]]:
    """The handoff list, indexed by `surface`. Both legal values are seeded and the key read
    with `.get`, so a build without it fails the demand's own assertion, not a `KeyError` here.
    """
    out: dict[str, list[dict]] = {"system": [], "reducer": []}
    for entry in handoffs:
        out.setdefault(str(entry.get("surface")), []).append(entry)
    return out


class Claim:
    """The pitfalls a tick's claim holds: rows are added as the claim's items, and each tick reports back what it decided
    (`outcomes`, and the `PitfallsDisposition`s `on_curated` hands back)."""

    def __init__(self) -> None:
        self.rows: list[dict] = []
        self.outcomes: dict = {}
        self.curated: list = []

    def add(self, *rows: dict) -> list[str]:
        self.rows.extend(rows)
        return [r["pitfall_id"] for r in rows]

    def items(self) -> list[tuple[str, str, dict]]:
        return [("pitfall", r["pitfall_id"], r) for r in self.rows]

    @property
    def committed(self) -> set[str]:
        return {i for d in self.curated for i in d.committed_ids}


def tick(lane, spawn, claim: Claim) -> int:
    """One real pitfalls tick over the batch draft `lane`, handed the claim's items; it reports into `claim`."""
    from defender.learning.leads import pitfalls_curator
    from defender.tests.support.learning.curation import _curator1134 as C

    claim.curated.clear()
    return pitfalls_curator.run_pitfalls(
        paths=lane.paths, trees=C.draft_trees(lane), batch=lane.batch, invoke=spawn,
        items=claim.items(), outcomes=claim.outcomes, on_curated=claim.curated.append)


def queue_pitfalls(w, *rows: dict) -> None:
    """File each row as a pitfall item of the world's tenant (`add_pitfall`: one row per occurrence)."""
    from defender.tests.support.learning.core._store1278 import call

    for row in rows:
        call(w.dsn, "add_pitfall", w.t.tenant_id, row)


def pitfall_items(w) -> dict[str, Any]:
    """The tenant's pitfall items by key (status, reason, attempts on each)."""
    from defender.tests.support.learning.core._store1278 import call

    return {i.key: i for i in call(w.dsn, "work", w.t.tenant_id) if i.kind == "pitfall"}


def lead_wakes(w) -> bool:
    """Whether the lead lane's wake gate (the store's claim rule at the env thresholds) finds work for the world's tenant."""
    from defender.learning.core.store_tick import LEAD_LANE, lane_waiting
    from defender.learning.store import blocking

    with blocking(w.dsn) as store:
        return lane_waiting(store, w.t.tenant_id, LEAD_LANE)


def queue_ids(paths) -> list[str]:
    """The ids still pending, in file order (where held rows stay)."""
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
