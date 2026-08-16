"""Substrate for the issue-870 executable spec (`spec-flow/specs/spec_graph_870.yaml`).

Pre-implementation. Every mechanism below is DESIGN, not code, at the graph's `base`
(05390bad) — so the suite that imports this module is RED by construction, and that is what
a spec written before its implementation looks like.

**The seam contract this spec pins** (write-code-from-spec implements it). Names are the
code's own wherever the code already owns one; the two new ones are marked NEW.

* `lead_extraction.collect_general_failures(executed, run_dir, *, catalog_dir, catalog)` —
  signature UNCHANGED. M5′ adds ONE branch: a lead whose `query_id` is EXACTLY
  `record_query.BASH_SHIM_QUERY_ID` emits a row whose `system` is `""`, whatever the lead was
  attributed to, and that branch runs BEFORE the systemless guard at `lead_extraction.py:111`.
  The `error_class != "agent-fixable"` guard still runs FIRST, so an infra-classed reduce
  never enqueues (N9). Nothing else about the four guards moves (C22).
* `pitfalls_curator._build_pitfalls_handoffs(rows, *, systems)` — signature UNCHANGED, return
  shape CHANGED (#0, F1 settled by FK-9):
      {"surface": "system",  "system": "elastic", "path": "defender/skills/elastic/execution.md", "failures": [...]}
      {"surface": "reducer",                      "path": REDUCER_REL,                            "failures": [...]}
  `execution_md_path` is GONE from both shapes; `system` is present on the SYSTEM shape only
  (OMITTED, not `""`, on the reducer shape); AT MOST ONE reducer entry per tick; and the
  reducer entry sorts LAST, after the system entries' existing by-name order.
* `pitfalls_curator._pitfalls_path_rule(xy, path, *, systems)` — signature UNCHANGED. M7 adds
  one literal allowance for `REDUCER_REL` which **falls through** to the delete branch rather
  than returning early (FK-1): every `D`-carrying status shape still raises on that path.
* `pitfalls_curator._pitfalls_content_rule(repo_root, xy, path)` — **NEW** (FK-2), the mirror
  of `lead_author._skills_content_rule(repo_root, resolver, xy, path)`: the content half of
  the gate, composed AFTER the path half and reached through `_verify_pitfalls_state`. A
  committed edit to `REDUCER_REL` is refused unless the YAML frontmatter survives unchanged,
  every `##` heading the committed file already carried survives, and every added line lands
  under `## Common pitfalls` (created if absent). Markdown INSIDE the bullets is deliberately
  NOT sanitized — FK-2 declines that half, RE-AFFIRMED AT PHASE F ON CORRECTED GROUNDS: the
  rationale FK-2 recorded ("the same exposure every `execution.md` already carries") is FALSE,
  and FK-4 says why — this is the one file EVERY system's reduce reads before EVERY attempt,
  where an `execution.md` bullet is read only when working that system, and it is the one
  corpus target with no correspondence audit (C13, refuted) and no scaffold rule (FF-12). The
  decline stands on the ground that the same untrusted→corpus laundering already exists
  per-system and re-keying it is a round of its own; the mitigation this round DOES take is
  FK-4's prompt requirement, carried by `prompt_names_both_targets`: a reducer bullet must be
  payload-shape-scoped in its own text, so a lesson about one envelope cannot read as advice
  for every reduce.
* `pitfalls_curator.run_pitfalls(*, paths, invoke, box)` — signature UNCHANGED, three
  behaviours changed: the tick gate (FK-3, below), the curated/held/dropped partition (FK-7,
  below), and the two human-visible records (FK-6) — the operator log names the reducer
  surface on a tick that taught it, and the commit message stops saying "per-system
  execution.md" unconditionally.
* THE TICK GATE AND THE WAKE GATE, one criterion at two readers (FK-3), ADDITIVE:
  `pitfalls_curator.run_pitfalls` and `drains._has_lead_author_work` both open the lane when
  the DISTINCT count of merged records reaches the threshold — every record, systemless ones
  included, EXACTLY AS TODAY — **or** when some record whose `system` is `""` carries
  `occurrences >= threshold` on its own. FK-3 adds a disjunct; it removes nothing. That is
  what makes the one eight-times-repeated diagnosed mistake reachable (one record, count 1,
  occurrences 8) while leaving the SYSTEM lane's arrival condition untouched — a queue of two
  declared-system mistakes plus a reducer record still clears a threshold of 3 on the count
  path and still teaches both system lessons, which `merged_work_is_not_reopened` requires and
  `the_system_lanes_arrival_condition_is_unchanged` asserts.
  WHAT THE NEW DISJUNCT DOES NOT DO: it is never satisfied by silent reducer failures. PO-R2
  (executed) shows each content-less digest keys to `(system, "\\x00" + pitfall_id)`, unique
  per row, so no number of them ever carries `occurrences > 1`. The narrower encoding — a
  systemless record leaving the count entirely — was REJECTED at phase F: it would have
  silently raised the system lane's own bar, which is not FK-3's decision to make.
* THE PARTITION, ASYMMETRIC (FK-7). System rows keep `kept`-membership, unchanged. A shim row
  is curated only when a reducer handoff was emitted AND the tick's `changed` list contains
  `REDUCER_REL`; a handoff without that edit leaves its rows IN THE QUEUE — neither rotated
  nor graveyarded. Which seam carries the condition (`_split_batch_by_membership`'s input, a
  flag, or a builder-computed id set) is fork F3 and is deliberately NOT pinned: every demand
  here observes `run_pitfalls`' own outputs — the queue file, the consumed ledger, the
  deadletter — so the implementer keeps F3's choice.
* `pitfalls_curator._graveyard_dropped_rows(paths, rows, dropped_ids)` — signature UNCHANGED,
  reason string per CLASS (M9): `no-system`, `malformed-system`, `undeclared-system:<name>`,
  in place of the one false `"system not in the declared adapter set"` all three share today.
* `persist.rotate_pitfalls(..., category=...)` — the uncurated category becomes
  `consumed_unattributable` (F4).
* `drains._retire_pitfalls_batch` retires with `reason=f"batch-error:{type(e).__name__}"`
  (FK-11), the fourth and last member of the deadletter vocabulary.
* THE SHIM EXIT TRANSLATION (FK-15): an exit code the translation table does not map — a
  signal kill, 137 — must not reach the queue as an agent-fixable lesson. Whether
  `tools._shim_exit_code` or `circuit_breaker.error_class_for_exit` grows the case is the
  implementer's; the demand observes that the row does not enqueue while exit 2 and exit 1
  still do.

Project idioms this file obeys, because CI ratchets them: fakes enter through the entry
point's own injection seams (`invoke=`), never `monkeypatch.setattr`; a fake injects and
records, and classifies nothing. Faults are induced through the real primitive in the test
wherever one exists — the bytes are written, the row is appended through `append_pitfalls`,
the status shape is driven through the real rule.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from defender.learning.leads.lead_extraction import ExecutedLead
from defender.scripts.gather_tools.record_query import BASH_SHIM_QUERY_ID
from defender.tests._declared869 import (  # noqa: F401 — re-exported substrate
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

# ---------------------------------------------------------------------------------------
# THE ONE LITERAL THIS ROUND ADDS, and the shape of the document behind it.
#
# Spelled HERE rather than imported from the target: an oracle a test reads out of the code
# it is judging cannot disagree with it (`tests/_repo.plant_named_dirs`' rule). Every
# assertion below is against these literals, and `test_870_handoff.py` asserts the REAL
# committed file still matches them — so a drift in production is a red test, not a silently
# agreeing one.
# ---------------------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------------------
# The two row shapes the lane routes on.
# ---------------------------------------------------------------------------------------


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

    return [str(r["pitfall_id"]) for r in persist.read_pitfalls(paths)]


def consumed_by_id(paths) -> dict[str, dict]:
    return {str(r["pitfall_id"]): r for r in read_rows(paths.pitfalls.consumed)}


def graveyard_by_id(paths) -> dict[str, dict]:
    from defender.learning.author import drain

    return {
        str(r["pitfall_id"]): r for r in read_rows(drain.graveyard_file(paths.pitfalls))
    }
