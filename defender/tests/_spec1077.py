"""Shared machinery for #1077's run-handle spec — NO test scripts.

The change (`spec-flow/specs/spec_graph_1077.yaml`, `70-resolutions.md`): no module outside
the name owners spells a run or episode record's name. `defender/_run_paths.py::RunPaths` grows
from seven accessors to ~twenty, a new `defender/_episode_paths.py::EpisodePaths` owns the
episode layout, a new `defender/_tenant.py` owns `<runs_base>/_tenant.json`, and a new handle
module wraps all three: `Run` with five sub-collections (`tables`, `facts`, `documents`,
`observability`, `session`), a `RunRecord` value object at `run.record`, and a per-kind
`RecordHandle` every record accessor answers.

NONE of it exists at base db1af01a. Every import goes through `mod()` PER CALL (the
`_triplet_947` / `_record_1049` idiom) so a missing module is ONE failure per test rather than
a collection error that hides every other assertion in the file.

COINED NAMES LIVE HERE AND NOWHERE ELSE. `70-resolutions.md` decision 1c names no type for the
wrapper and decision 1b says "`run.record` (or similar)", so `RecordHandle`, `RunRecord`, the
handle module's path and the `_tenant` / `_episode_paths` entry points are this suite's
coinage (spec_graph_1077 `handoff.deviations`, "A COINED ID"). They are gathered in this one
module so write-code-from-spec can RENAME the graph, this file and nothing else — never add a
`conceptAliases` entry, which silently disables `check_binds`' prose-not-in-binds scan for the
concept.

EVERY FAULT HERE IS A REAL INPUT THROUGH THE REAL PRIMITIVE unless a fake is named below: the
malformed tenant records, the traversal-shaped components, the colliding run ids, the
non-regular file squatting a record's path and the planted directory trees are written to the
filesystem by these helpers and re-probed on every run. Two fakes exist, both entering through
an injection seam and never `monkeypatch.setattr` (`scripts/lint/lint_monkeypatch.py`):

* `RecordingIo` — a pass-through recorder over the real `defender._io` that injects a fault
  only where a `IoFault` says to. Its fault content cites the ledger: `write_guarded`'s
  `OSError` carrying the alias marker on a non-plain target and its `FileExistsError` on the
  `O_CREAT|O_EXCL|O_NOFOLLOW` staging collision are claim C19's observed behaviour of the real
  `_io.py:818-822`, not an author's guess at what a write failure looks like.
* `ProbeDocker` — a fake `DockerFn` for the alias-ban probe. `docker exec` is the one
  dependency in this spec that is too expensive and too nondeterministic to drive for a
  timeout, and the two faults it injects cite the real seam: `subprocess.TimeoutExpired` is
  what `runtime/box/_docker.py`'s fixed `timeout=120` raises, and the malformed result is the
  probe's own `_CONTROL_FAILED_MARKER` path (claim C3 / claim C14, which observed the probe on
  the real sandbox).

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import subprocess
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import pytest

from defender.tests import _triplet_947 as T

mod = T.mod
sym = T.sym

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
KINDS_TSV = DEFENDER / "docs" / "run-records-kinds.tsv"
SITES_TSV = DEFENDER / "docs" / "run-records.tsv"
PAGE = DEFENDER / "docs" / "run-records.md"

NOT_ROOT = pytest.mark.skipif(
    os.geteuid() == 0, reason="root ignores permission bits — CI runs non-root (defender/CLAUDE.md)")


# ======================================================================================
# The coined module names. ONE place, so a rename is one edit.
# ======================================================================================

#: The handle module. D6(a)'s exempt owner set is `_run_paths.py`, `_episode_paths.py`,
#: `_tenant.py` and "the handle"; the other three are underscore-prefixed private modules
#: beside `_io.py` and `_provenance.py`, so the handle follows the same convention.
HANDLE_MODULE = "_run_handle"
TENANT_MODULE = "_tenant"
EPISODE_MODULE = "_episode_paths"
OWNER_MODULE_FILES = (
    "_run_paths.py", "_episode_paths.py", "_tenant.py", f"{HANDLE_MODULE}.py")


def handle() -> Any:
    """`defender/_run_handle.py` — `Run`, `RunRecord`, `RecordHandle`, `ArchivedWorld`."""
    return mod(HANDLE_MODULE)


def tenant() -> Any:
    """`defender/_tenant.py` — the tenant record's owner (D2)."""
    return mod(TENANT_MODULE)


def episode_paths() -> Any:
    """`defender/_episode_paths.py::EpisodePaths` — the episode layout's owner (D1)."""
    return mod(EPISODE_MODULE)


def run_paths_mod() -> Any:
    return mod("_run_paths")


def RunPaths(run_dir: Path) -> Any:  # noqa: N802 — it is the class's own name
    return run_paths_mod().RunPaths(run_dir)


def EpisodePaths(episode_dir: Path) -> Any:  # noqa: N802
    return episode_paths().EpisodePaths(episode_dir)


def Run() -> Any:  # noqa: N802
    return handle().Run


def ArchivedWorld() -> Any:  # noqa: N802
    return handle().ArchivedWorld


def RecordHandle() -> Any:  # noqa: N802
    return handle().RecordHandle


def RunRecord() -> Any:  # noqa: N802
    return handle().RunRecord


def io() -> Any:
    return mod("_io")


def provenance_mod() -> Any:
    return mod("_provenance")


def run_common() -> Any:
    return mod("run_common")


def branch_cli() -> Any:
    return mod("learning.branch.cli")


# ======================================================================================
# D2's tenant record and D5's grouped surface — the vocabulary the tests assert against.
# ======================================================================================

#: D2's file-backend location. The leading `_` is what keeps it out of the run-id space
#: (claim C18, executed: `is_valid_run_id("_tenant.json")` is False, `"tenant.json"` is True).
TENANT_RECORD_NAME = "_tenant.json"

#: D2's creation-time bootstrap value. Settled premise s31: it is a bootstrap default, NOT an
#: enforced constant — the record is the sole authority for the stamped tenant.
DEFAULT_TENANT_ID = "default"

TENANT_FIELDS = ("tenant_id", "base_world_id", "created_at")

#: Decision 1a held the pin: five group-named sub-collections, addressed group-then-kind.
GROUPS = ("tables", "facts", "documents", "observability", "session")

#: D5's group table, as member accessor names per group. `run.tables.queries` is the address
#: form decision 1a pinned.
GROUP_MEMBERS: dict[str, tuple[str, ...]] = {
    "tables": ("queries", "policy_denials", "leads", "payloads", "ticket_reads"),
    "facts": ("alert", "provenance", "run_end", "scrub_verdict", "accounting"),
    "documents": ("investigation", "report", "gather_summaries", "lead_author", "source_refs"),
    "observability": (
        "wire_log", "review_trace", "forward_check_trace", "tool_trace", "review_record",
        "budget", "circuit_breaker", "lessons_loaded", "ticket_write", "runtime_html",
        "box_sentinel", "session_pointer"),
    "session": ("session_db",),
}

#: Which group each member lives in, derived from D5's own table.
GROUP_OF: dict[str, str] = {
    name: group for group, names in GROUP_MEMBERS.items() for name in names}

#: The owner accessor behind each sub-collection member — what `RecordHandle.path` must equal
#: (demand h03) and which seam the writer method must reach (demand d44).
MEMBER_ACCESSOR: dict[str, str] = {
    "queries": "executed_queries", "policy_denials": "policy_denials", "leads": "lead_claim",
    "payloads": "payload", "ticket_reads": "ticket_read",
    "alert": "alert", "provenance": "provenance", "run_end": "run_end_sidecar",
    "scrub_verdict": "scrub_verdict", "accounting": "accounting_failures",
    "investigation": "investigation", "report": "report",
    "gather_summaries": "gather_summary", "lead_author": "lead_author",
    "source_refs": "source_refs",
    "wire_log": "wire_log", "review_trace": "review_trace",
    "forward_check_trace": "forward_check_trace", "tool_trace": "tool_trace",
    "review_record": "review_record", "budget": "budget",
    "circuit_breaker": "circuit_breaker", "lessons_loaded": "lessons_loaded",
    "ticket_write": "ticket_write", "runtime_html": "runtime_html",
    "box_sentinel": "box_sentinel", "session_pointer": "session_pointer",
    "session_db": "session_db",
}

#: Decision 11's uniform rule, per group: read everywhere, append or write only where the
#: runtime is the record's producer. `tables` and `observability` and `session` grow; `facts`
#: is written once by the host; `documents` is rewritten in place by the investigation.
GROUP_WRITE_VERB: dict[str, str] = {
    "tables": "append", "facts": "write", "documents": "write",
    "observability": "append", "session": "append"}

#: The two `observability` members that are LOCKED JSON STATES rather than logs: their writer
#: method reaches `_io.locked_for_rewrite` (a read-modify-write under `flock`), never a blind
#: replace — which is what "no accessor exposes an in-place rewrite of an existing entry"
#: means for them (obligation g08, demand d44).
LOCKED_STATE_MEMBERS = ("budget", "circuit_breaker")

#: D4's twelve descriptive fields, read-only, through readers that already exist. Decision 1b
#: moved them off `Run` onto a named `RunRecord` value object reached at `run.record`.
RUN_RECORD_FIELDS = (
    "tenant_id", "world_id", "commit", "dirty", "model", "run_id", "alert_ref",
    "parent_run_id", "fork_turn", "exit_class", "disposition", "review_outcome")

#: The archive's copied set (page §5, D5 / N5), as `ArchivedWorld` accessor names. Claim C17
#: is REFUTED-AS-STATED and EXTENDED: `gather_summaries`, `lessons_loaded` and `alert` come
#: from the four `archive.py` constants the design's enumeration omitted (:151, :153, :154).
ARCHIVED_WORLD_MEMBERS = (
    "report", "investigation", "provenance", "scrub_verdict", "run_end", "lessons_loaded",
    "alert", "gather_summaries", "executed_queries", "gather_raw", "run_dir_pointer")

#: Decision 6 / fork D-F5, reading 1: the gate's composed-PART set is the five DISCRIMINATING
#: fragments only. The generic suffixes are dropped — `.json` alone matches 1065 non-test
#: literals (claim R3), which is why D6(a) as spelled was unimplementable.
DISCRIMINATING_PARTS = (".lead.json", "review_record.", ".trace.jsonl", "_trace.jsonl", "served/")

#: The five composition idioms §7 decision 6 declared "the gate structurally cannot see" —
#: string concatenation, `%`-formatting, `.format`, `os.path.join`, multi-argument `Path()`.
#: IT SEES ALL FIVE when they carry the record name as a whole literal: D6(a) keys on the
#: `ast.Constant`, not on the syntax around it (executed probe, 93-safety-claim-sweep.md
#: finding A). What it genuinely cannot see is settled premise s34's narrower class — an
#: assembly in which NO WHOLE PART is ever a literal — whichever idiom does the assembling.
#: These are the function names h23's fixture plants, one per idiom, in both directions.
COMPOSITION_FORMS = ("concat", "percent", "formatted", "joined", "multi_arg")

#: Decision 5's carve-out: the three trees `lint_run_records` never enters, each holding live
#: record-name use today (claims S10 / G1 / G3, brief red flag R3).
UNSCANNED_TREES = ("defender/skills", "scripts", "experiments")


# ======================================================================================
# The kinds table — O2's walk reads the EXPECTED NAME OFF THE TSV rather than re-spelling it.
# This map is the other half: which accessor owns each row. Exactly one per row (demand h31).
# ======================================================================================

@dataclasses.dataclass(frozen=True)
class Accessor:
    """One row of the kinds table and the single accessor that owns its name.

    `owner` is "run" (`RunPaths`), "episode" (`EpisodePaths`) or "tenant" (`_tenant`); `attr`
    is the accessor's name on that owner; `args` are the components a composing accessor takes,
    in call order, as the concrete values this suite drives it with.
    """
    kind: str
    owner: str
    attr: str
    args: tuple[Any, ...] = ()
    composing: bool = False


LEAD_ID = "l-abc123"
SEQ = 7
TURN = 3
ROLE = "support"
LABEL = "overlay-a"
EPISODE_ID = "ep-2026-09-21"
LINEAGE_ID = "case-0011223344556677"
WORLD_TOKEN = f"{EPISODE_ID}.{LABEL}"
STAGE = "questioner"
PREFIX, STEM, CHECK_INDEX = "forward", "a-lesson", 2

ACCESSOR_FOR_KIND: tuple[Accessor, ...] = (
    Accessor("alert", "run", "alert"),
    Accessor("report", "run", "report"),
    Accessor("investigation", "run", "investigation"),
    Accessor("queries", "run", "executed_queries"),
    Accessor("source_refs", "run", "source_refs"),
    Accessor("gather_raw", "run", "payload", (LEAD_ID, SEQ), composing=True),
    Accessor("lead_claim", "run", "lead_claim", (LEAD_ID,), composing=True),
    Accessor("gather_summaries", "run", "gather_summary", (LEAD_ID,), composing=True),
    Accessor("lead_author", "run", "lead_author"),
    Accessor("wire_log", "run", "wire_log"),
    Accessor("forward_check_trace", "run", "forward_check_trace",
             (PREFIX, STEM, CHECK_INDEX), composing=True),
    Accessor("review_trace", "run", "review_trace", (ROLE,), composing=True),
    Accessor("review_record", "run", "review_record", (TURN,), composing=True),
    Accessor("tool_trace", "run", "tool_trace"),
    Accessor("policy_denials", "run", "policy_denials"),
    Accessor("budget", "run", "budget"),
    Accessor("circuit_breaker", "run", "circuit_breaker"),
    Accessor("lessons_loaded", "run", "lessons_loaded"),
    Accessor("ticket_write", "run", "ticket_write"),
    Accessor("ticket_reads", "run", "ticket_read", (SEQ,), composing=True),
    Accessor("session_pointer", "run", "session_pointer"),
    Accessor("runtime_html", "run", "runtime_html"),
    Accessor("box_sentinel", "run", "box_sentinel"),
    Accessor("provenance", "run", "provenance"),
    Accessor("run_end", "run", "run_end_sidecar"),
    Accessor("scrub_verdict", "run", "scrub_verdict"),
    Accessor("accounting", "run", "accounting_failures"),
    Accessor("session_db", "run", "session_db", (LINEAGE_ID,), composing=True),
    Accessor("family", "episode", "family"),
    Accessor("family_stamp", "episode", "family_stamp"),
    Accessor("review_yaml", "episode", "review"),
    Accessor("samples", "episode", "samples"),
    Accessor("judge_yaml", "episode", "judge"),
    Accessor("judge_draw", "episode", "judge_draw", (LABEL, 1), composing=True),
    Accessor("timing", "episode", "timing"),
    Accessor("staged", "episode", "staged"),
    Accessor("served", "episode", "served_base"),
    Accessor("priming_lock", "episode", "priming_lock"),
    Accessor("stage_trace", "episode", "stage_trace", (STAGE,), composing=True),
    Accessor("learning_html", "episode", "learning_html"),
    Accessor("episode_runs", "episode", "sibling_run_dir", (EPISODE_ID, LABEL), composing=True),
    Accessor("archive_proj", "episode", "world_dir", (LABEL,), composing=True),
    Accessor("tenant", "tenant", "record_path"),
)

#: The three UPWARD accessors (cluster B, dissolved by decision 10): their root is the runs
#: base, not the run directory. `session_db`'s root is the sessions directory, a sibling of the
#: runs base (claims C10/C15).
SIDECAR_ACCESSORS = ("run_end_sidecar", "scrub_verdict", "accounting_failures")
UPWARD_ACCESSORS = (*SIDECAR_ACCESSORS, "sessions_dir", "session_db")

#: Every accessor that builds a path from a caller-supplied component, with an ordinary value
#: and the component index decision 2's one rule must check. g10's census subjects.
COMPOSING = tuple(a for a in ACCESSOR_FOR_KIND if a.composing) + (
    Accessor("served", "episode", "served_world", (WORLD_TOKEN,), composing=True),
    Accessor("archive_proj", "episode", "run_dir_pointer", (LABEL,), composing=True),
    Accessor("gather_raw", "run", "payload_relpath", (LEAD_ID, SEQ), composing=True),
)

#: Values decision 2's anchored shape check must refuse, at every composing accessor. Each is a
#: REAL string handed to the REAL accessor; nothing here is a fake's canned fault.
HOSTILE_COMPONENTS = (
    "",                       # F017 — collapses onto the parent directory
    "..",                     # F011/F030 family — the traversal segment
    "../../etc/passwd",       # F031 — a separator-bearing component
    "a/b",                    # F026/F031 — a separator inside one component
    "/etc/passwd",            # F030 — `/`'s discard-the-left-operand behaviour
    "x" * 4096,               # F018 — oversized
    "a\nb",                   # F019 — a control character that the OS does NOT reject
    "a\x00b",                 # F019 — the NUL byte
)


def kinds_rows(path: Path = KINDS_TSV) -> list[dict[str, str]]:
    """The kinds table as dicts, read off the file the gate reads."""
    lines = path.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    return [dict(zip(header, line.split("\t"), strict=False)) for line in lines[1:] if line.strip()]


def appendix_only() -> frozenset[str]:
    """`lint_run_records.APPENDIX_ONLY_KINDS`, IMPORTED rather than re-spelled — fork D-F7's
    resolution is that O2's walk imports the exclusion set (waiver h51)."""
    from defender.tests._by_path import load_lint_gate
    return frozenset(load_lint_gate("lint_run_records").APPENDIX_ONLY_KINDS)


def resolve(acc: Accessor, *, run_dir: Path, runs_base: Path | None = None,
            episode_dir: Path | None = None, args: tuple[Any, ...] | None = None) -> Path:
    """Drive ONE accessor and hand back the path it resolved.

    The owner is reached through its own constructor every time — `RunPaths(run_dir)`,
    `EpisodePaths(episode_dir)` — so a test that walks the kinds table is driving ~43 real
    accessors, not asserting a structural property of a registry.
    """
    values = acc.args if args is None else args
    if acc.owner == "tenant":
        return tenant().record_path(runs_base)
    owner = RunPaths(run_dir) if acc.owner == "run" else EpisodePaths(episode_dir)
    member = getattr(owner, acc.attr)
    if acc.attr in UPWARD_ACCESSORS:
        return member(runs_base, *values) if values else member(runs_base)
    return member(*values) if values else member


# ======================================================================================
# Filesystem scaffolding — real trees, planted here, re-probed every run.
# ======================================================================================

def member(run: Any, group: str, name: str, *args: Any) -> Any:
    """`run.<group>.<name>` — the `RecordHandle` that member answers.

    A composed kind is CALLED with its caller-supplied components; a plain one is read as an
    attribute. Everything goes through the real handle, so this is a drive, not a lookup.
    """
    m = getattr(getattr(run, group), name)
    return m(*args) if args else m


def member_args(name: str, *, runs_base: Path | None = None) -> tuple[Any, ...]:
    """The components this suite drives one member with, in call order."""
    table: dict[str, tuple[Any, ...]] = {
        "leads": (LEAD_ID,), "payloads": (LEAD_ID, SEQ), "ticket_reads": (SEQ,),
        "gather_summaries": (LEAD_ID,), "review_trace": (ROLE,), "review_record": (TURN,),
        "forward_check_trace": (PREFIX, STEM, CHECK_INDEX), "session_db": (LINEAGE_ID,),
    }
    return table.get(name, ())


def make_runs_base(tmp_path: Path, name: str = "runs") -> Path:
    base = tmp_path / name
    base.mkdir(parents=True, exist_ok=True)
    return base


def make_run_dir(runs_base: Path, run_id: str = "run-1077") -> Path:
    d = runs_base / run_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def make_episode_dir(tmp_path: Path, episode_id: str = EPISODE_ID) -> Path:
    d = tmp_path / "episodes" / episode_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def plant_tenant_record(runs_base: Path, body: str | bytes | None = None, *,
                        tenant_id: str = DEFAULT_TENANT_ID,
                        base_world_id: str = "0123456789abcdef0123456789abcdef",
                        created_at: str = "2026-09-21T00:00:00Z",
                        drop: str | None = None, wrong_type: str | None = None) -> Path:
    """Write `<runs_base>/_tenant.json` — well-formed, or with a REAL corruption on disk.

    `body` writes raw bytes verbatim (the malformed-JSON, empty-file and truncated cases);
    `drop` removes a required field; `wrong_type` replaces one with a number. Every one of
    these is the actual byte sequence the reader will meet, not a fake's canned exception.
    """
    path = runs_base / TENANT_RECORD_NAME
    if body is not None:
        path.write_bytes(body.encode("utf-8") if isinstance(body, str) else body)
        return path
    obj: dict[str, Any] = {
        "tenant_id": tenant_id, "base_world_id": base_world_id, "created_at": created_at}
    if drop is not None:
        obj.pop(drop)
    if wrong_type is not None:
        obj[wrong_type] = 17
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def plant_stamp(run_dir: Path, **fields: Any) -> Path:
    """A `provenance.json` with exactly the keys given — including a MISSING or explicitly-null
    `tenant_id`/`world_id`, which is what the migration window produces (decision 15(2))."""
    path = run_dir / "provenance.json"
    path.write_text(json.dumps(fields, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def alert_ref(alert: Path) -> str:
    """Today's curation key, composed the way `run_common.py:286` composes it."""
    return f"case-{hashlib.sha256(alert.read_bytes()).hexdigest()[:16]}"


def seed_run_tree(run_dir: Path) -> Path:
    """The minimum a fixture run dir carries: an alert and the gather-raw directory."""
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    (run_dir / "alert.json").write_text('{"alert": "seed"}\n', encoding="utf-8")
    return run_dir


# ======================================================================================
# O3's tree observer (decision 21's TWO checks), as a helper every arm drives.
#
# DECISION 21 REPLACED DECISION 14 IN FULL. An executed probe (two `_replay()` calls against
# `main`, same run id, diffed) proved "byte-identical, two exemptions" false independently of
# this issue's code: eight files differ for reasons that predate the refactor — wall-clock
# timestamps (`budget.json`, `tool_trace.jsonl`), a per-run random security salt embedded in
# otherwise-meaningful text (`review_record.<turn>.json`, the three
# `wire_logs/review_*_trace.jsonl`) and random per-run session/case identifiers
# (`session_store_pointer.json`, `tool_trace.jsonl`). So the observer is two checks now:
#
#   STRUCTURAL (strict, load-bearing) — `snapshot` / `tree_diff`: the run directory produces
#   the SAME SET OF NAMES, with no file or directory added, removed, renamed or moved. A
#   directory and a symlink carry their kind and, for a symlink, its link target. NO BYTES AT
#   ALL, for any entry. This is the check that holds and the check that matters.
#
#   CONTENT (narrow) — `content_digests`: bytes are compared for `investigation.md` and
#   `report.md` ONLY, the two artifacts the model generates from the SAME fixed replay input
#   and that a human actually reads.
#
# THERE IS NO EXEMPTION LIST, and `snapshot` deliberately takes no `exclude` argument: the
# widening lever decision 14's `O3_EXEMPT` handed an implementer meeting a red test is gone
# rather than lengthened. Everything outside `O3_CONTENT` simply carries no byte assertion.
# Decision 18's wire-log writer id needs no carve-out for the same reason: the wire log was
# never byte-compared under this contract.
# ======================================================================================

@dataclasses.dataclass(frozen=True)
class Entry:
    """One tree entry in the STRUCTURAL check — its name, its kind, and nothing it contains.

    `target` is a symlink's link target and is `None` for a regular file and a directory:
    following the link would compare one file twice, and a file's BYTES are not part of this
    check at all (decision 21). Bytes live in `content_digests`, over two names.
    """
    rel: str
    kind: str                # "file" | "dir" | "symlink"
    target: str | None       # the link's target for a symlink; None otherwise


def snapshot(root: Path) -> dict[str, Entry]:
    """Decision 21's structural snapshot of one tree: every entry by relative name.

    No `exclude`: the structural check covers the whole run directory and admits no
    exemption, which is what makes "the same set of names" a claim worth making.
    """
    out: dict[str, Entry] = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if p.is_symlink():
            out[rel] = Entry(rel, "symlink", os.readlink(p))
        elif p.is_dir():
            out[rel] = Entry(rel, "dir", None)
        else:
            out[rel] = Entry(rel, "file", None)
    return out


def tree_diff(a: dict[str, Entry], b: dict[str, Entry]) -> list[str]:
    """The structural observer's findings: a name in one tree and not the other, or an entry
    whose KIND (or, for a symlink, whose link target) changed."""
    findings = []
    for rel in sorted(set(a) | set(b)):
        if rel not in b:
            findings.append(f"only in the baseline: {rel}")
        elif rel not in a:
            findings.append(f"only in the comparison: {rel}")
        elif a[rel] != b[rel]:
            findings.append(f"differs: {rel}")
    return findings


#: Decision 21's content check, in full. The investigation write-up and the final report are
#: the two artifacts the model generates from the SAME fixed replay input and that a human
#: actually reads; everything else in the tree (budget, tool trace, session pointer, the wire
#: logs, the review records and traces) gets NO byte assertion — not exempted-with-a-reason,
#: not normalised, simply not compared, because it was never stable to begin with.
O3_CONTENT = ("investigation.md", "report.md")


def content_digests(root: Path, names: Iterable[str] = O3_CONTENT) -> dict[str, str | None]:
    """The sha256 of each content file's bytes, `None` where the run produced no such file.

    `None` is a VALUE the comparison sees, not a skip: a report that stopped being written is
    a content finding, the same as one whose bytes changed.
    """
    out: dict[str, str | None] = {}
    for name in names:
        p = root / name
        out[name] = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
    return out


def mutation_census(root: Path) -> dict[str, tuple[str, str | None]]:
    """Every entry AND every regular file's bytes — the before/after census a READ-PURITY
    test needs (decision 9), never O3's observer.

    Deliberately separate from `snapshot`: this compares ONE tree to ITSELF across ONE
    operation, where the bytes are stable by construction. That is exactly the comparison
    decision 21 found does NOT hold between two separate runs, which is why the two live in
    different helpers and the structural one carries no bytes.
    """
    out: dict[str, tuple[str, str | None]] = {}
    for rel, e in snapshot(root).items():
        p = root / rel
        if e.kind == "file":
            out[rel] = ("file", hashlib.sha256(p.read_bytes()).hexdigest())
        else:
            out[rel] = (e.kind, e.target)
    return out


#: Decision 21 keeps decision 14's rule 4, scoped to the narrowed content check plus the
#: structural name-set: the baseline is captured on the SAME COMMIT as the comparison and
#: re-captured whenever that commit moves — so it carries the commit it was taken on, and a
#: baseline from another commit is REPORTED rather than compared. D7(1) is where it is first
#: captured: the observer must ship green on `main`, with no implementation behind it, before
#: step 3.
TREE_BASELINE = Path(__file__).with_name("_tree_baseline_1077.json")


def head_commit() -> str:
    """The commit the comparison runs on, through the repo's OWN git facade.

    `defender._git.git_head_sha`, not a second `rev-parse` of this suite's own: two places
    deriving one fact from the same argv is the shared-oracle shape
    (`scripts/lint/lint_shared_oracle.py`), and here the value is a plain identity read the
    facade already owns.
    """
    return mod("_git").git_head_sha(REPO_ROOT)


def load_baseline(path: Path = TREE_BASELINE) -> dict[str, Any]:
    """The captured baseline document: `commit`, the structural `entries`, the two `content`
    digests. Three keys, and the third is two names long — that IS the contract."""
    return json.loads(path.read_text(encoding="utf-8"))


def baseline_entries(doc: dict[str, Any]) -> dict[str, Entry]:
    return {rel: Entry(rel, kind, target) for rel, (kind, target) in doc["entries"].items()}


def capture_baseline(run_dir: Path, *, path: Path = TREE_BASELINE) -> dict[str, Any]:
    """Write the O3 baseline for `run_dir`: the whole name set, the two documents' bytes, and
    the commit it was taken on."""
    doc = {
        "commit": head_commit(),
        "entries": {rel: [e.kind, e.target] for rel, e in snapshot(run_dir).items()},
        "content": content_digests(run_dir),
    }
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return doc


def structural_findings(run_dir: Path, doc: dict[str, Any]) -> list[str]:
    """The strict half: the run directory's name set against the baseline's, in full."""
    return tree_diff(baseline_entries(doc), snapshot(run_dir))


def content_findings(run_dir: Path, doc: dict[str, Any]) -> list[str]:
    """The narrow half: the two documents' bytes, and no other file's."""
    want: dict[str, str | None] = doc["content"]
    got = content_digests(run_dir, want)
    return [f"content differs: {name}" for name in sorted(want) if want[name] != got.get(name)]


def compare_to_baseline(run_dir: Path, *, path: Path = TREE_BASELINE) -> list[str]:
    """O3's findings for `run_dir` — structural first, then content — or the one finding a
    stale baseline is (decision 21, keeping decision 14's rule 4)."""
    doc = load_baseline(path)
    if doc["commit"] != head_commit():
        return [f"baseline captured on {doc['commit']}, comparison on {head_commit()} — "
                "re-capture it rather than compare across commits"]
    return structural_findings(run_dir, doc) + content_findings(run_dir, doc)


# ======================================================================================
# The `_io` recorder / fault injector — one fake, driven by a data fault-spec, injecting only.
# ======================================================================================

@dataclasses.dataclass(frozen=True)
class IoFault:
    """A declarative fault-spec for `RecordingIo`. The fake classifies nothing and decides no
    policy: it raises what it is told to raise, where it is told to raise it.

    `fail_on` names the `_io` operations that raise; `error` is the exception raised, defaulting
    to the one claim C19 observed on the REAL `_io.write_guarded` when its staged
    `O_CREAT|O_EXCL|O_NOFOLLOW` create meets an existing entry. `raise_after` lets the Nth call
    through before failing. `before_write` runs just before the real call, which is how the
    tenant-record create race (decision 13) is opened deterministically.
    """
    fail_on: tuple[str, ...] = ()
    error: BaseException | None = None
    raise_after: int = 0
    before_write: Callable[[Path], None] | None = None


class RecordingIo:
    """A pass-through recorder over the real `defender._io`, entering through the owner's
    `io=` injection seam (never `monkeypatch.setattr` — `scripts/lint/lint_monkeypatch.py`).

    It records every operation the owner asks of it, with the path, so a `kind: seam` demand
    can assert on the CAPTURED INBOUND CALL rather than on a canned return value.
    """

    def __init__(self, fault: IoFault | None = None) -> None:
        self.fault = fault or IoFault()
        self.calls: list[tuple[str, Path]] = []
        self._real = io()

    @property
    def ops(self) -> list[str]:
        return [name for name, _ in self.calls]

    def _dispatch(self, name: str):
        real = getattr(self._real, name)

        def call(path, *a, **kw):
            self.calls.append((name, Path(path)))
            prior = sum(1 for n, _ in self.calls[:-1] if n == name)
            if name in self.fault.fail_on and self.fault.raise_after <= prior:
                    raise self.fault.error or FileExistsError(
                        f"{path}: staged create collided (write_guarded O_EXCL, claim C19)")
            if name.startswith("write") and self.fault.before_write is not None:
                self.fault.before_write(Path(path))
            return real(path, *a, **kw)

        return call

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        return self._dispatch(name)


# ======================================================================================
# The alias-ban probe's docker seam — the one dependency too costly to drive for a timeout.
# ======================================================================================

@dataclasses.dataclass(frozen=True)
class ProbeFault:
    """`timeout` raises what `runtime/box/_docker.py`'s fixed `subprocess.run(..., timeout=120)`
    raises; `malformed` returns the probe's own control-failed shape, which the real probe
    already treats as "could not be OBSERVED" (claim C3, claim C14). `clean` is the control."""
    mode: str = "clean"


class ProbeDocker:
    """A fake `DockerFn` for `runtime/box/_alias`'s probe, injected at the `docker=` argument
    the real call site already threads. It injects a fault and nothing else."""

    def __init__(self, fault: ProbeFault | None = None) -> None:
        self.fault = fault or ProbeFault()
        self.argv: list[list[str]] = []

    def __call__(self, argv: list[str], **kw: Any):
        self.argv.append(list(argv))
        if self.fault.mode == "timeout":
            raise subprocess.TimeoutExpired(cmd=argv, timeout=120)
        if self.fault.mode == "malformed":
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="CONTROL-FAILED")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


# ======================================================================================
# The gate. D6 REWRITES `scripts/lint/lint_run_records.py`, so every call goes through these
# two helpers: when the implementation names the rewritten entry point differently, TWO
# helpers change, not the twenty-eight tests that drive them.
# ======================================================================================

def gate():
    """The gate, loaded the way CI reaches it (a standalone program, not a package)."""
    from defender.tests._by_path import load_lint_gate
    return load_lint_gate("lint_run_records")


def plant(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def gate_findings(root: Path, rel: str | None = None, text: str | None = None) -> list[Any]:
    """Run D6's rewritten sweep over `root` and hand back its findings.

    `rel`/`text` plant one source file first. The pinned entry point is
    `lint_run_records.scan(root)` — the root-taking pure pass D6's rewrite needs so the sweep
    can be driven over a tmp tree instead of the checkout.
    """
    if rel is not None:
        plant(root, rel, text or "")
    return list(gate().scan(root))


def displays(found: Iterable[Any]) -> str:
    return "\n".join(getattr(f, "display", str(f)) for f in found)


def reports(found: Iterable[Any], needle: str) -> bool:
    return needle in displays(found)


# ======================================================================================
# Refusals — "the run is refused" as an observable, not as "something raised".
# ======================================================================================

def refused_run(fn: Callable[[], Any], *, runs_base: Path, run_id: str) -> BaseException:
    """Drive `fn` and assert the RUN was refused, not degraded.

    Decision 4 makes the tenant record the sole exception to read-as-`None`, and decision 7
    makes an identity-bearing write fail LOUDLY. "Refused" is three observables together: the
    call raised, and no run directory was left addressable with a degraded identity — no
    provenance stamp naming a defaulted tenant. A bare `pytest.raises` would be green on any
    exception at all, including one from the harness.
    """
    with pytest.raises((SystemExit, Exception)) as excinfo:  # noqa: B017,PT011
        fn()
    stamp = runs_base / run_id / "provenance.json"
    if stamp.is_file():
        body = json.loads(stamp.read_text(encoding="utf-8"))
        assert body.get("tenant_id") is None, (
            "the run was DEGRADED, not refused: it stamped "
            f"tenant_id={body.get('tenant_id')!r} over a tenant record it could not read")
    return excinfo.value
