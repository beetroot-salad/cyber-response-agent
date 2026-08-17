from __future__ import annotations

import re
import stat
from dataclasses import dataclass
from pathlib import Path


#: The run's ONE wire log, and the subdirectory that holds it — the layout fact, spelled here
#: so the writers (`runtime.observe.wire_log_path` for the runtime, `stage_trace_path` for
#: every learning stage), the read gate (`permission.files.names_wire_log_dir`) and the readers
#: (the visualizers) share one source. Named in this module rather than in `runtime.observe`
#: because the visualizer needs the location and must not pay for pydantic-ai to learn it.
#:
#: `WIRE_LOG_DIR` is the whole class, not just this file: every WIRE log in the tree writes
#: under it — `<run_dir>/wire_logs/llm_requests.jsonl` for the investigation, and
#: `<root>/wire_logs/<stage>.trace.jsonl` for the actor, oracle, judge, curators and
#: forward-check verifier. One component means one rule can name them all, which is what
#: `names_wire_log_dir` is. The class is "carries a wire body verbatim", NOT "is a
#: `RequestLogger`": `runtime.observe.denial_logger` builds one too and stays at
#: `<run_dir>/policy_denials.jsonl`, per the root-level census below.
#:
#: THE SUBDIRECTORY IS THE GATE, not tidiness. MAIN's and GATHER's run-dir read shape is
#: `under(run, SEG)` (`runtime/permission/policies/_common.read_shapes`, the builder only
#: those two share) and `SEG` spells ONE path segment — so a run-root file is admitted by that
#: shape and a file one level down is not, on the read tool and the bash `cat` lane alike
#: (they share the shape OBJECT). At the run root this log was readable by MAIN, which is a
#: boundary crossing: every gather subagent logs through the SAME `RequestLogger`
#: (`driver.build_gather_agent`), so gather's raw payload bytes — which `decide_read` refuses
#: MAIN one call earlier with `RAW_DENY_REASON` — sat verbatim in a file MAIN could
#: `read_file`/`cat`, unframed (`is_untrusted_read` did not fire). GATHER's shape is the same,
#: so the mirror held too: an injected subagent could read MAIN's whole transcript.
#:
#: THE SUBDIRECTORY ARGUMENT DOES NOT GENERALIZE PAST THOSE TWO ROLES. The JUDGE's `cat` scope
#: is `under(run, TREE)` (`judge/engine_pydantic._judge_bash_shapes`) — multi-segment, so a
#: subdirectory hides nothing from it — and the ACTOR carries no `cat` grant, so
#: `read_allow_of` yields an EMPTY shape tuple and `decide_read` applies no shape filter at
#: all, leaving it gated by root containment alone. Those two share the LEARNING run dir,
#: where the same defect lived: the judge's trace carries its prompt's payload exemplars
#: UNREDACTED (`judge/compare.unredacted_exemplar`) and the gray-box actor could read them
#: back, around the `gather_raw` deny.
#:
#: Which is why the component ALSO carries an outright deny (`permission.files.names_wire_log_dir`,
#: both read surfaces, every role) rather than resting on the shapes. The directory is what
#: makes the deny addressable — one component test covers a trace name nobody has invented yet
#: — and the deny is what makes it hold for the roles a shape cannot reach.
#:
#: The run's OTHER root-level streams stay at the root deliberately: `tool_trace.jsonl` is a
#: projection carrying tool NAMES (`observe._user_event`), `policy_denials.jsonl` carries a
#: parameter DIGEST rather than the blob (`RequestLogger.log_policy_denial`), and
#: `budget.json`/`circuit_breaker.json` are counters. None replays another agent's context,
#: which is the property that made this one a leak.
#:
#: `review_{role}_trace.jsonl` IS in the class and lives here too. `_write_trace_row` appends
#: each review stage's RAW wrapped reply, while MAIN is handed only the composer's
#: `target: ask` lines (`close_tool._render_challenged_message`) and never the two blind
#: lenses' replies — the blindness the gate is built on. `challenge_gate.review_trace_path`
#: owns the filename.
#:
#: `transcript.html`/`runtime.html` are the ONE exception, recorded so it is not inferred:
#: they DO inline MAIN's transcript verbatim (rendered from this log by `visualize_messages`)
#: and sit at the run root inside GATHER's shape. They are out of reach on TIMING, not on
#: content — `run.py` renders them after `run_investigation` returns, so no agent of that run
#: is still alive. That is a thinner guarantee than a directory, and anything that moves the
#: render INTO the run (a mid-flight `--visualize`, a live page) must move these two under
#: `wire_logs/` in the same change.
WIRE_LOG_DIR = "wire_logs"
WIRE_LOG = "llm_requests.jsonl"

#: The reserved key on a `tool-return` part's `metadata` that the TOON view gate parks the
#: tool's ORIGINAL JSON under when it substitutes a smaller view. Spelled HERE for the reason
#: the wire log's location is: the WRITER is `runtime.toon_gate` (which imports pydantic-ai, a
#: `runtime`-extra-only dependency) and the READER is `scripts/visualize/visualize_messages`,
#: which a learning-loop or CI install must not pay a pydantic-ai edge to learn a field name.
#: `runtime.toon_gate` re-exports it under its own name, where §7 r1 pins the literal.
GATE_METADATA_KEY = "json"


@dataclass(frozen=True)
class RunPaths:
    """One run's directories and its six artifact accessors: the alert, the report, the
    investigation log, the executed-queries table, the raw-payload dir and the wire log.

    Every artifact accessor resolves relative to ``run_dir``, so construct
    ``RunPaths(some_dir)`` on whichever root you hold. ONE root, deliberately: a caller
    needing a second (the per-case leg-output dir) takes it as its own argument rather than
    making every single-root construction carry an always-`None` `Optional`.
    """

    run_dir: Path

    @property
    def alert(self) -> Path:
        return self.run_dir / "alert.json"

    @property
    def report(self) -> Path:
        return self.run_dir / "report.md"

    @property
    def investigation(self) -> Path:
        return self.run_dir / "investigation.md"

    @property
    def executed_queries(self) -> Path:
        return self.run_dir / "executed_queries.jsonl"

    @property
    def gather_raw(self) -> Path:
        return self.run_dir / "gather_raw"

    @property
    def wire_log(self) -> Path:
        return self.run_dir / WIRE_LOG_DIR / WIRE_LOG


# A run bundle is ALWAYS `runs_dir / <run_id>` (`LoopPaths.runs_dir` is the only place the
# learning loop creates one), so a recorded `source_run_dir` contributes a NAME and nothing
# else. A degenerate input (`"/"`, `"."`, `".."`, `""`) names no run: it maps to a child that
# cannot exist, so a caller's `is_dir()` check reads it as a missing bundle rather than
# admitting the runs root — or its parent — as one.
_NO_BUNDLE = "_unresolvable_source_run_dir"
_NAMELESS = {"", ".", ".."}

#: The lead-id alphabet, as the BODY of `l-<body>` — ONE spelling for every gate that has an
#: opinion about a lead id, because they are not independent facts. A validator that admits an
#: id a path shape refuses does not fail loose, it fails ABSURD: `claim_lead` mints the payload
#: at `gather_raw/l-auth1/0.json`, the query tool hands gather that exact path and tells it to
#: `cat` it, and gather's own read gate then refuses its own payload.
#:
#: The three id validators (`hooks.record_lead.LEAD_ID_RE`, `scripts.gather_tools.record_query.
#: LEAD_ID_RE`, `learning.lead_repository._LEAD_ID_RE`) and the two path shapes
#: (`_PAYLOAD_SHAPES` below, `permission.policies._common.read_shapes`) all compose off this.
#: BOUNDED, and generously: every id is spent as a FILENAME COMPONENT —
#: `gather_raw/{lead_id}.lead.json`, `gather_summaries/{lead_id}.md` — so an unbounded body
#: lets a model-coined id fail the claim's `os.open` with ENAMETOOLONG rather than at a seam,
#: and "could not write" is the answer a caller has the least to say about. 64 is far above
#: anything the `:L` set spells (`l-001`, `l-auth1`) and far below a filename component's 255.
LEAD_ID_BODY = r"[A-Za-z0-9]{1,64}"

#: `\Z`, not `$`: `$` also matches BEFORE a trailing newline, so `l-abc\n` would pass
#: `.match()` and compose a lead dir whose name ends in a newline. The path shapes never
#: admitted that, so the anchor is what keeps validator and gate agreeing at BOTH ends.
LEAD_ID_RE = re.compile(rf"^l-{LEAD_ID_BODY}\Z")

#: The gather payload family, relative to a run dir. Shared with the runtime read gate rather
#: than re-spelled there: it is the same set of files, named once.
GATHER_RAW_SHAPE = rf"gather_raw/l-{LEAD_ID_BODY}/[0-9]+\.json"

# The two by-ref payload families a run writes, as literal shapes: the gather lane's
# `gather_raw/{lead_id}/{seq}.json` and the judge's ticket-read capture
# `ticket_reads/{seq}.json`. Anything else recorded in the queries table is not an artifact
# this system produces.
#
# `[0-9]`, not `\d`: a str pattern's `\d` matches every Unicode decimal (`٣.json` passes),
# widening the whitelist past anything a writer produces and past the ASCII-only lead-id
# alphabet beside it. Both seqs are `f"{int}"`, so ASCII is the exact shape.
_PAYLOAD_SHAPES = (
    re.compile(GATHER_RAW_SHAPE),
    re.compile(r"ticket_reads/[0-9]+\.json"),
)

#: The case's ANSWER KEY: the finished investigation's own reasoning, its disposition, and the
#: query record behind them. Named as a set because the learning loop STAGES all four into
#: `<learning_run_dir>/` (`learning.core.persist._copy_shared_inputs`,
#: `lead_repository.stage_tables`) — and that dir IS the gray-box actor's own run root, whose
#: whole purpose is to withhold them. `alert.json` is deliberately NOT here: it is the case
#: INPUT, handed to the actor in its own user message, so denying it would withhold nothing.
#:
#: The read gate spends this at `permission.files.names_case_answer_key`; the names live here
#: because this module already owns what a run dir is called.
CASE_ANSWER_KEY_NAMES = frozenset(
    {"investigation.md", "report.md", "source_refs.yaml", "executed_queries.jsonl"}
)

# `resolve()` on a hostile operand — a symlink cycle, an embedded NUL, a name past PATH_MAX.
_RESOLVE_ERRORS = (OSError, RuntimeError, ValueError)


def _lstat_is(path: Path, kind) -> bool:
    """`kind` of the entry ITSELF — never of what it points at. Fails closed: an entry the
    caller cannot judge is not one it may copy."""
    try:
        return bool(kind(path.lstat().st_mode))
    except (OSError, ValueError):
        return False


def artifact_file(path: Path) -> bool:
    """True when ``path`` is a REGULAR FILE, not a link (or FIFO, or device) wearing its name.

    Nothing this system writes into a run dir is ever a link, and the run dir is the box's rw
    bind — so a link at an artifact's name is something the model planted. The distinction
    matters at the COPY, not at the read: ``is_file()`` answers about the link's target, so a
    `copy2` of it writes the TARGET's bytes into learning state under an artifact's name, where
    the actor and judge read them as a legitimate in-run file and no later gate can tell.
    """
    return _lstat_is(path, stat.S_ISREG)


def artifact_dir(path: Path) -> bool:
    """True when ``path`` is a REAL directory rather than a link to one — see ``artifact_file``.

    Separate from the per-entry rule inside a tree: `copytree`'s ``symlinks=True`` governs what
    it finds while walking and says nothing about the root it was handed, so a symlinked
    ``gather_raw`` copies the target directory's whole contents in.
    """
    return _lstat_is(path, stat.S_ISDIR)


def resolve_run_bundle(runs_dir: Path, source_run_dir: object) -> Path:
    """The run bundle a recorded ``source_run_dir`` names, always under ``runs_dir``.

    The recorded string is a label, never an address: only its last segment is honored, so
    neither a traversal nor an absolute path can move the read off the runs root.

    Typed ``object`` for the same reason ``contained_payload`` is: the value comes off a queued
    JSONL row, so a non-string there must read as a missing bundle rather than raise out of a
    drain batch mid-flight."""
    if not isinstance(source_run_dir, str):
        return runs_dir / _NO_BUNDLE
    name = Path(source_run_dir.rstrip("/")).name
    return runs_dir / (_NO_BUNDLE if name in _NAMELESS else name)


def contained_payload(run_dir: Path, payload_path: object) -> Path | None:
    """The by-ref payload ``payload_path`` names under ``run_dir``, or ``None`` if it names
    anything else. Two gates, because they answer different questions (#648):

    1. **the shape** — the value must spell one of the payload families a run actually writes.
       This is what makes the read an artifact lookup rather than an open of a path an
       attacker chose: `..`, an absolute path and a stray filename all fail it outright.
    2. **containment after resolution** — a well-formed name can still be a symlink, and
       model-written bash writes into the run dir (it is the box's rw bind), so the shape gate
       alone would happily open a link planted at exactly the expected name. The resolved
       target must land inside the resolved ``run_dir``, on whichever root the caller holds.

    A `resolve()` fault FAILS CLOSED, the same posture the runtime read gate takes."""
    if not isinstance(payload_path, str) or not any(
        shape.fullmatch(payload_path) for shape in _PAYLOAD_SHAPES
    ):
        return None
    run_root = Path(run_dir)
    candidate = run_root / payload_path
    try:
        root, target = run_root.resolve(), candidate.resolve()
    except _RESOLVE_ERRORS:
        return None
    if root not in target.parents:
        return None
    # The UNresolved path: callers re-derive `relative_to(run_dir)` off it, and resolving
    # would break that wherever the run root itself sits behind a symlink.
    return candidate
