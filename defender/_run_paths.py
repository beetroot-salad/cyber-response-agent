from __future__ import annotations

import dataclasses
import errno
import re
import stat
from pathlib import Path, PurePosixPath

from defender._io import ALIAS_READ_REFUSAL, _mark_alias, is_plain_entry

# STDLIB `@dataclass`, not `defender._model.model` (#1077 D1): the box entrypoint's import
# closure needs this module with no third-party package installed — `runtime/box/__init__.py`
# now imports the sentinel name from here, and `_io.py`/`box/_spec.py` already made the same
# switch for the same reason (#1067).


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
#: was `under(run, TREE)` (the old pipeline judge's `cat` shapes) — multi-segment, so a
#: subdirectory hides nothing from it — and the ACTOR carries no `cat` grant, so
#: `read_allow_of` yields an EMPTY shape tuple and `decide_read` applies no shape filter at
#: all, leaving it gated by root containment alone. Those two share the LEARNING run dir,
#: where the same defect lived: the judge's trace carries its prompt's payload exemplars
#: UNREDACTED (that judge's prompt exemplars carried real values) and the gray-box actor
#: could read them
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
#: lenses' replies — the blindness the gate is built on. `review_trace`/`review_record` moved
#: onto this module from `challenge_gate.py` (#1077 D1): the owner of a run's names owns these
#: two too.
#:
#: `runtime.html` is the ONE exception, recorded so it is not inferred: it DOES inline
#: MAIN's transcript verbatim (rendered from this log by `visualize_messages`) and sits at
#: the run root inside GATHER's shape. It is out of reach on TIMING, not on content —
#: `run.py` renders it after `run_investigation` returns, so no agent of that run is still
#: alive. That is a thinner guarantee than a directory, and anything that moves the render
#: INTO the run (a mid-flight `--visualize`, a live page) must move it under `wire_logs/`
#: in the same change.
WIRE_LOG_DIR = "wire_logs"
WIRE_LOG = "llm_requests.jsonl"

#: The run's provenance stamp (#976), named here rather than inline in the accessor for the
#: reason `WIRE_LOG_DIR` is: a SECOND module needs the same string. `scripts/workspace_map`
#: suppresses this name from the model-facing directory view, and a suppression that spells
#: the filename independently of the writer keeps suppressing a name that no longer exists the
#: day the writer renames it — after which the stamp silently reappears in MAIN's message 0,
#: which is the one outcome that suppression exists to prevent.
PROVENANCE = "provenance.json"

#: The reserved key on a `tool-return` part's `metadata` that the TOON view gate parks the
#: tool's ORIGINAL JSON under when it substitutes a smaller view. Spelled HERE for the reason
#: the wire log's location is: the WRITER is `runtime.toon_gate` (which imports pydantic-ai, a
#: `runtime`-extra-only dependency) and the READER is `scripts/visualize/visualize_messages`,
#: which a learning-loop or CI install must not pay a pydantic-ai edge to learn a field name.
#: `runtime.toon_gate` re-exports it under its own name, where §7 r1 pins the literal.
GATE_METADATA_KEY = "json"

# ======================================================================================
# #1077 D1 — every run-level record name, as a named constant. The gate's literal pass
# (scripts/lint/lint_run_records.py) reads its "whole name" set and its composed-PART set off
# these — every module-level UPPERCASE string constant here is a name the gate protects.
# ======================================================================================

ALERT = "alert.json"
REPORT = "report.md"
INVESTIGATION = "investigation.md"
EXECUTED_QUERIES = "executed_queries.jsonl"
SOURCE_REFS = "source_refs.yaml"

#: The by-ref gather payload family's directory, and the judge's ticket-read capture's sibling.
#: `RAW_MARKER`/`TICKET_READS_MARKER` are what `runtime/permission/files.py`'s six deny
#: predicates import rather than spell (#1077 D1 — claim C20).
RAW_MARKER = "gather_raw"
GATHER_SUMMARIES_DIRNAME = "gather_summaries"
LEAD_AUTHOR_DIRNAME = "lead_author"
TICKET_READS_MARKER = "ticket_reads"

#: The composed-name PARTS decision 6 keeps in the gate's substring-match set — the five
#: DISCRIMINATING fragments (fork D-F5, reading 1): generic suffixes (`.json`, `.db` alone)
#: are deliberately NOT constants of this shape, because a bare suffix matches ~1065 non-target
#: literals (claim R3) and would make the gate unimplementable. `TRACE_SUFFIX` is shared with
#: `_episode_paths.stage_trace`, imported there rather than re-spelled (claim: one reused
#: constant, not two).
LEAD_CLAIM_SUFFIX = ".lead.json"
REVIEW_RECORD_PREFIX = "review_record."
TRACE_SUFFIX = ".trace.jsonl"

#: The REVIEW GATE's own trace — `wire_logs/review_<role>_trace.jsonl`, one review stage's raw
#: wrapped reply (`RunPaths.review_trace`). Its own constant, and NOT the stage seam's below,
#: although the two spell the same eight characters today (#1077 D7).
#:
#: THEY ARE TWO RECORDS, not one. The review gate's trace belongs to a RUN and is keyed by the
#: reviewing role; the stage seam's belongs to an EPISODE and is keyed by an agent id
#: (`<agent_id>_trace.jsonl`, the questioner's and the judge's draws). Binding both to one
#: name meant a change made for one silently renamed every file of the other — and the
#: framed-companion pairing the episode page does would have broken with it, with no error
#: anywhere, because the page pairs the two by stem.
REVIEW_TRACE_SUFFIX = "_trace.jsonl"

#: The STAGE SEAM's agent trace, and its FRAMED companion — `<agent_id>_trace.jsonl` and
#: `<agent_id>_framed_trace.jsonl` under an episode's `wire_logs/`. The framed one carries the
#: prompt/reply pair the seam does not itself produce (`judge._write_wire_log`); the episode
#: page pairs them by stem, which is why they are composed by ONE owner (`WIRE_LOG_NAMES`)
#: rather than two call sites each spelling half the pair.
#: The line-delimited extension both trace families carry. Generic (decision 6 keeps bare
#: suffixes out of the gate's part set), spelled here only so `trace_key` can drop it without
#: a literal at the call site.
JSONL_EXT = ".jsonl"

AGENT_TRACE_SUFFIX = "_trace.jsonl"
AGENT_FRAMED_TRACE_SUFFIX = "_framed_trace.jsonl"
#: The episode layout's `served/` directory prefix — an EPISODE-level fragment, kept here
#: (rather than only on `_episode_paths.py`) because D6's part set is read off this module;
#: `_episode_paths.py` imports it rather than re-spelling it.
SERVED_PREFIX = "served/"

#: Generic — composed with a caller-supplied component, but not itself a discriminating part
#: (decision 6 drops it from the gate's part-matching set; D6(b)'s accessor-derived pass is
#: what catches a hand-rolled composition of these instead).
PAYLOAD_SUFFIX = ".json"
SESSION_DB_SUFFIX = ".db"

TOOL_TRACE = "tool_trace.jsonl"
POLICY_DENIALS = "policy_denials.jsonl"
BUDGET = "budget.json"
CIRCUIT_BREAKER = "circuit_breaker.json"
LESSONS_LOADED = "lessons_loaded.jsonl"
TICKET_WRITE = "ticket_write.json"
SESSION_POINTER = "session_store_pointer.json"
RUNTIME_HTML = "runtime.html"
#: The box startup sentinel (#1077 D1). Re-homed here so `runtime/box/_lifecycle.py` imports
#: it rather than spelling `.box-sentinel` inline — the same D1 move `WIRE_LOG_DIR` made.
BOX_SENTINEL = ".box-sentinel"

#: The three sidecars beside the runs base, keyed `<run_id><suffix>` — a pure function of a
#: path the host already holds (`run_end.sidecar_path`, `scrub.verdict_path`, and the
#: accounting-failure sidecar `hooks/budget_enforcer._accounting_failure_path`).
RUN_END_SIDECAR_SUFFIX = ".run-end.json"
SCRUB_VERDICT_SUFFIX = ".scrub-verdict.json"
ACCOUNTING_FAILURES_SUFFIX = ".accounting_failures.json"

#: The sessions directory is a SIBLING of the runs base (claims C10/C15), never a child.
SESSIONS_DIRNAME = "sessions"


# ==========================================================================================
# THE LAYOUT — every run record as a path RELATIVE to the run dir (#1077 D7).
#
# One spelling, two views, mirroring `_episode_paths.EpisodeLayout`. The relative form exists
# because the tree's screened readers (`_io.Bound`) address records by a name relative to the
# root handle they hold and never by an absolute path; before D7 those callers hand-composed
# that name out of an imported constant, which is the same drift as a hand-composed absolute
# path. `payload_relpath` was this idea with one member.
#
# The three sidecars, the sessions dir and the session db have NO relative form and are not
# here: they resolve against the runs BASE or its sibling, not against the run dir, and a
# relative-to-the-run-dir spelling of them would be a lie a caller could join.
# ==========================================================================================


@dataclasses.dataclass(frozen=True)
class RunLayout:
    """Every run record, relative to the run dir. Stateless — see `RUN_LAYOUT`."""

    # -- content the run produced -----------------------------------------------------------

    @property
    def alert(self) -> PurePosixPath:
        return PurePosixPath(ALERT)

    @property
    def report(self) -> PurePosixPath:
        return PurePosixPath(REPORT)

    @property
    def investigation(self) -> PurePosixPath:
        return PurePosixPath(INVESTIGATION)

    @property
    def executed_queries(self) -> PurePosixPath:
        return PurePosixPath(EXECUTED_QUERIES)

    @property
    def source_refs(self) -> PurePosixPath:
        return PurePosixPath(SOURCE_REFS)

    @property
    def gather_raw(self) -> PurePosixPath:
        return PurePosixPath(RAW_MARKER)

    @property
    def gather_summaries(self) -> PurePosixPath:
        return PurePosixPath(GATHER_SUMMARIES_DIRNAME)

    @property
    def lead_author(self) -> PurePosixPath:
        return PurePosixPath(LEAD_AUTHOR_DIRNAME)

    @property
    def ticket_reads(self) -> PurePosixPath:
        return PurePosixPath(TICKET_READS_MARKER)

    @property
    def wire_log_dir(self) -> PurePosixPath:
        return PurePosixPath(WIRE_LOG_DIR)

    @property
    def wire_log(self) -> PurePosixPath:
        return self.wire_log_dir / WIRE_LOG

    @property
    def tool_trace(self) -> PurePosixPath:
        return PurePosixPath(TOOL_TRACE)

    @property
    def policy_denials(self) -> PurePosixPath:
        return PurePosixPath(POLICY_DENIALS)

    @property
    def budget(self) -> PurePosixPath:
        return PurePosixPath(BUDGET)

    @property
    def circuit_breaker(self) -> PurePosixPath:
        return PurePosixPath(CIRCUIT_BREAKER)

    @property
    def lessons_loaded(self) -> PurePosixPath:
        return PurePosixPath(LESSONS_LOADED)

    @property
    def ticket_write(self) -> PurePosixPath:
        return PurePosixPath(TICKET_WRITE)

    @property
    def session_pointer(self) -> PurePosixPath:
        return PurePosixPath(SESSION_POINTER)

    @property
    def runtime_html(self) -> PurePosixPath:
        return PurePosixPath(RUNTIME_HTML)

    @property
    def box_sentinel(self) -> PurePosixPath:
        return PurePosixPath(BOX_SENTINEL)

    @property
    def provenance(self) -> PurePosixPath:
        return PurePosixPath(PROVENANCE)

    # -- composing — decision 2's SHAPE half lives here, containment stays on `RunPaths` -----

    def payload(self, lead_id: str, seq: int) -> PurePosixPath:
        """`gather_raw/<lead_id>/<seq>.json` — the by-ref gather payload (O8's relative form,
        the string the queries row records)."""
        lead_id = _check_component(lead_id, what="lead_id")
        seq = _check_index(seq, what="seq")
        return self.gather_raw / lead_id / f"{seq}{PAYLOAD_SUFFIX}"

    def lead_claim(self, lead_id: str) -> PurePosixPath:
        """`gather_raw/<lead_id>.lead.json` — the per-lead exclusive-create claim sidecar."""
        lead_id = _check_component(lead_id, what="lead_id")
        return self.gather_raw / f"{lead_id}{LEAD_CLAIM_SUFFIX}"

    def gather_summary(self, lead_id: str) -> PurePosixPath:
        """`gather_summaries/<lead_id>.md`."""
        lead_id = _check_component(lead_id, what="lead_id")
        return self.gather_summaries / f"{lead_id}.md"

    def ticket_read(self, seq: int) -> PurePosixPath:
        """`ticket_reads/<seq>.json` — the retired pipeline judge's closed-ticket capture."""
        seq = _check_index(seq, what="seq")
        return self.ticket_reads / f"{seq}{PAYLOAD_SUFFIX}"

    def forward_check_trace(self, prefix: str, stem: str, n: int) -> PurePosixPath:
        """`wire_logs/<prefix>.<stem>.<n>.trace.jsonl`."""
        prefix = _check_component(prefix, what="prefix")
        stem = _check_component(stem, what="stem")
        n = _check_index(n, what="n")
        return self.wire_log_dir / f"{prefix}.{stem}.{n}{TRACE_SUFFIX}"

    def review_trace(self, role: str) -> PurePosixPath:
        """`wire_logs/review_<role>_trace.jsonl`."""
        role = _check_component(role, what="role")
        return self.wire_log_dir / f"review_{role}{REVIEW_TRACE_SUFFIX}"

    def review_record(self, turn: int = 1) -> PurePosixPath:
        """`review_record.<turn>.json`."""
        turn = _check_index(turn, what="turn")
        return PurePosixPath(f"{REVIEW_RECORD_PREFIX}{turn}.json")


#: The run layout, as one value. Stateless, so one instance serves every caller.
RUN_LAYOUT = RunLayout()


@dataclasses.dataclass(frozen=True)
class WireLogNames:
    """The LEAF names that land under a `wire_logs/` directory (#1077 D7).

    `observe.stage_trace_path(root, name)` joins one of these under whichever root a stage
    runs against — a run dir, an episode dir, a curator batch's tree — so the leaf is the only
    part the caller chooses, and it is the part that used to be composed by hand at four
    unrelated call sites out of two constants shared between three record families.

    `agent_trace` and `agent_framed_trace` are ONE PAIR and are spelled here together: the
    episode page finds a trace's framed companion by stripping the suffix and matching stems
    (`visualize_episode._load_wire_logs`), so a change to one that does not reach the other
    leaves every framed row keyed to a stem no trace holds — no error, just a page that
    renders no prompt/reply pairs. `stem_of` is the strip half, owned here for the same reason.
    """

    def agent_trace(self, agent_id: str) -> str:
        """`<agent_id>_trace.jsonl` — one stage seam's raw wire trace."""
        return f"{self._agent_stem(agent_id)}{AGENT_TRACE_SUFFIX}"

    def agent_framed_trace(self, agent_id: str) -> str:
        """`<agent_id>_framed_trace.jsonl` — its framed prompt/reply companion."""
        return f"{self._agent_stem(agent_id)}{AGENT_FRAMED_TRACE_SUFFIX}"

    def trace_key(self, name: str) -> str:
        """The key a trace and its FRAMED companion share — what the episode page pairs on.

        Both suffixes, in one function, because the pairing is the whole point: the page used
        to derive this key by two different hand-spelled arithmetics, one per branch — strip
        `_framed_trace.jsonl` and append `"_trace"`, or strip `.jsonl`. They agreed only
        because the two suffixes happened to line up. Either one moving left every framed row
        keyed to a stem no trace holds, and the page renders no prompt/reply pair, silently.

        Normalise the framed spelling onto the unframed one, then drop the extension — so the
        two halves cannot disagree whatever the suffixes become.
        """
        if name.endswith(AGENT_FRAMED_TRACE_SUFFIX):
            name = name[: -len(AGENT_FRAMED_TRACE_SUFFIX)] + AGENT_TRACE_SUFFIX
        return name.removesuffix(JSONL_EXT)

    def is_framed(self, name: str) -> bool:
        return name.endswith(AGENT_FRAMED_TRACE_SUFFIX)

    def is_agent_trace(self, name: str) -> bool:
        """An unframed stage-seam trace — the half the page reads rows from."""
        return name.endswith(AGENT_TRACE_SUFFIX)

    def forward_check(self, prefix: str, stem: str, n: int) -> str:
        """`<prefix>.<stem>.<n>.trace.jsonl` — the forward-check verifier's own family."""
        return f"{_check_component(prefix, what='prefix')}." \
               f"{_check_component(stem, what='stem')}." \
               f"{_check_index(n, what='n')}{TRACE_SUFFIX}"

    def curator_batch(self, batch_id: str, pid: int) -> str:
        """`<batch_id>.<pid>.trace.jsonl` — one curator spawn's own family."""
        return f"{batch_id}.{_check_index(pid, what='pid')}{TRACE_SUFFIX}"

    @staticmethod
    def _agent_stem(agent_id: str) -> str:
        """An agent id carries `:` (`judge:world-b`), which is not a filename character this
        design wants to reason about. Folded HERE rather than at each call site, where three
        copies of `agent_id.replace(':', '_')` stood."""
        return _check_component(str(agent_id).replace(":", "_"), what="agent_id")


#: The wire-log leaf names, as one value.
WIRE_LOG_NAMES = WireLogNames()


@dataclasses.dataclass(frozen=True)
class RunPaths:
    """One run's directories and its accessors — every name a run reads or writes.

    Every accessor resolves relative to ``run_dir``, so construct ``RunPaths(some_dir)`` on
    whichever root you hold. ONE root, deliberately: a caller needing a second (the per-case
    leg-output dir) takes it as its own argument rather than making every single-root
    construction carry an always-`None` `Optional`.

    A handful of accessors resolve relative to `run_dir`'s PARENT (the runs base) or its
    sibling `sessions/` directory instead — the three sidecars, `sessions_dir` and
    `session_db` — each documented at its own accessor rather than assumed of the class
    (decision 10 dissolved the idea of one shared root: each accessor answers against its OWN
    root).

    ``provenance`` IS THE ONE RUN-DIR ACCESSOR THAT DOES NOT RESOLVE ON EVERY BUNDLE. A
    caller holding an arbitrary run dir must read the stamp as ``_provenance.read`` returns it
    (``None`` = no stamp here), never as a file this class promises exists.
    """

    run_dir: Path

    def __post_init__(self) -> None:
        # The pydantic model this class used to be coerced a `str` here; a stdlib dataclass
        # does not, and `"…" / ALERT` is a `TypeError` at the first accessor. Coerced, so a
        # caller holding the directory as text (an env var, an argv) constructs as before.
        object.__setattr__(self, "run_dir", Path(self.run_dir))

    # -- content the run produced -----------------------------------------------------------

    @property
    def alert(self) -> Path:
        return self.run_dir / RUN_LAYOUT.alert

    @property
    def report(self) -> Path:
        return self.run_dir / RUN_LAYOUT.report

    @property
    def investigation(self) -> Path:
        return self.run_dir / RUN_LAYOUT.investigation

    @property
    def executed_queries(self) -> Path:
        return self.run_dir / RUN_LAYOUT.executed_queries

    @property
    def source_refs(self) -> Path:
        """No writer in the repo (claim R9 — test helpers only); the accessor exists because
        the answer-key set and the case-answer-key deny key on this name."""
        return self.run_dir / RUN_LAYOUT.source_refs

    @property
    def gather_raw(self) -> Path:
        return self.run_dir / RUN_LAYOUT.gather_raw

    @property
    def gather_summaries(self) -> Path:
        """The directory `gather_summary` composes into — the judge's directory-of-summaries
        role, walked whole by the driver's pointer builder and the archive."""
        return self.run_dir / RUN_LAYOUT.gather_summaries

    @property
    def lead_author(self) -> Path:
        return self.run_dir / RUN_LAYOUT.lead_author

    def payload(self, lead_id: str, seq: int) -> Path:
        """`gather_raw/<lead_id>/<seq>.json` — the by-ref gather payload (O8's absolute form)."""
        target = self.run_dir / RUN_LAYOUT.payload(lead_id, seq)
        return _confine(target, self.run_dir, what="payload")

    def payload_relpath(self, lead_id: str, seq: int) -> str:
        """O8's run-dir-relative form — the string the queries row records. Composed and
        returned unconditionally: no shape detection, no refusal for an already-absolute
        caller assumption (§7 non-material item 8) — choosing the right accessor is the
        caller's own duty."""
        return str(RUN_LAYOUT.payload(lead_id, seq))

    def lead_claim(self, lead_id: str) -> Path:
        """`gather_raw/<lead_id>.lead.json` — the per-lead exclusive-create claim sidecar."""
        target = self.run_dir / RUN_LAYOUT.lead_claim(lead_id)
        return _confine(target, self.run_dir, what="lead_claim")

    def gather_summary(self, lead_id: str) -> Path:
        """`gather_summaries/<lead_id>.md`."""
        target = self.run_dir / RUN_LAYOUT.gather_summary(lead_id)
        return _confine(target, self.run_dir, what="gather_summary")

    def ticket_read(self, seq: int) -> Path:
        """`ticket_reads/<seq>.json` — the retired pipeline judge's closed-ticket capture; the
        payload read cap keys on this name (D1's stated reason for keeping the accessor)."""
        target = self.run_dir / RUN_LAYOUT.ticket_read(seq)
        return _confine(target, self.run_dir, what="ticket_read")

    @property
    def wire_log(self) -> Path:
        return self.run_dir / RUN_LAYOUT.wire_log

    def forward_check_trace(self, prefix: str, stem: str, n: int) -> Path:
        """`wire_logs/<prefix>.<stem>.<n>.trace.jsonl` — the learning forward-check verifier's
        trace, written into the CITED run's own dir while reading it as evidence."""
        target = self.run_dir / RUN_LAYOUT.forward_check_trace(prefix, stem, n)
        return _confine(target, self.run_dir, what="forward_check_trace")

    def review_trace(self, role: str) -> Path:
        """`wire_logs/review_<role>_trace.jsonl` — one review stage's raw wrapped reply,
        re-homed from `challenge_gate` (#1077 D1)."""
        target = self.run_dir / RUN_LAYOUT.review_trace(role)
        return _confine(target, self.run_dir, what="review_trace")

    def review_record(self, turn: int = 1) -> Path:
        """`review_record.<turn>.json`, re-homed from `challenge_gate` (#1077 D1)."""
        target = self.run_dir / RUN_LAYOUT.review_record(turn)
        return _confine(target, self.run_dir, what="review_record")

    @property
    def tool_trace(self) -> Path:
        return self.run_dir / RUN_LAYOUT.tool_trace

    @property
    def policy_denials(self) -> Path:
        return self.run_dir / RUN_LAYOUT.policy_denials

    @property
    def budget(self) -> Path:
        return self.run_dir / RUN_LAYOUT.budget

    @property
    def circuit_breaker(self) -> Path:
        return self.run_dir / RUN_LAYOUT.circuit_breaker

    @property
    def lessons_loaded(self) -> Path:
        return self.run_dir / RUN_LAYOUT.lessons_loaded

    @property
    def ticket_write(self) -> Path:
        return self.run_dir / RUN_LAYOUT.ticket_write

    @property
    def session_pointer(self) -> Path:
        return self.run_dir / RUN_LAYOUT.session_pointer

    @property
    def runtime_html(self) -> Path:
        return self.run_dir / RUN_LAYOUT.runtime_html

    @property
    def box_sentinel(self) -> Path:
        return self.run_dir / RUN_LAYOUT.box_sentinel

    @property
    def provenance(self) -> Path:
        return self.run_dir / RUN_LAYOUT.provenance

    # -- upward: the runs base, and the sessions dir beside it -------------------------------

    def run_end_sidecar(self, runs_base: Path) -> Path:
        return Path(runs_base) / f"{self.run_dir.name}{RUN_END_SIDECAR_SUFFIX}"

    def scrub_verdict(self, runs_base: Path) -> Path:
        return Path(runs_base) / f"{self.run_dir.name}{SCRUB_VERDICT_SUFFIX}"

    def accounting_failures(self, runs_base: Path) -> Path:
        return Path(runs_base) / f"{self.run_dir.name}{ACCOUNTING_FAILURES_SUFFIX}"

    def sessions_dir(self, runs_base: Path) -> Path:
        """The sessions directory — a SIBLING of the runs base (claims C10/C15), never a
        child."""
        return Path(runs_base).parent / SESSIONS_DIRNAME

    def session_db(self, runs_base: Path, lineage_id: str) -> Path:
        """`<sessions>/<lineage_id>.db`. Refuses a lineage id the case-id pattern rejects
        EXACTLY as `session_store.store_path_for` does today — the pattern is pinned BY
        REFERENCE (RG-4), never re-spelled — and, beside that existing check (decision 20),
        refuses one that is not case-stable (`_run_id.is_case_stable_id`)."""
        from defender._run_id import is_case_stable_id
        from defender.runtime.session_store import CASE_ID_RE, InvalidCaseId

        if not isinstance(lineage_id, str) or not CASE_ID_RE.match(lineage_id):
            raise InvalidCaseId(repr(lineage_id))
        if not is_case_stable_id(lineage_id):
            raise InvalidCaseId(
                f"{lineage_id!r} is not case-stable — two ids differing only by case would "
                f"become one file wherever the filesystem folds case; use "
                f"{lineage_id.casefold()!r}"
            )
        return self.sessions_dir(runs_base) / f"{lineage_id}{SESSION_DB_SUFFIX}"


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
GATHER_RAW_SHAPE = rf"{RAW_MARKER}/l-{LEAD_ID_BODY}/[0-9]+\.json"

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
    re.compile(rf"{TICKET_READS_MARKER}/[0-9]+\.json"),
)

#: The case's ANSWER KEY: the finished investigation's own reasoning, its disposition, and the
#: query record behind them. Named as a set because the learning loop STAGES all four into
#: `<learning_run_dir>/` (the retired per-case cycle's input staging, and
#: `lead_repository.stage_tables`) — and that dir IS the gray-box actor's own run root, whose
#: whole purpose is to withhold them. `alert.json` is deliberately NOT here: it is the case
#: INPUT, handed to the actor in its own user message, so denying it would withhold nothing.
#:
#: The read gate spends this at `permission.files.names_case_answer_key`; the names live here
#: because this module already owns what a run dir is called.
CASE_ANSWER_KEY_NAMES = frozenset(
    {INVESTIGATION, REPORT, SOURCE_REFS, EXECUTED_QUERIES}
)

# `resolve()` on a hostile operand — a symlink cycle, an embedded NUL, a name past PATH_MAX.
_RESOLVE_ERRORS = (OSError, RuntimeError, ValueError)

#: Decision 2's ANCHORED SHAPE CHECK, applied to every caller-supplied path COMPONENT before it
#: is composed into a name: a `/`, an embedded NUL or newline, `.`/`..`, the empty string, or
#: anything past a filename component's practical length is refused outright — one rule every
#: composing accessor on this class (and `_episode_paths.EpisodePaths`) inherits.
_UNSAFE_COMPONENT_CHARS = re.compile(r"[/\x00\n]")
_COMPONENT_MAX_LEN = 255


def _check_component(value: object, *, what: str) -> str:
    """Decision 2's shape half: refuse a caller-supplied path component that is not a plain,
    single-segment name. Every composing accessor on `RunPaths`/`EpisodePaths` calls this on
    each string component before joining it — never a second, looser check per accessor."""
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _COMPONENT_MAX_LEN
        or value in (".", "..")
        or _UNSAFE_COMPONENT_CHARS.search(value)
    ):
        raise ValueError(f"{what} {value!r} is not a valid path component")
    return value


def _check_index(value: object, *, what: str) -> int:
    """The shape half for a NUMBERED component (`<seq>.json`, `review_record.<turn>.json`): a
    non-negative `int`, never a string that merely formats into the name — `"../x"` would."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{what} {value!r} is not a non-negative integer")
    return value


def _confine(candidate: Path, root: Path, *, what: str) -> Path:
    """Decision 2's containment half: refuse a composed path that resolves outside `root`.

    ONE REFUSAL TYPE with the write seam. A composed name that resolves outside its root is
    the same fact `_io.write_guarded` refuses at the open — an entry under the record's name
    that is not the plain file it should be (here: a planted link whose target leaves the
    tree) — so it raises the same alias-marked `OSError`, and every caller whose `except
    OSError` arm already records the write refusal handles this one identically instead of
    aborting on a `ValueError` it never expected (`close_tool._commit`'s record-first-report-
    second contract). A malformed ARGUMENT (`_check_component`/`_check_index`) stays a
    `ValueError`: that is the caller's bug, not the tree's state."""
    try:
        resolved_root = Path(root).resolve()
        resolved = Path(candidate).resolve()
    except _RESOLVE_ERRORS as e:
        raise _mark_alias(
            OSError(errno.ELOOP, f"{what}: {candidate} could not be resolved: {e}",
                    str(candidate)),
            is_alias=True) from e
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise _mark_alias(
            OSError(errno.ELOOP, f"{what}: {ALIAS_READ_REFUSAL} — {candidate} resolves "
                    f"outside {root}", str(candidate)),
            is_alias=True)
    return candidate


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


def plain_file(path: Path) -> bool:
    """True when ``path`` is a regular file with ONE name — ``artifact_file`` plus no hard link.

    The DESTINATION-side rule, ``_io.is_plain_entry`` — the same predicate ``write_guarded``
    applies before it replaces an entry. A source hard-linked elsewhere is still the bytes it
    is; a hard link at a destination is a second name for someone else's file, and a
    ``copy2`` onto it opens that file for writing — the copied bytes land wherever the other
    name lives. ``artifact_file`` cannot see this: a hard link IS a regular file to ``lstat``.
    """
    try:
        return is_plain_entry(path.lstat())
    except (OSError, ValueError):
        return False


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
