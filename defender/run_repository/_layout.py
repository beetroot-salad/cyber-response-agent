from __future__ import annotations

import dataclasses
import errno
import re
import stat
from pathlib import Path, PurePosixPath

from defender._io import ALIAS_READ_REFUSAL, _mark_alias, is_plain_entry
from defender._run_id import refuse_bad_case_id

# Stdlib `@dataclass`, not `defender._model.model`: the box entrypoint imports this module
# with no third-party package installed.


#: The run's one wire log and its subdirectory. Defined here (not in `runtime.observe`) so the
#: visualizers can import it without pydantic-ai. Every log that carries a wire body verbatim
#: lives under `WIRE_LOG_DIR` — the investigation's `llm_requests.jsonl`, each learning stage's
#: `<stage>.trace.jsonl`, and `review_{role}_trace.jsonl` (raw lens replies MAIN must never see).
#:
#: The subdirectory is a security boundary. MAIN's and GATHER's run-dir read shape
#: `under(run, SEG)` admits exactly one path segment, so a file one level down is unreadable
#: to both; at the run root, MAIN could read gather's raw payloads and gather could read MAIN's
#: transcript through this shared log. That argument covers only those two roles — others have
#: multi-segment or no shape filters — so `permission.files.names_wire_log_dir` also denies the
#: directory outright for every role; the directory is what makes that deny addressable.
#:
#: Other root-level streams (`tool_trace.jsonl` tool names, `policy_denials.jsonl` digests,
#: counters) replay no agent's context. `runtime.html` does inline MAIN's transcript at the run
#: root; it is safe only because it is rendered after the run's agents have exited. Anything
#: that renders it during a run must move it under `wire_logs/`.
WIRE_LOG_DIR = "wire_logs"
WIRE_LOG = "llm_requests.jsonl"

#: The run's provenance stamp. Shared with `scripts/workspace_map`, which hides it from the
#: model-facing directory view; an independent spelling would stop hiding it after a rename.
PROVENANCE = "provenance.json"

#: The `tool-return` metadata key under which the TOON view gate keeps the tool's original
#: JSON. Here so the visualizer can read it without importing pydantic-ai via
#: `runtime.toon_gate` (which re-exports it).
GATE_METADATA_KEY = "json"

# ======================================================================================
# Every run-level record name, as a named constant. `scripts/lint/lint_run_records.py` reads
# its protected names and composed parts off every module-level UPPERCASE string constant here.
# ======================================================================================

ALERT = "alert.json"
REPORT = "report.md"
INVESTIGATION = "investigation.md"
EXECUTED_QUERIES = "executed_queries.jsonl"
SOURCE_REFS = "source_refs.yaml"

#: The by-ref gather payload directory and the ticket-read capture directory, imported by
#: `runtime/permission/files.py`'s deny predicates.
RAW_MARKER = "gather_raw"
GATHER_SUMMARIES_DIRNAME = "gather_summaries"
LEAD_AUTHOR_DIRNAME = "lead_author"
TICKET_READS_MARKER = "ticket_reads"

#: Discriminating name fragments the lint gate substring-matches. Generic suffixes (`.json`,
#: `.db`) are kept out of this set: they match far too many unrelated literals.
LEAD_CLAIM_SUFFIX = ".lead.json"
REVIEW_RECORD_PREFIX = "review_record."
TRACE_SUFFIX = ".trace.jsonl"

#: The review gate's trace suffix (`RunPaths.review_trace`). Deliberately separate from
#: `AGENT_TRACE_SUFFIX` despite the same value: different records (run/role vs episode/agent),
#: and renaming one must not silently rename the other.
REVIEW_TRACE_SUFFIX = "_trace.jsonl"

#: The line-delimited extension, so `trace_key` can drop it without a literal.
JSONL_EXT = ".jsonl"

#: The stage seam's agent trace and its framed companion under an episode's `wire_logs/`; the
#: episode page pairs them by stem, so both are composed by `WIRE_LOG_NAMES`.
AGENT_TRACE_SUFFIX = "_trace.jsonl"
AGENT_FRAMED_TRACE_SUFFIX = "_framed_trace.jsonl"
#: The episode layout's `served/` prefix — here because the lint gate's part set is read off
#: this module; `_episode_paths.py` imports it.
SERVED_PREFIX = "served/"

#: Generic suffixes, not discriminating parts; the gate catches hand-rolled compositions of
#: these through its accessor-derived pass instead.
PAYLOAD_SUFFIX = ".json"
SESSION_DB_SUFFIX = ".db"

TOOL_TRACE = "tool_trace.jsonl"
POLICY_DENIALS = "policy_denials.jsonl"
BUDGET = "budget.json"
CIRCUIT_BREAKER = "circuit_breaker.json"
LESSONS_LOADED = "lessons_loaded.jsonl"
SESSION_POINTER = "session_store_pointer.json"
RUNTIME_HTML = "runtime.html"
#: The box startup sentinel.
BOX_SENTINEL = ".box-sentinel"

#: The four sidecars beside the run dir in the runs base, keyed `<run_id><suffix>`.
RUN_END_SIDECAR_SUFFIX = ".run-end.json"
SCRUB_VERDICT_SUFFIX = ".scrub-verdict.json"
ACCOUNTING_FAILURES_SUFFIX = ".accounting_failures.json"
#: The case-ticket write's receipt: a host record the box must neither plant nor block (#1107).
TICKET_WRITE_SUFFIX = ".ticket-write.json"
#: The four host-only sidecars, each `<run id><suffix>` beside the run folder in the runs base.
_SIDECAR_SUFFIXES = (RUN_END_SIDECAR_SUFFIX, SCRUB_VERDICT_SUFFIX, ACCOUNTING_FAILURES_SUFFIX,
                     TICKET_WRITE_SUFFIX)
#: The tail a sidecar write's staged file carries before its rename (`_io.staged_leaf`:
#: `.staged-` and lowercase hex digits; one or more, #1105 DV-5).
_STAGED_TAIL = re.compile(r"\.staged-[0-9a-f]+\Z")

#: The sessions directory is a sibling of the runs base, never a child.
SESSIONS_DIRNAME = "sessions"


# ==========================================================================================
# THE LAYOUT — every run record as a path relative to the run dir.
#
# Mirrors `_episode_paths.EpisodeLayout`: `_io.Bound` readers address records relative to the
# root they hold, never by absolute path. The sidecars and session store resolve against the
# runs base, so they have no relative form here.
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

    # -- composing — shape checks here; containment stays on `RunPaths` ----------------------

    def payload(self, lead_id: str, seq: int) -> PurePosixPath:
        """`gather_raw/<lead_id>/<seq>.json` — the by-ref gather payload, as the queries row
        records it."""
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
    """The leaf names that land under a `wire_logs/` directory, joined under any root by
    `observe.stage_trace_path(root, name)`.

    `agent_trace` and `agent_framed_trace` are a pair the episode page matches by stem, so
    they (and `trace_key`) are defined together; if they diverged, framed rows would silently
    match no trace.
    """

    def agent_trace(self, agent_id: str) -> str:
        """`<agent_id>_trace.jsonl` — one stage seam's raw wire trace."""
        return f"{self._agent_stem(agent_id)}{AGENT_TRACE_SUFFIX}"

    def agent_framed_trace(self, agent_id: str) -> str:
        """`<agent_id>_framed_trace.jsonl` — its framed prompt/reply companion."""
        return f"{self._agent_stem(agent_id)}{AGENT_FRAMED_TRACE_SUFFIX}"

    def trace_key(self, name: str) -> str:
        """The key a trace and its framed companion share — what the episode page pairs on.
        Normalises the framed spelling onto the unframed one, then drops the extension, so the
        two cannot disagree whatever the suffixes become.
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
        """An agent id with `:` (`judge:world-b`) folded to a filename-safe component."""
        return _check_component(str(agent_id).replace(":", "_"), what="agent_id")


#: The wire-log leaf names, as one value.
WIRE_LOG_NAMES = WireLogNames()


@dataclasses.dataclass(frozen=True)
class RunPaths:
    """One run's directories and its accessors — every name a run reads or writes.

    18 accessors (a census test checks this count against the set it pins).

    Accessors resolve relative to ``run_dir``, except the four sidecars, `sessions_dir` and
    `session_db`, which take the runs base explicitly.

    ``provenance`` may be absent on an arbitrary run dir: read it via ``_provenance.read``
    (``None`` = no stamp), never assume the file exists.
    """

    run_dir: Path

    def __post_init__(self) -> None:
        # Coerce, so callers holding the directory as text (env var, argv) still work.
        object.__setattr__(self, "run_dir", Path(self.run_dir))

    @staticmethod
    def sidecar_owner(name: str) -> str | None:
        """The run id a sidecar file named `name` belongs to — `<id>` of `<id><suffix>`, or of
        the staged `<id><suffix>.staged-<hex>` a sidecar write creates first — or `None` when
        `name` is not shaped like a sidecar. The one statement of the sidecar clause (#1105
        D2.1, MF-21): run setup and `open_run` refuse an id it answers for, and the runs
        repository's listings take a regular file it answers for as a known sidecar when
        `RunId.parse` admits the owner (any other such file is refused)."""
        bare = name[: m.start()] if (m := _STAGED_TAIL.search(name)) else name
        for suffix in _SIDECAR_SUFFIXES:
            if bare.endswith(suffix) and len(bare) > len(suffix):
                return bare[: -len(suffix)]
        return None

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
        """No production writer; the accessor exists because the case-answer-key deny keys on
        this name."""
        return self.run_dir / RUN_LAYOUT.source_refs

    @property
    def gather_raw(self) -> Path:
        return self.run_dir / RUN_LAYOUT.gather_raw

    @property
    def gather_summaries(self) -> Path:
        """The directory `gather_summary` composes into, walked whole by the driver's pointer
        builder and the archive."""
        return self.run_dir / RUN_LAYOUT.gather_summaries

    @property
    def lead_author(self) -> Path:
        return self.run_dir / RUN_LAYOUT.lead_author

    def payload(self, lead_id: str, seq: int) -> Path:
        """`gather_raw/<lead_id>/<seq>.json` — the by-ref gather payload."""
        target = self.run_dir / RUN_LAYOUT.payload(lead_id, seq)
        return _confine(target, self.run_dir, what="payload")

    def payload_relpath(self, lead_id: str, seq: int) -> str:
        """The payload's run-dir-relative form — the string the queries row records."""
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
        """`ticket_reads/<seq>.json` — the retired pipeline judge's closed-ticket capture, kept
        because the payload read cap keys on this name."""
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
        """`wire_logs/review_<role>_trace.jsonl` — one review stage's raw wrapped reply."""
        target = self.run_dir / RUN_LAYOUT.review_trace(role)
        return _confine(target, self.run_dir, what="review_trace")

    def review_record(self, turn: int = 1) -> Path:
        """`review_record.<turn>.json`."""
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

    def ticket_write(self, runs_base: Path) -> Path:
        return Path(runs_base) / f"{self.run_dir.name}{TICKET_WRITE_SUFFIX}"

    def sessions_dir(self, runs_base: Path) -> Path:
        """The sessions directory (a sibling of the runs base), from `SessionPaths`."""
        return SessionPaths(runs_base).sessions_dir

    def session_db(self, runs_base: Path, lineage_id: str) -> Path:
        """`<sessions>/<lineage_id>.db` — asked of `SessionPaths`, which refuses a malformed or
        case-unstable lineage id (`InvalidCaseId`)."""
        return SessionPaths(runs_base).session_db(lineage_id)


@dataclasses.dataclass(frozen=True)
class SessionPaths:
    """The session store's directory, per-lineage database files, and trust root — built from
    the runs base, since one store spans a run and all its resumes and forks.
    """

    runs_base: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "runs_base", Path(self.runs_base))

    @property
    def trust_root(self) -> Path:
        """The runs base's parent: the highest point no box gets a writable mount on. Anchoring
        higher would refuse on a symlinked runs base (`/tmp` on macOS)."""
        return self.runs_base.parent

    @property
    def sessions_dir(self) -> Path:
        """A sibling of the runs base, never a child."""
        return self.trust_root / SESSIONS_DIRNAME

    def session_db(self, lineage_id: str) -> Path:
        """`<sessions>/<lineage_id>.db`. Raises `InvalidCaseId` for a malformed or
        case-unstable lineage id."""
        refuse_bad_case_id(lineage_id)
        return self.sessions_dir / f"{lineage_id}{SESSION_DB_SUFFIX}"


# A run bundle is always `runs_dir / <run_id>`, so a recorded `source_run_dir` contributes
# only a name. Degenerate names map to a child that cannot exist, reading as a missing bundle.
_NO_BUNDLE = "_unresolvable_source_run_dir"
_NAMELESS = {"", ".", ".."}

#: The lead-id alphabet, the body of `l-<body>`. Every lead-id validator and payload path
#: shape composes off this; if they disagreed, gather's read gate could refuse gather's own
#: payload. Bounded because ids become filename components (64 is well under 255).
LEAD_ID_BODY = r"[A-Za-z0-9]{1,64}"

#: `\Z`, not `$`: `$` also matches before a trailing newline (`l-abc\n`).
LEAD_ID_RE = re.compile(rf"^l-{LEAD_ID_BODY}\Z")

#: The gather payload family, relative to a run dir; shared with the runtime read gate.
GATHER_RAW_SHAPE = rf"{RAW_MARKER}/l-{LEAD_ID_BODY}/[0-9]+\.json"

# The two by-ref payload families a run writes; anything else in the queries table is not
# an artifact. `[0-9]`, not `\d`, which matches every Unicode decimal (`٣.json`).
_PAYLOAD_SHAPES = (
    re.compile(GATHER_RAW_SHAPE),
    re.compile(rf"{TICKET_READS_MARKER}/[0-9]+\.json"),
)

#: The case's answer key: the finished investigation, its disposition, and the query record.
#: The learning loop stages these into a run root that must withhold them from the reader
#: (`permission.files.names_case_answer_key`). `alert.json` is the case input, not the key.
CASE_ANSWER_KEY_NAMES = frozenset(
    {INVESTIGATION, REPORT, SOURCE_REFS, EXECUTED_QUERIES}
)


def is_case_answer_key(name: str) -> bool:
    """Is `name` one of the case's answer-key artifacts? A predicate, so the read gate asks
    rather than holding its own copy of the names.
    """
    return name in CASE_ANSWER_KEY_NAMES


def gather_summaries_shape(segment: str) -> str:
    """`gather_summaries/<segment>` as a regex fragment, the directory name escaped. It builds
    a read grant, so an unescaped metacharacter would silently widen it.
    """
    return f"{re.escape(GATHER_SUMMARIES_DIRNAME)}/{segment}"

# `resolve()` on a hostile operand — a symlink cycle, an embedded NUL, a name past PATH_MAX.
_RESOLVE_ERRORS = (OSError, RuntimeError, ValueError)

#: The shape check for every caller-supplied path component: no `/`, NUL or newline, not
#: `.`/`..`/empty, and within a filename component's length.
_UNSAFE_COMPONENT_CHARS = re.compile(r"[/\x00\n]")
_COMPONENT_MAX_LEN = 255


def _check_component(value: object, *, what: str) -> str:
    """Refuse a caller-supplied path component that is not a plain, single-segment name.
    Every composing accessor on `RunPaths`/`EpisodePaths` uses this one check."""
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
    """The shape check for a numbered component: a non-negative `int`, never a string (which
    could format as `"../x"`)."""
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{what} {value!r} is not a non-negative integer")
    return value


def _confine(candidate: Path, root: Path, *, what: str) -> Path:
    """Refuse a composed path that resolves outside `root`.

    Raises the same alias-marked `OSError` as `_io.write_guarded` (it is the same fact: a
    planted link), so callers' `except OSError` arms handle it. Malformed arguments stay
    `ValueError`, being the caller's bug rather than the tree's state."""
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
    """`kind` of the entry itself, never its target. Fails closed."""
    try:
        return bool(kind(path.lstat().st_mode))
    except (OSError, ValueError):
        return False


def artifact_file(path: Path) -> bool:
    """True when ``path`` is a regular file, not a link (or FIFO, or device) wearing its name.

    The run dir is the box's rw bind and nothing the system writes there is a link, so a link
    is planted. ``is_file()`` follows it, and copying would import the target's bytes into
    learning state under an artifact's name.
    """
    return _lstat_is(path, stat.S_ISREG)


def plain_file(path: Path) -> bool:
    """True when ``path`` is a regular file with one name — the destination-side rule
    (``_io.is_plain_entry``). Copying onto a hard link would write into another name's file.
    """
    try:
        return is_plain_entry(path.lstat())
    except (OSError, ValueError):
        return False


def artifact_dir(path: Path) -> bool:
    """True when ``path`` is a real directory rather than a link to one. Needed because
    `copytree(symlinks=True)` still follows a symlinked root.
    """
    return _lstat_is(path, stat.S_ISDIR)


def resolve_run_bundle(runs_dir: Path, source_run_dir: object) -> Path:
    """The run bundle a recorded ``source_run_dir`` names, always under ``runs_dir``.

    The recorded string is a label, never an address: only its last segment is honored, so
    neither a traversal nor an absolute path can move the read off the runs root.

    Typed ``object``: the value comes off a queued JSONL row, and a non-string must read as a
    missing bundle rather than raise mid-batch."""
    if not isinstance(source_run_dir, str):
        return runs_dir / _NO_BUNDLE
    name = Path(source_run_dir.rstrip("/")).name
    return runs_dir / (_NO_BUNDLE if name in _NAMELESS else name)


def contained_payload(run_dir: Path, payload_path: object) -> Path | None:
    """The by-ref payload ``payload_path`` names under ``run_dir``, or ``None`` if it names
    anything else. Two gates:

    1. **shape** — must spell a payload family a run writes, so `..`, absolute paths and stray
       names fail outright.
    2. **containment after resolution** — a well-formed name may be a planted symlink, so the
       resolved target must lie inside the resolved ``run_dir``.

    A `resolve()` fault fails closed."""
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
    # Unresolved: callers take `relative_to(run_dir)`, which a symlinked run root would break.
    return candidate
