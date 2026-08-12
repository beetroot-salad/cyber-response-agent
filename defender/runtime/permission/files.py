"""The file gates: deny-by-default read allowlist + write allowlist.

Both return a plain `Decision`. Reads must resolve inside the run dir or the
defender corpus (with a belt-and-suspenders secret/ground-truth denylist on top);
writes must `fullmatch` one of the agent's `policy.write_allow` patterns (its
declared paths — a flat, deny-by-default allowlist). On top of the allowlist, the
run's two model-authored output artifacts get an OUTPUT-STRUCTURE gate (#629) —
this module decides WHICH artifact a resolved path is, and `defender._artifact_schema`
decides whether the proposed text is a well-formed one (#714).
`is_untrusted_read` flags attacker-influenced data the caller must tag-wrap."""

from __future__ import annotations

import re
from pathlib import Path

from defender import _artifact_schema
from defender._run_paths import WIRE_LOG_DIR
from defender.runtime import bash_policy

from .decision import Decision
from .policy import AgentPolicy

# Everything `Path.resolve()` can throw on a hostile operand, so every gate that
# resolves one fails CLOSED instead of propagating. `OSError`/`RuntimeError` are the
# filesystem + symlink-cycle cases; `ValueError` is an embedded NUL (`cat a\0b`),
# which `shlex` happily tokenizes into an operand — without it the exception escapes
# `decide_read`/`decide_bash` and crashes the tool call rather than denying it.
RESOLVE_ERRORS: tuple[type[BaseException], ...] = (OSError, RuntimeError, ValueError)


def _is_within(p: Path, root: Path) -> bool:
    """True iff resolved path `p` is `root` or below it."""
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False


def denylisted(rp: Path) -> bool:
    """True iff a resolved path hits the secret/ground-truth denylist — a denied
    filename substring (`.env` / `cases.json` / `ground_truth` / `credentials`) or a
    denied path component (`.ssh`). Belt-and-suspenders that applies INSIDE every
    allowed root, on BOTH read surfaces: the read tool (`decide_read`) and the judge's
    bash operand lane (`read_allowed_path`) — so the two surfaces can't disagree about a
    denied file that resolves within-root (the held-out `ground_truth.yaml` under the
    defender corpus, a captured `.env` in the run dir)."""
    return any(d in set(rp.parts) for d in bash_policy.read_deny_dirs()) or any(
        s in rp.name for s in bash_policy.read_deny_substrings()
    )


def _resolved_read_roots(
    policy: AgentPolicy, run_dir: Path, defender_dir: Path
) -> tuple[Path, ...]:
    """The resolved roots a read must land within for `policy`. When
    `policy.read_confine` is non-empty it REPLACES the `defender_dir` base (the
    gray-box confine — a confined actor sees only its lesson corpora, not the whole
    corpus); `run_dir` and the agent's `read_roots` still widen. Empty confine is
    the legacy `{run_dir, defender_dir, *read_roots}`. May raise `OSError` /
    `RuntimeError` / `ValueError` from `resolve()` (a symlink cycle, an embedded NUL) —
    every caller FAILS CLOSED."""
    base = policy.read_confine if policy.read_confine else (Path(defender_dir),)
    return tuple(
        r.resolve() for r in (Path(run_dir), *base, *policy.read_roots)
    )


def build_write_allow(root: Path, *, suffix: str = "") -> re.Pattern[str]:
    """Build one `AgentPolicy.write_allow` pattern admitting `root` itself and everything
    under it — optionally only paths whose basename ends `suffix` (a `re`-escaped literal,
    e.g. `".md"`). `decide_write` `fullmatch`es this against the RESOLVED operand, so `root`
    is `resolve()`d here to align the two, and a `..` in the operand is collapsed before the
    match (a subtree, not a string prefix — `<root>-evil/x` can't match either). The write
    twin of the bash lane's baked reader anchors (`policies._common`), used by every writer's
    policy (`policies.main`, `lead_author_engine`) so the flat allowlist has one builder."""
    base = re.escape(str(root.resolve()))
    tail = r"/[^\x00]*" + re.escape(suffix) if suffix else r"(?:/[^\x00]*)?"
    return re.compile(base + tail)


def build_scoped_write_allow(root: Path, *, suffix: str = "") -> re.Pattern[str]:
    """Build one `AgentPolicy.write_allow` pattern admitting exactly the DIRECT CHILDREN of
    `root` that the corpus walk can see, narrowed to the SAME filename segment class the read
    side's `Grant.scope` shapes use (`grant.SEG`, `[\\w.@=+-]+`) rather than
    `build_write_allow`'s `[^\\x00]*`, foreclosing a space/newline write-only name from the
    frame-injection channel a wide tail would otherwise open (#691 MD-7). The read-back grants
    stay WIDER (the curator's `cat`/`rm` carry `under(corpus, TREE)`), which is the safe
    direction: every name this admits is readable back, and nothing writable is unreadable.
    `root` is `resolve()`d to align with the RESOLVED operand `decide_write` matches against,
    same as `build_write_allow`.

    WHAT THE WALK CAN SEE, exactly (#776): its only caller is the curator's lesson-corpus
    write allow, and every corpus reader — retrieval, the manifest, the idempotency scan, the
    frontend — goes through `_corpus.iter_lesson_paths`, which is `glob('*.md')` (flat) MINUS
    any name starting `_` (the corpus `_TEMPLATE.md`). A write outside that set produced a
    file no reader could ever see, which the environment forward-check then certified as
    retrievability-verified off a basename collision with a visible sibling. So the tail is
    one level AND non-underscore: `<corpus>/sub/x.md` and `<corpus>/_x.md` are equally
    invisible, and both are now refused at the source. `verify_forward/env.py` rejects the
    same shape independently."""
    from .grant import SEG

    base = re.escape(str(root.resolve()))
    tail = rf"/(?!_){SEG}"
    if suffix:
        tail += re.escape(suffix)
    return re.compile(base + tail)


def build_named_write_allow(root: Path, names: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    """A POSITIVE allow-list of EXACTLY `<root>/<name>` for each name — one anchored
    pattern per basename, matched against the RESOLVED operand (#631, S2). Deliberately
    tighter than `build_write_allow`'s subtree/`.md`-suffix forms: a suffix filter is a
    filename filter, not a subtree narrowing (`decide_write` applies no path shapes), so
    it would admit `gather_raw/evil.md` and `sub/report.md` at depth. Resolving both
    sides means an alias that resolves to `<root>/investigation.md` matches the
    investigation.md pattern (and is then invlang-validated on the RESOLVED name), while
    `<root>/sub/report.md` never matches the report.md pattern."""
    base = re.escape(str(root.resolve()))
    return tuple(re.compile(base + "/" + re.escape(name)) for name in names)


def read_allowed_path(
    path: str | Path, *, run_dir: Path | None, defender_dir: Path | None,
    policy: AgentPolicy,
) -> bool:
    """Whether a file operand resolves within `policy`'s read roots — the
    ROOTS half of `decide_read` (the shape half is `policy.read_allow`), reused by `decide_write`
    for its `write_allow ⊆ read roots` check. FAILS CLOSED: a `resolve()` error (a symlink cycle,
    an embedded NUL) OR a missing root context (`run_dir`/`defender_dir` `None`) returns `False`,
    never raises. The secret/ground-truth denylist IS applied (parity with `decide_read`, so a
    write can't land on a denied file the read tool refuses — the held-out `ground_truth.yaml`, a
    captured `.env`), and so is the `wire_logs/` component: the wire logs are HOST-side
    observability, so no agent may AUTHOR one either. Resting that on "no writer's `write_allow`
    happens to reach there" would leave the run's own spend record one widened write shape away
    from forgeable, which is the property `tests/test_budget_write_scope_631.py` exists to hold.
    It applies NO path shapes: containment by shape is the caller's job (the
    read tool checks `read_allow`; the bash lane checks the claiming grant's scope)."""
    if run_dir is None or defender_dir is None:
        return False  # no root context to gate against — fail closed
    try:
        rp = Path(path).resolve()
        roots = _resolved_read_roots(policy, run_dir, defender_dir)
    except RESOLVE_ERRORS:
        return False
    if denylisted(rp) or names_wire_log_dir(rp):
        return False  # a secret / ground-truth file, or a wire log, even inside a root
    return any(_is_within(rp, root) for root in roots)


def decide_read(
    path: Path, *, run_dir: Path, defender_dir: Path, policy: AgentPolicy
) -> Decision:
    """Allow/deny a file read — a **deny-by-default allowlist** over the RESOLVED path, the
    shape `decide_write` already uses for writes. Two gates, both necessary:

    1. **the roots** — a read must resolve inside the run dir, the defender corpus
       (`defender_dir`) or, when the policy declares a `read_confine`, that confine set IN
       PLACE of the corpus (the gray-box actor sees only its lesson dirs), plus the agent's
       declared `read_roots` (the judge's comparison dir under the investigation run dir).
       `resolve()` collapses `..` and symlinks, so an allowed-root prefix can't be escaped;
    2. **`policy.read_allow`** — the agent's path SHAPES (#575). This is the same tuple object
       the agent's bash `cat` grant carries as its scope, so the read tool admits exactly the
       paths `cat` does: read↔bash parity by construction, with nothing to keep in sync. This
       is also what makes "main cannot read gather_raw" positive enumeration rather than a
       clamp — the gather_raw shape is simply not in main's list. Empty `read_allow` (every
       non-reader agent) applies no shape filter, leaving the gate root-only.

    On top of both, the declarative secret/ground-truth denylist (`bash_policy.json`) denies a
    sensitive file that lands INSIDE an allowed shape — a captured `.env` in the run dir, the
    eval `cases.json`/`ground_truth.yaml` — cheap belt-and-suspenders applied to every agent.
    A `resolve()` error (a symlink cycle, an embedded NUL) FAILS CLOSED rather than propagating
    out of a blocking gate."""
    p = Path(path)
    try:
        rp = p.resolve()
        roots = _resolved_read_roots(policy, run_dir, defender_dir)
    except RESOLVE_ERRORS:
        return Decision(False, f"Blocked: {p!r} could not be resolved (failing closed).")
    if not any(_is_within(rp, root) for root in roots):
        return Decision(
            False,
            "Blocked: reads are limited to the run dir, the defender corpus (or "
            "this agent's read confine), and its declared roots; "
            f"{p} is outside them.",
        )
    admitted = any(shape.fullmatch(str(rp)) for shape in policy.read_allow)
    # The attacker-influenced channel is OPT-IN, for EVERY agent — including one that declares no
    # shapes at all. An empty `read_allow` means "no shape filter", which is a WIDENING default,
    # and `gather_raw` is the one path class where a widening default is a security failure: the
    # learning loop STAGES the investigation's whole `gather_raw/` tree into the learning run dir
    # (`lead_repository.stage_tables`), and that dir IS the actor's own root — so a root-only read
    # would hand the gray-box actor the very payloads it must write its story WITHOUT seeing.
    # Reading a payload therefore requires a shape that NAMES it (gather's own raw shape; the
    # judge's scope over its comparison roots), never merely a root that happens to contain it.
    # This is the same enumeration everywhere else obeys, applied to the default that would
    # otherwise widen; the reason is the one the model needs (re-dispatch gather), and the e2e
    # deny-tail asserts it as a substring.
    if _names_raw(rp) and not admitted:
        return Decision(False, RAW_DENY_REASON)
    # `wire_logs/` is denied OUTRIGHT — not "unless a shape admits it", the way `gather_raw` is
    # one line up. That asymmetry is the difference between the two path classes: GATHER
    # legitimately reads payloads, so raw has to stay opt-in-able, while a wire log is host
    # observability that NO agent has business reading. Making it unconditional is also what
    # makes it work at all here, because the two lanes that need it cannot be reached by a
    # shape: the JUDGE's `cat` scope is `under(run, TREE)`, which fullmatches a subdirectory
    # and would set `admitted`, and the ACTOR declares no shapes at all, so `admitted` is
    # never True for it and no positive enumeration can ever exclude anything.
    if names_wire_log_dir(rp):
        return Decision(False, WIRE_LOG_DENY_REASON)
    if policy.read_allow and not admitted:
        return Decision(
            False,
            f"Blocked: {rp.name} is not a readable path for this agent — its reads are the "
            "paths it declares (its own run dir + the corpus `.md` under "
            "lessons/skills/examples), and this is not one of them.",
        )
    # Belt-and-suspenders: a secret / ground-truth file INSIDE an allowed shape is still denied
    # (substrings match the filename, dirs match any path component). Shared with the bash
    # operand lane (`bash._in_scope`) so both surfaces agree.
    if denylisted(rp):
        return Decision(False, f"Blocked: {rp.name} is a denied read (secrets / ground truth).")
    return Decision(True)


# The `gather_raw/` path component, and the reason a read of one earns. Both used to live in
# `hooks/block_main_loop_raw_access.py`, a retired `claude -p` PreToolUse script whose OTHER
# mechanism — a `RAW_MARKER in <command text>` substring clamp — this package deliberately does
# NOT implement (see `bash.py`: containment is positive grant enumeration, and the substring scan
# wrongly denied `… | grep gather_raw`, where the word is a search PATTERN, not a path). Only the
# marker and the reason survived that supersession, and this is their sole reader.
RAW_MARKER = "gather_raw"
RAW_DENY_REASON = (
    "Blocked: the main loop must not read gather_raw/. Gather's returned "
    "summary is the authoritative record (defender SKILL §Principles). If an "
    "obligation came back unaddressed, re-dispatch gather naming that "
    "obligation more sharply — never a field list or a filter — and do not "
    "Read/Grep/jq the raw payload from the main loop; that defeats the "
    "subagent isolation."
)


# The `wire_logs/` path component (`_run_paths.WIRE_LOG_DIR`, the layout's own name for it) and the
# reason a read of one earns. Every WIRE log in the tree writes under this component — the
# runtime's wire log at `<run_dir>/wire_logs/`, every learning stage's trace at
# `<learning_run_dir>/wire_logs/` — so ONE component test covers the whole class. NOT every
# `RequestLogger`: `observe.denial_logger` uses the same class for `<run_dir>/policy_denials.jsonl`
# and stays at the root deliberately, because it projects a parameter DIGEST rather than the blob.
# The class this component names is "carries a wire body verbatim", not "is a RequestLogger".
#
# WHY A DENY AND NOT JUST A SHAPE. A wire log holds another agent's context verbatim, which makes
# it a boundary wherever two roles share a root. Moving it into a subdirectory is enough for MAIN
# and GATHER, whose read shape is a single segment — but that is a property of THEIR shapes, not
# of subdirectories, and the learning lane has neither: the JUDGE reads `under(run, TREE)` (a
# subdirectory fullmatches) and the ACTOR declares no shape at all (root containment only, so
# every depth is admitted). The concrete case is the gray-box actor: `_names_raw` above keeps it
# out of `gather_raw/`, and `judge_trace.jsonl` at the learning run dir's root handed it the SAME
# payloads back through the judge's prompt (`judge/compare.unredacted_exemplar` — real values,
# not the oracle's scrubbed skeleton), with both legs of an `inconclusive` case running
# CONCURRENTLY against one `LegDirs` and a re-LEARN reopening the dir with the previous pass's
# traces still in it. The component is what holds; the subdirectory alone is not.
# DISTINCTIVE ON PURPOSE, like `gather_raw` and `ticket_reads` beside it. This deny is
# unconditional and applies inside EVERY read root, not just a run dir — and the judge's shapes
# span the whole `defender/` tree — so an ordinary word here would be a trap: a system skill or
# query-catalog dir that happened to be named for observing would go unreadable for every agent,
# with a reason about wire logs that has nothing to do with the file.
WIRE_LOG_MARKER = WIRE_LOG_DIR
WIRE_LOG_DENY_REASON = (
    "Blocked: wire_logs/ holds this run's wire logs — the verbatim request/response stream of "
    "every agent that shares this root, including payload bytes and transcripts this agent is "
    "deliberately not shown. It is host-side observability, readable by no agent. Work from "
    "the artifacts your own role is given."
)


def names_wire_log_dir(p: Path) -> bool:
    """Whether a resolved path is INSIDE an `wire_logs/` dir — a path COMPONENT test, for the
    reason `_names_raw` gives below: a substring scan is decided by text the path's owner does
    not control.

    Public, and shared with the bash operand lane (`bash._in_scope`) exactly as `denylisted` is,
    so the two read surfaces cannot disagree about a wire log that resolves within-root. That
    sharing is not decoration here: the JUDGE holds a `cat` grant whose scope is
    `under(run, TREE)`, so without this the bash lane would admit the very file `decide_read`
    refuses it."""
    return WIRE_LOG_MARKER in p.parts


def _names_raw(p: Path) -> bool:
    """Whether a resolved path is INSIDE `gather_raw/` — a path COMPONENT test, never a substring
    scan of the whole string. A substring scan is decided by text the path's owner does not
    control: an ancestor dir that merely carries the word (a pytest tmp dir named
    `test_gather_raw_…`, a checkout under `~/gather_raw-notes/`) would tag every file in the tree
    as an attacker-influenced payload. The component is the fact; the substring was a proxy."""
    return RAW_MARKER in p.parts


# The two path components that together name a draft query template:
# `{defender_dir}/skills/gather/queries/{system}/_draft/{verb}.md`.
QUERIES_MARKER = "queries"
DRAFT_MARKER = "_draft"


def _names_query_draft(p: Path) -> bool:
    """Whether a resolved path is a DRAFT query template — inside `_draft/` under the gather query
    catalog. Two path COMPONENTS, for the reason `_names_raw` gives: `_draft` alone would tag any
    file under any dir of that name anywhere in the tree."""
    return QUERIES_MARKER in p.parts and DRAFT_MARKER in p.parts


def is_untrusted_read(path: Path) -> bool:
    """True for reads of attacker-influenced data the caller must SALT-TAG WRAP: the alert
    payload, the raw gather payloads, and a DRAFT query template.

    Keyed on the gather_raw SHAPE, and deliberately kept when the raw *clamp* was deleted
    (#575): the clamp was containment (now positive enumeration), while this is the TRUST
    boundary. gather_raw is the primary attacker-influenced channel — untagging it would leave
    the model unable to tell data from instructions, failing the prompt-injection defense OPEN.
    A deletion of the clamp is not a deletion of the boundary.

    `queries/{system}/_draft/` joins it (#585). A draft is not curated prose: `draft_synthesis`
    mints it from an EXECUTED gather query, and the skeleton it writes embeds the lead's goal text
    and the query body the gather LLM coined *in response to alert data* — attacker-influenced by
    definition, on the same channel as the payload that produced it. `template_search` now returns
    hits from those files, so without this the text would reach the model bare. An ESTABLISHED
    template stays trusted (False): it is the curated corpus gather exists to reuse, and wrapping
    it would teach gather to distrust its own catalog."""
    p = Path(path)
    return p.name == "alert.json" or _names_raw(p) or _names_query_draft(p)


# The judge's ticket-read capture writes `ticket_reads/{seq}.json` instead of `gather_raw/`
# (`learning/pipeline/judge/closed_ticket_tool.py`). `_run_paths._PAYLOAD_SHAPES` already names
# BOTH as "the two by-ref payload families a run writes"; a cap that knew only the first left the
# judge — which holds `read=True` — able to re-read at the authored ceiling exactly what the
# capture view withheld, which is the one property the #832 O7 split exists to keep.
TICKET_READS_MARKER = "ticket_reads"


def is_captured_payload(path: Path) -> bool:
    """Whether a resolved path is a payload a capture wrote — `gather_raw/` (the `query` tool)
    or `ticket_reads/` (the judge's closed-ticket capture).

    Narrower than `is_untrusted_read` on purpose, and answering a different question. That one
    asks "must this be salt-tagged?" and takes in the alert and draft templates too; this one
    asks "was this text already bounded once, on its way into context?" — which is true only of
    a captured payload, and decides which read cap applies (#832 O7). `alert.json` is the run's
    own input and is read whole; a payload is not."""
    p = Path(path)
    return _names_raw(p) or TICKET_READS_MARKER in p.parts


def decide_write(
    path: Path, proposed_text: str = "", *,
    run_dir: Path, defender_dir: Path,
    policy: AgentPolicy,
) -> Decision:
    """Allow/deny a write of `proposed_text` to `path` — a **flat, deny-by-default allowlist**
    (the write twin of `bash_allow`): the RESOLVED path must `fullmatch` one of the agent's
    `policy.write_allow` patterns (the specific paths it declares it may author — the main
    loop's run-dir subtree, the lead author's `defender/skills/**.md`). Empty `write_allow`
    (every read-only / predictor stage) denies all writes. `resolve()` collapses `..`/symlinks
    before the match so a pattern is a true path set, not a string prefix an operand can escape;
    a `resolve()` error (a symlink cycle, or an embedded NUL — `ValueError`, reachable from any
    model-supplied operand) FAILS CLOSED rather than propagating out of the gate.

    `run_dir`/`defender_dir` are REQUIRED run roots — the same shape `decide_read` has always
    had, and REQUIRED rather than optional since #681. A write target must ALSO resolve within
    the agent's read CONTAINMENT — its read roots (`read_confine`/`read_roots`/run dir/
    `defender_dir`) minus the secret/ground-truth denylist (`read_allowed_path`), the
    `write_allow ⊆ read roots` invariant `edit_file` relies on. NOTE this is containment +
    denylist, NOT the full `decide_read` gate: it does not apply the read-side path SHAPES
    (`read_allow`), so a writer whose `write_allow` admits a path its read shapes exclude is not
    additionally blocked here — a writer's declared paths are its own, and MAIN legitimately
    writes run-dir artifacts.

    The roots are threaded by TYPE because the output-structure gate below KEYS on
    `<run_dir>/<name>`: under the former `run_dir: Path | None = None` an omitted kwarg silently
    skipped that whole gate and fell through to `Decision(True)` — a caller could lose a blocking
    gate by forgetting an argument, with no signal (#681). Requiring both moves that failure to
    the call site (a `TypeError`, and a mypy error in CI) where it cannot hide, and retires the
    guard's former dormant-when-omitted mode: the containment check now always runs, a pinned
    no-op for every real writer whose `write_allow` already sits inside its read roots.

    Once both allowlist halves pass, a write to one of the run's two model-authored
    artifacts faces its CONTENT SCHEMA (`defender._artifact_schema`): report.md's
    frontmatter grammar and byte bounds, investigation.md's byte bound and structural
    invlang validation. Any schema reason denies with that text, so the model can fix its
    own output — the in-process equivalent of the hook's exit-2 feedback.
    """
    path = Path(path)
    try:
        rp = path.resolve()
    except RESOLVE_ERRORS:
        return Decision(False, f"Blocked: {path!r} could not be resolved (failing closed).")
    if not any(pat.fullmatch(str(rp)) for pat in policy.write_allow):
        return Decision(
            False,
            "Blocked: writes are limited to this agent's declared paths "
            f"(its write allowlist); {path} is not one of them.",
        )
    # Defense-in-depth (write ⊆ read roots): the write target must also sit inside the agent's
    # read CONTAINMENT — its read roots minus the secret/ground-truth denylist
    # (`read_allowed_path`), fails closed on a resolve error. This is containment + denylist, NOT
    # the full `decide_read` (the read-side path SHAPES are not applied: a writer's declared paths
    # are its own). A no-op for every real writer (its write_allow already sits within its read
    # roots); it only closes a hypothetical write_allow that escapes them.
    if not read_allowed_path(rp, run_dir=run_dir, defender_dir=defender_dir, policy=policy):
        return Decision(
            False,
            f"Blocked: {path} is outside this agent's read roots — a write must land within the "
            "agent's read containment (write ⊆ read roots).",
        )

    # #629 — the run's two model-authored output artifacts get a structural + volume gate,
    # keyed on the operand RESOLVING to the run-dir ROOT (not `path.name` alone). Resolving
    # first closes the symlink/subdir disguise (a `decoy.md` -> `<run_dir>/report.md` IS
    # gated; a `<run_dir>/sub/report.md` is NOT), and scoping to the run-dir root leaves a
    # same-named lesson in a curator's corpus untouched (the verify_forward forward-check
    # operand — F-A2: gating it would flip its pure-containment allow into a deny).
    # BOTH artifacts key that one way. investigation.md's legacy exact-basename fallback
    # retired with the run_dir-less caller it existed for (#681): the roots are required now,
    # so nothing reaches here without a run root and the fallback was unreachable — while
    # keeping a name-only key would gate a corpus file that merely SHARES the basename, the
    # F-A2 regression above. Resolving still decides for investigation.md too (#631, PBW2D):
    # a symlink `alias.md` resolving to investigation.md clears the allowlist on `rp`, so it
    # must face the same validator the direct write does, or identical text is refused through
    # the real name and admitted through the alias.
    artifact = next(
        (n for n in _artifact_schema.ARTIFACT_NAMES if _is_run_dir_file(rp, run_dir, n)), None
    )
    if artifact is None:
        return Decision(True)
    # The append-only baseline, read HERE so the schema module stays filesystem-free (#714).
    # Read only for the artifacts whose schema takes a baseline: an unconditional read would
    # put a `read_text` that can raise on the report.md path, where none ran before.
    current = (
        rp.read_text(encoding="utf-8")
        if artifact in _artifact_schema.NEEDS_BASELINE and rp.is_file()
        else None
    )
    return _as_decision(_artifact_schema.validate_artifact(artifact, proposed_text, current))


def _as_decision(reason: str | None) -> Decision:
    """Wrap a content-schema verdict (`defender._artifact_schema`, which returns a deny reason
    or `None`) back into the gate's `Decision`. The reason text is the model-facing ModelRetry
    body and is passed through unchanged."""
    return Decision(True) if reason is None else Decision(False, reason)


def _is_run_dir_file(rp: Path, run_dir: Path, name: str) -> bool:
    """True iff the RESOLVED operand `rp` is exactly `<run_dir>/<name>` — the run-dir ROOT,
    exact basename, symlinks already collapsed into `rp` by the caller's `resolve()`. `run_dir`
    is resolved here to align with `rp`'s resolution. A `resolve()` error returns False — the
    artifact branch then simply does not fire, and the write stands on the generic allowlist
    decision that already ran above."""
    try:
        return rp == run_dir.resolve() / name
    except RESOLVE_ERRORS:
        return False


def _decide_report_write(proposed_text: str) -> Decision:
    """The report.md output-structure gate (#629) as a `Decision` — a thin wrapper over
    `_artifact_schema.validate_report`, which owns the grammar (#714). Kept as a named export
    because the frames suite drives this half directly."""
    return _as_decision(_artifact_schema.validate_report(proposed_text))


def _decide_investigation_write(proposed_text: str, rp: Path) -> Decision:
    """The investigation.md gate as a `Decision` — a thin wrapper over
    `_artifact_schema.validate_investigation`, reading the append-only baseline off `rp` the way
    `decide_write` does. Kept as a named export because the frames suite drives this half
    directly."""
    current = rp.read_text(encoding="utf-8") if rp.is_file() else None
    return _as_decision(_artifact_schema.validate_investigation(proposed_text, current))
