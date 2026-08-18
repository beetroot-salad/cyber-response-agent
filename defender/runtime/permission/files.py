"""The file gates: deny-by-default read allowlist + write allowlist.

Both return a plain `Decision`. Reads must resolve inside the run dir or the
defender corpus (with a belt-and-suspenders secret/ground-truth denylist on top);
writes must `fullmatch` one of the agent's `policy.write_allow` patterns. On top of
the allowlist, the run's two model-authored output artifacts get an OUTPUT-STRUCTURE
gate — this module decides WHICH artifact a resolved path is, and
`defender._artifact_schema` decides whether the proposed text is a well-formed one.
`is_untrusted_read` flags attacker-influenced data the caller must tag-wrap."""

from __future__ import annotations

import re
from pathlib import Path

from defender import _artifact_schema
from defender._run_paths import CASE_ANSWER_KEY_NAMES, WIRE_LOG_DIR
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
    denied path component (`.ssh`). Belt-and-suspenders applied INSIDE every allowed
    root, on BOTH read surfaces (`decide_read` and the bash operand lane's
    `read_allowed_path`), so the two cannot disagree about a denied file that resolves
    within-root."""
    return any(d in set(rp.parts) for d in bash_policy.read_deny_dirs()) or any(
        s in rp.name for s in bash_policy.read_deny_substrings()
    )


def _resolved_read_roots(
    policy: AgentPolicy, run_dir: Path, defender_dir: Path
) -> tuple[Path, ...]:
    """The resolved roots a read must land within for `policy`. A non-empty
    `policy.read_confine` REPLACES the `defender_dir` base (the gray-box confine — a
    confined actor sees only its lesson corpora); `run_dir` and `read_roots` still
    widen. Empty confine is `{run_dir, defender_dir, *read_roots}`. May raise from
    `resolve()` — every caller FAILS CLOSED."""
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
    twin of the bash lane's baked reader anchors (`policies._common`).

    NO production caller left — its `[^\\x00]*` tail admits an agent's own system prompt and
    every space/newline filename besides. Kept only because ~10 tests still build a policy
    through it as their stand-in for "a subtree writer". Do not reach for this for a new
    writer: use `build_scoped_write_allow` or a per-lane builder."""
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
    `root` is `resolve()`d to align with the RESOLVED operand `decide_write` matches against.

    WHAT THE WALK CAN SEE, exactly: its only caller is the curator's lesson-corpus write
    allow, and every corpus reader goes through `_corpus.iter_lesson_paths`, which is
    `glob('*.md')` (flat) MINUS any name starting `_`. A write outside that set produces a
    file no reader can ever see, which the environment forward-check would then certify as
    retrievability-verified off a basename collision with a visible sibling. So the tail is
    one level AND non-underscore: `<corpus>/sub/x.md` and `<corpus>/_x.md` are equally
    invisible and both refused at the source. `verify_forward/env.py` rejects the same shape
    independently."""
    from .grant import SEG

    base = re.escape(str(root.resolve()))
    tail = rf"/(?!_){SEG}"
    if suffix:
        tail += re.escape(suffix)
    return re.compile(base + tail)


def build_named_write_allow(root: Path, names: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    """A POSITIVE allow-list of EXACTLY `<root>/<name>` for each name — one anchored
    pattern per basename, matched against the RESOLVED operand. Deliberately tighter than
    `build_write_allow`'s subtree/suffix forms: a suffix filter is a filename filter, not a
    subtree narrowing (`decide_write` applies no path shapes), so it would admit
    `gather_raw/evil.md` and `sub/report.md` at depth. Resolving both sides means an alias
    resolving to `<root>/investigation.md` matches that pattern (and is then
    invlang-validated on the RESOLVED name), while `<root>/sub/report.md` never matches."""
    base = re.escape(str(root.resolve()))
    return tuple(re.compile(base + "/" + re.escape(name)) for name in names)


def read_allowed_path(
    path: str | Path, *, run_dir: Path | None, defender_dir: Path | None,
    policy: AgentPolicy,
) -> bool:
    """Whether a file operand resolves within `policy`'s read roots — the ROOTS half of
    `decide_read` (the shape half is `policy.read_allow`), reused by `decide_write` for its
    `write_allow ⊆ read roots` check. FAILS CLOSED: a `resolve()` error or a missing root
    context (`run_dir`/`defender_dir` `None`) returns `False`, never raises.

    The secret/ground-truth denylist IS applied (parity with `decide_read`, so a write can't
    land on a denied file the read tool refuses), and so is the `wire_logs/` component: wire
    logs are HOST-side observability, so no agent may AUTHOR one either. Resting that on "no
    writer's `write_allow` happens to reach there" would leave the run's own spend record one
    widened write shape away from forgeable.

    It applies NO path shapes: containment by shape is the caller's job (the read tool checks
    `read_allow`; the bash lane checks the claiming grant's scope)."""
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
    2. **`policy.read_allow`** — the agent's path SHAPES. This is the same tuple object the
       agent's bash `cat` grant carries as its scope, so the read tool admits exactly the paths
       `cat` does: read↔bash parity by construction, with nothing to keep in sync. It is also
       what makes "main cannot read gather_raw" positive enumeration rather than a clamp — the
       gather_raw shape is simply not in main's list. Empty `read_allow` (every non-reader
       agent) applies no shape filter, leaving the gate root-only.

    Three path classes are then judged on top of the two gates, because a ROOT the agent holds is
    not the same claim as a FILE it may see: `gather_raw/` and the case's answer-key artifacts at
    the agent's own run-dir root (`names_case_answer_key`, confined agents only) are denied unless
    a declared shape names them, and `wire_logs/` is denied outright. Each is commented at its
    line with why it is opt-in-able or not.

    On top of all of it, the declarative secret/ground-truth denylist (`bash_policy.json`) denies
    a sensitive file that lands INSIDE an allowed shape — cheap belt-and-suspenders applied to
    every agent. A `resolve()` error FAILS CLOSED rather than propagating out of a blocking
    gate."""
    p = Path(path)
    try:
        rp = p.resolve()
        rd = Path(run_dir).resolve()
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
    # shapes at all. An empty `read_allow` means "no shape filter", a WIDENING default, and
    # `gather_raw` is the one path class where that is a security failure: the learning loop
    # STAGES the investigation's whole `gather_raw/` tree into the learning run dir
    # (`lead_repository.stage_tables`), and that dir IS the actor's own root — so a root-only read
    # would hand the gray-box actor the very payloads it must write its story WITHOUT seeing.
    # Reading a payload therefore requires a shape that NAMES it (gather's own raw shape; the
    # judge's scope over its comparison roots), never merely a root that happens to contain it.
    if _names_raw(rp) and not admitted:
        return Decision(False, RAW_DENY_REASON)
    # `wire_logs/` is denied OUTRIGHT — not "unless a shape admits it", the way `gather_raw` is
    # one line up. GATHER legitimately reads payloads, so raw stays opt-in-able, while a wire log
    # is host observability NO agent has business reading. Unconditional is also what makes it
    # work at all: the JUDGE's `cat` scope is `under(run, TREE)`, which fullmatches a
    # subdirectory and would set `admitted`, and the ACTOR declares no shapes at all, so
    # `admitted` is never True for it and no positive enumeration can exclude anything.
    if names_wire_log_dir(rp):
        return Decision(False, WIRE_LOG_DENY_REASON)
    # The same argument as `gather_raw` one step up, applied to the OTHER thing the learning loop
    # stages into the gray-box agent's own root. `persist._copy_shared_inputs` and
    # `lead_repository.stage_tables` write the source run's investigation.md, report.md,
    # source_refs.yaml and executed_queries.jsonl into `<learning_run_dir>/` — which IS the actor's
    # `run_dir`, an unconditional read root it declares no shapes over — so the case's reasoning
    # and its disposition sit one `read_file` away from the agent whose whole confine exists to
    # withhold them. Not reachable on a clean first pass (persist runs after that leg's actor), but
    # the dir is `mkdir(exist_ok=True)` with no cleanup and no once-only guard, so ANY second pass
    # over the same run id starts the actor in a dir already holding them.
    #
    # CONDITIONAL ON `read_confine`, unlike the wire log's outright deny: the judge reads exactly
    # these files as the case it is grading (its comparison roots are declared read_roots), and it
    # is unconfined. A confine is this system's one declaration of "this agent is being TESTED on
    # this case", so it is the right key — and `not admitted` keeps the opt-in door the raw deny
    # has, for a future confined role that declares a shape naming one of them.
    #
    # THE RUN-DIR ROOT, not the basename anywhere: a confined agent's other root is a lesson
    # corpus, and a flat name test would make a lesson called `report.md` unreadable with a reason
    # about answer keys. Every staged copy is `<run_dir>/<name>`, so the parent is part of the fact.
    #
    # decide_read ONLY, like `_names_raw` and unlike the wire log. The bash lane cannot reach here:
    # the actor holds no file-opening grant at all (only `python3 <pinned script>`), and the
    # curator's `cat` scope is `under(corpus, TREE)` — neither grant's scope spans its run dir, so
    # there is no second surface to disagree with. `read_allowed_path` is deliberately untouched
    # for the other reason too: it also backs `decide_write`'s containment half, and a confined
    # agent authoring into its own run dir is not the leak.
    if policy.read_confine and not admitted and names_case_answer_key(rp, rd):
        return Decision(False, ANSWER_KEY_DENY_REASON)
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


# The `gather_raw/` path component, and the reason a read of one earns. Deliberately NOT paired
# with a `RAW_MARKER in <command text>` substring clamp (see `bash.py`: containment is positive
# grant enumeration, and a substring scan wrongly denies `… | grep gather_raw`, where the word is
# a search PATTERN, not a path).
RAW_MARKER = "gather_raw"
RAW_DENY_REASON = (
    "Blocked: the main loop must not read gather_raw/. Gather's returned "
    "summary is the authoritative record (defender SKILL §Principles). If an "
    "obligation came back unaddressed, re-dispatch gather naming that "
    "obligation more sharply — never a field list or a filter — and do not "
    "Read/Grep/jq the raw payload from the main loop; that defeats the "
    "subagent isolation."
)


# The `wire_logs/` path component (`_run_paths.WIRE_LOG_DIR`) and the reason a read of one earns.
# Every WIRE log in the tree writes under this component — the runtime's at `<run_dir>/wire_logs/`,
# every learning stage's trace at `<learning_run_dir>/wire_logs/` — so ONE component test covers
# the whole class. NOT every `RequestLogger`: `observe.denial_logger` uses the same class for
# `<run_dir>/policy_denials.jsonl` and stays at the root deliberately, because it projects a
# parameter DIGEST rather than the blob. The class named here is "carries a wire body verbatim".
#
# WHY A DENY AND NOT JUST A SHAPE. A wire log holds another agent's context verbatim, which makes
# it a boundary wherever two roles share a root. The subdirectory alone suffices for MAIN and
# GATHER, whose read shape is a single segment — but that is a property of THEIR shapes, and the
# learning lane has neither: the JUDGE reads `under(run, TREE)` (a subdirectory fullmatches) and
# the ACTOR declares no shape at all (root containment only, every depth admitted). The concrete
# case is the gray-box actor: `_names_raw` keeps it out of `gather_raw/`, while a judge trace at
# the learning run dir's root hands the SAME payloads back through the judge's prompt
# (`judge/compare.unredacted_exemplar` — real values, not the oracle's scrubbed skeleton).
#
# DISTINCTIVE ON PURPOSE, like `gather_raw` and `ticket_reads` beside it. This deny is
# unconditional and applies inside EVERY read root, not just a run dir — and the judge's shapes
# span the whole `defender/` tree — so an ordinary word here would be a trap: a system skill or
# query-catalog dir named for observing would go unreadable for every agent, with a reason about
# wire logs that has nothing to do with the file.
WIRE_LOG_MARKER = WIRE_LOG_DIR
WIRE_LOG_DENY_REASON = (
    "Blocked: wire_logs/ holds this run's wire logs — the verbatim request/response stream of "
    "every agent that shares this root, including payload bytes and transcripts this agent is "
    "deliberately not shown. It is host-side observability, readable by no agent. Work from "
    "the artifacts your own role is given."
)


def names_wire_log_dir(p: Path) -> bool:
    """Whether a resolved path is INSIDE a `wire_logs/` dir — a path COMPONENT test, for the
    reason `_names_raw` gives below.

    Public, and shared with the bash operand lane (`bash._in_scope`) exactly as `denylisted` is,
    so the two read surfaces cannot disagree about a wire log that resolves within-root: the
    JUDGE holds a `cat` grant scoped `under(run, TREE)`, so without this the bash lane would
    admit the very file `decide_read` refuses it."""
    return WIRE_LOG_MARKER in p.parts


# The reason a confined agent earns for reading a staged case artifact. Names the FILE and the
# posture, never the roots — the actor is not told where its run dir is (no disclosure in its
# instructions, its user message, or the out-of-roots denial reason), and a reason that spelled
# the layout back would hand it the address it has to guess today.
ANSWER_KEY_DENY_REASON = (
    "Blocked: that file is the finished case — the defender's own reasoning, its disposition, "
    "and the queries behind them. Your run dir holds a staged copy for archival, not for you: "
    "you are written against this case WITHOUT its answer, and reading it would make your output "
    "a restatement of the verdict rather than an independent one. Work from what your role is "
    "handed — the alert, your inputs, and your corpus."
)


def names_case_answer_key(p: Path, run_dir: Path) -> bool:
    """Whether RESOLVED path `p` is one of the case's answer-key artifacts staged at the ROOT of
    RESOLVED `run_dir` (`_run_paths.CASE_ANSWER_KEY_NAMES`).

    Both operands are already-resolved — the caller resolves them together inside its one
    fail-closed `try`, so a symlink at `investigation.md`'s name is collapsed onto the staged file
    before parents are compared, and a `..` cannot spell the root some other way."""
    return p.name in CASE_ANSWER_KEY_NAMES and p.parent == run_dir


def _names_raw(p: Path) -> bool:
    """Whether a resolved path is INSIDE `gather_raw/` — a path COMPONENT test, never a substring
    scan of the whole string. A substring scan is decided by text the path's owner does not
    control: an ancestor dir that merely carries the word (a pytest tmp dir named
    `test_gather_raw_…`, a checkout under `~/gather_raw-notes/`) would tag every file in the tree
    as an attacker-influenced payload."""
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


# The judge's ticket-read capture writes `ticket_reads/{seq}.json` instead of `gather_raw/`
# (`learning/pipeline/judge/closed_ticket_tool.py`). Both are by-ref payload families
# (`_run_paths._PAYLOAD_SHAPES`); a cap that knew only the first would leave the judge (which
# holds `read=True`) able to re-read at the authored ceiling exactly what the capture view
# withheld.
TICKET_READS_MARKER = "ticket_reads"


def is_untrusted_read(path: Path) -> bool:
    """True for reads of attacker-influenced data the caller must SALT-TAG WRAP: the alert
    payload, the raw gather payloads, a captured closed TICKET, and a DRAFT query template.

    This is the TRUST boundary, distinct from containment (which is positive grant enumeration).
    gather_raw is the primary attacker-influenced channel — untagging it would leave the model
    unable to tell data from instructions, failing the prompt-injection defense OPEN.

    `queries/{system}/_draft/`: a draft is not curated prose — `draft_synthesis` mints it from an
    EXECUTED gather query, and the skeleton embeds the lead's goal text and the query body the
    gather LLM coined *in response to alert data*. `template_search` returns hits from those
    files, so without this the text reaches the model bare. An ESTABLISHED template stays trusted
    (False): it is the curated corpus gather exists to reuse, and wrapping it would teach gather
    to distrust its own catalog.

    `ticket_reads/`: the closed-ticket store's free text is attacker-influenced (`_predates_case`
    exists because a comment on a three-year-old record can name the live incident), and the
    judge's capture persists it verbatim, then prints the absolute path so the model can re-open
    what the 8 KB view elided. Every other route to those bytes already frames them, so an
    unframed `read_file` would be the one lane delivering a withheld span bare. Additive only:
    `decide_read` never consults this, so nothing new is denied.

    It joins by DELEGATION rather than a second spelling of the marker: the
    `is_captured_payload ⊆ is_untrusted_read` relation below is load-bearing, and two parallel
    disjunction lists drift (the cap's once grew a family the frame's did not). Calling the
    narrower predicate makes the containment structural."""
    p = Path(path)
    return (
        p.name == "alert.json"
        or is_captured_payload(p)
        or _names_query_draft(p)
    )


def is_captured_payload(path: Path) -> bool:
    """Whether a resolved path is a payload a capture wrote — `gather_raw/` (the `query` tool)
    or `ticket_reads/` (the judge's closed-ticket capture).

    A strict SUBSET of `is_untrusted_read`, answering a different question. That one asks "must
    this be salt-tagged?" and takes in the alert and draft templates too; this one asks "was this
    text already bounded once, on its way into context?" — true only of a captured payload, and
    it decides which read cap applies. `alert.json` is the run's own input and is read whole; a
    payload is not.

    The subset relation is load-bearing: a capture is by construction a copy of bytes that
    arrived from outside, so a path this predicate admits and the other one refuses would be a
    payload delivered unlabeled. Hence `is_untrusted_read` CALLS this rather than restating its
    members."""
    p = Path(path)
    return _names_raw(p) or TICKET_READS_MARKER in p.parts


def decide_write(
    path: Path, proposed_text: str = "", *,
    run_dir: Path, defender_dir: Path,
    policy: AgentPolicy,
) -> Decision:
    """Allow/deny a write of `proposed_text` to `path` — a **flat, deny-by-default allowlist**
    (the write twin of `bash_allow`): the RESOLVED path must `fullmatch` one of the agent's
    `policy.write_allow` patterns (the specific paths it declares it may author). Empty
    `write_allow` (every read-only / predictor stage) denies all writes. `resolve()` collapses
    `..`/symlinks before the match so a pattern is a true path set, not a string prefix an operand
    can escape; a `resolve()` error FAILS CLOSED rather than propagating out of the gate.

    `run_dir`/`defender_dir` are REQUIRED run roots. A write target must ALSO resolve within the
    agent's read CONTAINMENT — its read roots minus the secret/ground-truth denylist
    (`read_allowed_path`), the `write_allow ⊆ read roots` invariant `edit_file` relies on. NOTE
    this is containment + denylist, NOT the full `decide_read` gate: the read-side path SHAPES
    (`read_allow`) are not applied, so a writer whose `write_allow` admits a path its read shapes
    exclude is not additionally blocked — a writer's declared paths are its own, and MAIN
    legitimately writes run-dir artifacts.

    The roots are REQUIRED rather than optional because the output-structure gate below KEYS on
    `<run_dir>/<name>`: with a defaulted `run_dir=None` an omitted kwarg silently skipped that
    whole gate and fell through to `Decision(True)` — a caller could lose a blocking gate by
    forgetting an argument, with no signal. Requiring both moves that failure to the call site (a
    `TypeError`, and a mypy error in CI) where it cannot hide.

    Once both allowlist halves pass, EVERY allowed write is checked for UTF-8-encodability —
    through the artifact's own CONTENT SCHEMA (`defender._artifact_schema`, which leads with that
    check) for the two model-authored artifacts, and through a direct call on the non-artifact
    branch. The schema also carries report.md's frontmatter grammar and byte bounds and
    investigation.md's byte bound and structural invlang validation. Any schema reason denies with
    that text, so the model can fix its own output."""
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
    # Defense-in-depth (write ⊆ read roots), fails closed on a resolve error. A no-op for every
    # real writer; it only closes a write_allow that escapes the agent's read roots.
    if not read_allowed_path(rp, run_dir=run_dir, defender_dir=defender_dir, policy=policy):
        return Decision(
            False,
            f"Blocked: {path} is outside this agent's read roots — a write must land within the "
            "agent's read containment (write ⊆ read roots).",
        )

    # The run's two model-authored output artifacts get a structural + volume gate, keyed on the
    # operand RESOLVING to the run-dir ROOT (not `path.name` alone). Resolving first closes the
    # symlink/subdir disguise (a `decoy.md` -> `<run_dir>/report.md` IS gated; a
    # `<run_dir>/sub/report.md` is NOT), and scoping to the run-dir root leaves a same-named lesson
    # in a curator's corpus untouched — a name-only key would flip the verify_forward
    # forward-check's pure-containment allow into a deny. Resolving matters for investigation.md
    # too: a symlink `alias.md` resolving to it clears the allowlist on `rp`, so it must face the
    # same validator the direct write does, or identical text is refused through the real name and
    # admitted through the alias.
    artifact = next(
        (n for n in _artifact_schema.ARTIFACT_NAMES if _is_run_dir_file(rp, run_dir, n)), None
    )
    if artifact is None:
        # The UTF-8-encodability check applies to EVERY allowed write, not only the two artifacts
        # whose schemas measure bytes. It otherwise lives only inside `validate_artifact`, so a
        # lone surrogate — reachable from a model tool-call arg on a provider that hands args back
        # as an already-parsed dict — was ALLOWED on every non-artifact path (the curator's and
        # lead author's corpus files) and then raised `UnicodeEncodeError` out of `write_guarded`,
        # past a write tool that maps no exception, quarantining the authoring spawn instead of
        # returning the refusal the SAME content earns on report.md. Checking here keeps the gate's
        # "return a Decision, never propagate" contract true on this branch too. Spelled HERE
        # rather than above the keying so the artifact branch keeps ONE refusal text for this
        # condition, and so the 64 KiB investigation.md is not `.encode()`d twice on every append.
        reason = _artifact_schema.encodable_or_reason(proposed_text, str(path))
        return Decision(True) if reason is None else Decision(False, reason)
    # The append-only baseline, read HERE so the schema module stays filesystem-free. Read only
    # for the artifacts whose schema takes a baseline, to keep a raising `read_text` off the
    # report.md path.
    #
    # FAILS CLOSED on a read fault rather than propagating (the same rule the resolve above
    # obeys). Deny rather than fall back to `current=None`, which would drop the append-only
    # baseline and let the faulting write REPLACE the document — a fail-open on the one invariant
    # this branch exists to hold.
    current: str | None = None
    if artifact in _artifact_schema.NEEDS_BASELINE and rp.is_file():
        try:
            current = rp.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as e:
            return Decision(
                False,
                f"Blocked: the current {artifact} could not be read to check this write "
                f"against it (failing closed): {e}.",
            )
    return _as_decision(_artifact_schema.validate_artifact(artifact, proposed_text, current))


def _as_decision(reason: str | None) -> Decision:
    """Wrap a content-schema verdict (`defender._artifact_schema`, which returns a deny reason
    or `None`) back into the gate's `Decision`. The reason text is the model-facing ModelRetry
    body and is passed through unchanged."""
    return Decision(True) if reason is None else Decision(False, reason)


def _is_run_dir_file(rp: Path, run_dir: Path, name: str) -> bool:
    """True iff the RESOLVED operand `rp` is exactly `<run_dir>/<name>`; `run_dir` is resolved
    here to align with `rp`. A `resolve()` error returns False — the artifact branch then does
    not fire, and the write stands on the generic allowlist decision above."""
    try:
        return rp == run_dir.resolve() / name
    except RESOLVE_ERRORS:
        return False


def _decide_report_write(proposed_text: str) -> Decision:
    """The report.md output-structure gate as a `Decision` — a thin wrapper over
    `_artifact_schema.validate_report`, which owns the grammar. Kept as a named export because
    the frames suite drives this half directly."""
    return _as_decision(_artifact_schema.validate_report(proposed_text))


def _decide_investigation_write(proposed_text: str, rp: Path) -> Decision:
    """The investigation.md gate as a `Decision` — a thin wrapper over
    `_artifact_schema.validate_investigation`, reading the append-only baseline off `rp` the way
    `decide_write` does. Kept as a named export because the frames suite drives this half
    directly."""
    current = rp.read_text(encoding="utf-8") if rp.is_file() else None
    return _as_decision(_artifact_schema.validate_investigation(proposed_text, current))
