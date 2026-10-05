"""The file gates: deny-by-default read allowlist + write allowlist.

Reads must resolve inside the run dir or the defender corpus (plus a secret/ground-truth
denylist); writes must `fullmatch` one of `policy.write_allow`. The run's two model-authored
artifacts additionally go through `defender._artifact_schema`. `is_untrusted_read` flags
attacker-influenced data the caller must tag-wrap."""

from __future__ import annotations

import re
from pathlib import Path

from defender import _artifact_schema
from defender._io import rooted_read_plain
from defender._run_paths import (
    RUN_LAYOUT,
    RunPaths,
    gather_summaries_shape,  # noqa: F401 — re-export for the policy builder
    is_case_answer_key,
)
from defender.runtime import bash_policy

from .decision import Decision
from .policy import AgentPolicy

# Everything `Path.resolve()` can throw on a hostile operand, so every gate fails closed
# instead of crashing the tool call. `ValueError` is an embedded NUL (`cat a\0b`), which
# `shlex` tokenizes into an operand.
RESOLVE_ERRORS: tuple[type[BaseException], ...] = (OSError, RuntimeError, ValueError)


def _is_within(p: Path, root: Path) -> bool:
    """True iff resolved path `p` is `root` or below it."""
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False


def denylisted(rp: Path) -> bool:
    """True iff a resolved path hits the secret/ground-truth denylist (a filename substring
    or a path component). Shared by both read surfaces so they agree on a denied file
    inside an allowed root."""
    return any(d in set(rp.parts) for d in bash_policy.read_deny_dirs()) or any(
        s in rp.name for s in bash_policy.read_deny_substrings()
    )


def read_roots(
    policy: AgentPolicy, run_dir: Path, defender_dir: Path
) -> tuple[Path, ...]:
    """@owns read_roots: the roots a read must land within, as the caller and the policy
    spell them (unresolved). A non-empty `policy.read_confine` replaces the `defender_dir`
    base; `run_dir` and `read_roots` always apply."""
    base = policy.read_confine if policy.read_confine else (Path(defender_dir),)
    return (Path(run_dir), *base, *policy.read_roots)


def _resolved_read_roots(
    policy: AgentPolicy, run_dir: Path, defender_dir: Path
) -> tuple[Path, ...]:
    """:func:`read_roots`, resolved. May raise from `resolve()`; callers fail closed."""
    return tuple(r.resolve() for r in read_roots(policy, run_dir, defender_dir))


def build_write_allow(root: Path, *, suffix: str = "") -> re.Pattern[str]:
    """Build a `write_allow` pattern admitting `root` and everything under it, optionally
    only basenames ending `suffix`. `root` is resolved to align with the resolved operand.

    Test-only: the `[^\\x00]*` tail admits space/newline filenames. New writers should use
    `build_scoped_write_allow` or a per-lane builder."""
    base = re.escape(str(root.resolve()))
    tail = r"/[^\x00]*" + re.escape(suffix) if suffix else r"(?:/[^\x00]*)?"
    return re.compile(base + tail)


def build_scoped_write_allow(root: Path, *, suffix: str = "") -> re.Pattern[str]:
    """Build a `write_allow` pattern admitting exactly the direct children of `root` that
    the corpus walk can see, with the `grant.SEG` filename class (no space/newline names,
    which would open a frame-injection channel).

    The corpus walk (`_corpus.iter_lesson_paths`) is flat `*.md` minus names starting `_`.
    A write outside that set is invisible to every reader, yet the forward-check could
    certify it off a basename collision with a visible sibling, so it is refused here."""
    from .grant import SEG

    base = re.escape(str(root.resolve()))
    tail = rf"/(?!_){SEG}"
    if suffix:
        tail += re.escape(suffix)
    return re.compile(base + tail)


def build_named_write_allow(root: Path, names: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    """One anchored pattern per name admitting exactly `<root>/<name>`. A suffix filter
    would also admit `gather_raw/evil.md` or `sub/report.md` at depth, since `decide_write`
    applies no path shapes."""
    base = re.escape(str(root.resolve()))
    return tuple(re.compile(base + "/" + re.escape(name)) for name in names)


def read_allowed_path(
    path: str | Path, *, run_dir: Path | None, defender_dir: Path | None,
    policy: AgentPolicy,
) -> bool:
    """Whether a file operand resolves within `policy`'s read roots: the roots half of
    `decide_read`, also used for `decide_write`'s `write ⊆ read roots` check. Fails closed
    (returns `False`) on a resolve error or missing root context.

    Applies the denylist and the `wire_logs/` deny, so no agent can write a denied file or
    forge a wire log either. Applies no path shapes; that is the caller's job."""
    if run_dir is None or defender_dir is None:
        return False
    try:
        rp = Path(path).resolve()
        roots = _resolved_read_roots(policy, run_dir, defender_dir)
    except RESOLVE_ERRORS:
        return False
    if denylisted(rp) or names_wire_log_dir(rp):
        return False
    return any(_is_within(rp, root) for root in roots)


def decide_read(
    path: Path, *, run_dir: Path, defender_dir: Path, policy: AgentPolicy
) -> Decision:
    """Allow/deny a file read: a deny-by-default allowlist over the resolved path.

    1. Roots: the run dir, the defender corpus (or `read_confine` in its place), and the
       agent's `read_roots`.
    2. `policy.read_allow` shapes: the same tuple the agent's bash `cat` grant carries as its
       scope, so the read tool and `cat` admit the same paths. Empty means no shape filter.

    Holding a root is not permission to see every file under it: `gather_raw/`, the case's
    answer-key artifacts (confined agents), `wire_logs/` and the provenance stamp get their own
    denies below. The secret/ground-truth denylist applies last. Resolve errors fail closed."""
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
    # Raw payloads are opt-in for every agent, including one with no shapes: the learning loop
    # stages `gather_raw/` into the actor's own run dir, so a root-only read would hand a
    # gray-box actor the payloads it must not see. Reading one needs a shape that names it.
    if _names_raw(rp) and not admitted:
        return Decision(False, RAW_DENY_REASON)
    # Wire logs are denied unconditionally: no agent should read host observability, and the
    # judge's `under(run, TREE)` scope would otherwise admit them.
    if names_wire_log_dir(rp):
        return Decision(False, WIRE_LOG_DENY_REASON)
    if names_run_provenance(rp, rd):
        return Decision(False, PROVENANCE_DENY_REASON)
    # The case's answer key (investigation.md, report.md, ...) can be staged into a confined
    # agent's own run dir, and a rerun over the same run id finds it already there. Denied only
    # under `read_confine` because the unconfined judge grades exactly these files. Keyed on the
    # run-dir root, not the basename, so a lesson named `report.md` stays readable. The bash lane
    # needs no twin: no confined agent holds a file-opening grant spanning its run dir.
    if policy.read_confine and not admitted and names_case_answer_key(rp, rd):
        return Decision(False, ANSWER_KEY_DENY_REASON)
    if policy.read_allow and not admitted:
        return Decision(
            False,
            f"Blocked: {rp.name} is not a readable path for this agent — its reads are the "
            "paths it declares (its own run dir + the corpus `.md` under "
            "lessons/skills/examples), and this is not one of them.",
        )
    # A secret / ground-truth file inside an allowed shape is still denied.
    if denylisted(rp):
        return Decision(False, f"Blocked: {rp.name} is a denied read (secrets / ground truth).")
    return Decision(True)


# No substring clamp on command text pairs with this: `… | grep gather_raw` names a pattern,
# not a path. Containment is positive grant enumeration.
RAW_DENY_REASON = (
    "Blocked: the main loop must not read gather_raw/. Gather's returned "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    "summary is the authoritative record (defender SKILL §Principles). If an "
    "obligation came back unaddressed, re-dispatch gather naming that "
    "obligation more sharply — never a field list or a filter — and do not "
    "Read/Grep/jq the raw payload from the main loop; that defeats the "
    "subagent isolation."
)


# Every log that carries a wire body verbatim writes under the `wire_logs/` component, so one
# component test covers the class (`policy_denials.jsonl` holds only digests and stays at the
# root). A wire log holds another agent's context, including payloads, so it is a boundary
# wherever two roles share a root; a subdirectory alone does not protect it from the judge
# (`under(run, TREE)`) or the shapeless actor. The component name must stay distinctive: this
# deny applies inside every read root.
WIRE_LOG_DENY_REASON = (
    "Blocked: wire_logs/ holds this run's wire logs — the verbatim request/response stream of "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    "every agent that shares this root, including payload bytes and transcripts this agent is "
    "deliberately not shown. It is host-side observability, readable by no agent. Work from "
    "the artifacts your own role is given."
)


# The provenance stamp is denied to every role: unlike other run-root files it describes the
# host tree (a sha and paths of uncommitted work), which is reconnaissance on the defender's
# own source. Hiding it from the workspace map is not enough, since MAIN's and GATHER's
# `under(run, SEG)` shape admits a guessed filename.
PROVENANCE_DENY_REASON = (
    "Blocked: provenance.json records the host checkout this run was launched from — a commit "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    "and the paths of uncommitted work in the defender's own source tree. It is host-side "
    "bookkeeping about the run, readable by no agent, and it says nothing about the case. Work "
    "from the artifacts your own role is given."
)


def names_run_provenance(p: Path, run_dir: Path) -> bool:
    """Whether resolved `p` is the provenance stamp at the root of `run_dir` (rooted so a
    corpus file named `provenance.json` stays readable)."""
    try:
        return p == RunPaths(run_dir).provenance.resolve()
    except RESOLVE_ERRORS:
        return False


def names_wire_log_dir(p: Path) -> bool:
    """Whether a resolved path is inside a `wire_logs/` dir (a component test). Shared with
    the bash operand lane so both read surfaces refuse it."""
    return str(RUN_LAYOUT.wire_log_dir) in p.parts


# Names the file, never the roots: the confined actor is not told where its run dir is.
ANSWER_KEY_DENY_REASON = (
    "Blocked: that file is the finished case — the defender's own reasoning, its disposition, "
    "and the queries behind them. Your run dir holds a staged copy for archival, not for you: "
    "you are written against this case WITHOUT its answer, and reading it would make your output "
    "a restatement of the verdict rather than an independent one. Work from what your role is "
    "handed — the alert, your inputs, and your corpus."
)


def names_case_answer_key(p: Path, run_dir: Path) -> bool:
    """Whether resolved `p` is a case answer-key artifact at the root of resolved `run_dir`.
    Both must already be resolved so symlinks and `..` cannot spell the root another way."""
    return is_case_answer_key(p.name) and p.parent == run_dir


def _names_raw(p: Path) -> bool:
    """Whether a resolved path is inside `gather_raw/`. A component test, not a substring
    scan, so an ancestor dir that merely contains the word does not match."""
    return str(RUN_LAYOUT.gather_raw) in p.parts


# The two path components that together name a draft query template:
# `{defender_dir}/skills/gather/queries/{system}/_draft/{verb}.md`.
QUERIES_MARKER = "queries"
DRAFT_MARKER = "_draft"


def _names_query_draft(p: Path) -> bool:
    """Whether a resolved path is a draft query template (both components, since `_draft`
    alone would match any dir of that name)."""
    return QUERIES_MARKER in p.parts and DRAFT_MARKER in p.parts


def is_untrusted_read(path: Path) -> bool:
    """True for reads of attacker-influenced data the caller must salt-tag wrap: the alert,
    captured payloads (`gather_raw/`, `ticket_reads/`), and draft query templates.

    This is the trust boundary, separate from containment; `decide_read` never consults it.
    Drafts are minted from queries the gather LLM wrote in response to alert data, so they are
    untrusted; established templates are the curated catalog and stay trusted. Delegates to
    `is_captured_payload` so the subset relation holds by construction."""
    p = Path(path)
    return (
        p.name == RUN_LAYOUT.alert.name
        or is_captured_payload(p)
        or _names_query_draft(p)
    )


def is_captured_payload(path: Path) -> bool:
    """Whether a resolved path is a captured payload (`gather_raw/` or `ticket_reads/`);
    decides which read cap applies.

    Must stay a subset of `is_untrusted_read`: a capture is always outside bytes, so a path
    admitted here but not there would be a payload delivered unlabeled."""
    p = Path(path)
    return _names_raw(p) or str(RUN_LAYOUT.ticket_reads) in p.parts


def decide_write(
    path: Path, proposed_text: str = "", *,
    run_dir: Path, defender_dir: Path,
    policy: AgentPolicy,
) -> Decision:
    """Allow/deny a write of `proposed_text` to `path`: the resolved path must `fullmatch` one
    of `policy.write_allow` (empty denies all) and lie within the agent's read containment
    (`read_allowed_path`; read shapes are not applied). Resolve errors fail closed.

    The roots are required, not optional, because the artifact gate keys on
    `<run_dir>/<name>`; an omitted `run_dir` would silently skip it. Every allowed write is
    checked for UTF-8 encodability; the two model-authored artifacts are validated against
    `defender._artifact_schema`, whose reason text is returned so the model can fix its output."""
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
    # Defense-in-depth: catches a write_allow that escapes the agent's read roots.
    if not read_allowed_path(rp, run_dir=run_dir, defender_dir=defender_dir, policy=policy):
        return Decision(
            False,
            f"Blocked: {path} is outside this agent's read roots — a write must land within the "
            "agent's read containment (write ⊆ read roots).",
        )

    # Keyed on the operand resolving to the run-dir root, not on `path.name`: a symlink alias
    # to report.md faces the same validator, and a same-named lesson in a curator corpus is
    # left alone.
    artifact = next(
        (n for n in _artifact_schema.artifact_names() if _is_run_dir_file(rp, run_dir, n)), None
    )
    if artifact is None:
        # A lone surrogate from a model tool-call arg would otherwise raise
        # `UnicodeEncodeError` out of `write_guarded` instead of returning a refusal. The
        # artifact branch gets the same check inside `validate_artifact`.
        reason = _artifact_schema.encodable_or_reason(proposed_text, str(path))
        return Decision(True) if reason is None else Decision(False, reason)
    # The append-only baseline is read here so the schema module stays filesystem-free. A read
    # fault denies: falling back to `current=None` would let the write replace the document.
    # Read through the rooted core off the run dir (`rp` is exactly `<run_dir>/<artifact>`), so
    # a link or hard link at the name is a read fault and denies, never a baseline.
    current: str | None = None
    if _artifact_schema.needs_baseline(artifact):
        try:
            current = rooted_read_plain(rp.parent, rp.name)
        except FileNotFoundError:
            current = None
        except (OSError, UnicodeDecodeError) as e:
            return Decision(
                False,
                f"Blocked: the current {artifact} could not be read to check this write "
                f"against it (failing closed): {e}.",
            )
    return _as_decision(_artifact_schema.validate_artifact(artifact, proposed_text, current))


def _as_decision(reason: str | None) -> Decision:
    """Wrap a content-schema deny reason (or `None`) as a `Decision`, reason unchanged."""
    return Decision(True) if reason is None else Decision(False, reason)


def _is_run_dir_file(rp: Path, run_dir: Path, name: str) -> bool:
    """True iff resolved `rp` is exactly `<run_dir>/<name>`; False on a resolve error."""
    try:
        return rp == run_dir.resolve() / name
    except RESOLVE_ERRORS:
        return False


def _decide_report_write(proposed_text: str) -> Decision:
    """`_artifact_schema.validate_report` as a `Decision`; tests drive this directly."""
    return _as_decision(_artifact_schema.validate_report(proposed_text))


def _decide_investigation_write(proposed_text: str, rp: Path) -> Decision:
    """`_artifact_schema.validate_investigation` against `rp`'s current text, as a `Decision`;
    tests drive this directly."""

    current = rp.read_text(encoding="utf-8") if rp.is_file() else None
    return _as_decision(_artifact_schema.validate_investigation(proposed_text, current))
