"""The file gates: deny-by-default read allowlist + write/invlang validation.

Both return a plain `Decision`. Reads must resolve inside the run dir or the
defender corpus (with a belt-and-suspenders secret/ground-truth denylist on top);
writes must `fullmatch` one of the agent's `policy.write_allow` patterns (its
declared paths — a flat, deny-by-default allowlist), and an `investigation.md`
write must additionally pass the structural invlang validator. `is_untrusted_read`
flags attacker-influenced data the caller must tag-wrap."""

from __future__ import annotations

import re
from pathlib import Path

from defender.hooks.block_main_loop_raw_access import RAW_DENY_REASON, RAW_MARKER
from defender.runtime import bash_policy
from defender.skills.invlang.validate import validate_companion

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
    captured `.env`). It applies NO path shapes: containment by shape is the caller's job (the
    read tool checks `read_allow`; the bash lane checks the claiming grant's scope)."""
    if run_dir is None or defender_dir is None:
        return False  # no root context to gate against — fail closed
    try:
        rp = Path(path).resolve()
        roots = _resolved_read_roots(policy, run_dir, defender_dir)
    except RESOLVE_ERRORS:
        return False
    if denylisted(rp):
        return False  # a secret / ground-truth file is denied even inside a root
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
    if policy.read_allow and not any(shape.fullmatch(str(rp)) for shape in policy.read_allow):
        # The path is in-roots but is not one of this agent's shapes. `gather_raw` is the case
        # the model most needs explained — the main loop reaches for a payload constantly — and
        # its dedicated reason (which the e2e deny-tail asserts as a substring) tells it what to
        # do INSTEAD: re-dispatch gather. The reason is prompt surface; the CHECK above is the
        # enumeration, so this is a message, not a second gate.
        if _names_raw(rp):
            return Decision(False, RAW_DENY_REASON)
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


def _names_raw(p: Path) -> bool:
    """Whether a resolved path is INSIDE `gather_raw/` — a path COMPONENT test, never a substring
    scan of the whole string. A substring scan is decided by text the path's owner does not
    control: an ancestor dir that merely carries the word (a pytest tmp dir named
    `test_gather_raw_…`, a checkout under `~/gather_raw-notes/`) would tag every file in the tree
    as an attacker-influenced payload. The component is the fact; the substring was a proxy."""
    return RAW_MARKER in p.parts


def is_untrusted_read(path: Path) -> bool:
    """True for reads of attacker-influenced data the caller must SALT-TAG WRAP: the alert
    payload and the raw gather payloads.

    Keyed on the gather_raw SHAPE, and deliberately kept when the raw *clamp* was deleted
    (#575): the clamp was containment (now positive enumeration), while this is the TRUST
    boundary. gather_raw is the primary attacker-influenced channel — untagging it would leave
    the model unable to tell data from instructions, failing the prompt-injection defense OPEN.
    A deletion of the clamp is not a deletion of the boundary."""
    p = Path(path)
    return p.name == "alert.json" or _names_raw(p)


def decide_write(
    path: Path, proposed_text: str = "", *,
    run_dir: Path | None = None, defender_dir: Path | None = None,
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

    `run_dir`/`defender_dir` are the OPTIONAL run roots (uniform with `decide_read`/`decide_bash`):
    when both are supplied, a write target must ALSO resolve within the agent's read CONTAINMENT
    — its read roots (`read_confine`/`read_roots`/run dir/`defender_dir`) minus the secret/ground-
    truth denylist (`read_allowed_path`), the `write_allow ⊆ read roots` invariant `edit_file`
    relies on. NOTE this is containment + denylist, NOT the full `decide_read` gate: it does not
    apply the read-side path SHAPES (`read_allow`), so a writer whose `write_allow` admits a path
    its read shapes exclude is not additionally blocked here — a writer's declared paths are its
    own, and MAIN legitimately writes run-dir artifacts. Skipped when omitted
    (the run-dir tool callers, already confined by `write_allow`); mirrors `decide_bash`'s
    optional-roots shape.

    For `investigation.md`, run the structural invlang validator against the
    full proposed text (current on-disk text supplies the append-only baseline);
    any error denies with the validator's messages so the model can fix its
    invlang — the in-process equivalent of the hook's exit-2 feedback.
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
    # Defense-in-depth (write ⊆ read roots): when the run roots are supplied, the write target
    # must also sit inside the agent's read CONTAINMENT — its read roots minus the secret/ground-
    # truth denylist (`read_allowed_path`), fails closed on a resolve error. This is containment +
    # denylist, NOT the full `decide_read` (the read-side path SHAPES are not applied: a writer's
    # declared paths are its own). A no-op for every real writer (its write_allow already sits
    # within its read roots); it only closes a hypothetical write_allow that escapes them.
    if run_dir is not None and defender_dir is not None and not read_allowed_path(
        rp, run_dir=run_dir, defender_dir=defender_dir, policy=policy
    ):
        return Decision(
            False,
            f"Blocked: {path} is outside this agent's read roots — a write must land within the "
            "agent's read containment (write ⊆ read roots).",
        )

    if path.name == "investigation.md":
        current = path.read_text() if path.is_file() else None
        # Fail closed on an internal validator error — same as invlang_validate's
        # hook, which exits 2 (block) rather than letting the write through.
        try:
            errors = validate_companion(proposed_text, current)
        except Exception as e:  # noqa: BLE001 — a blocking gate must fail closed
            return Decision(
                False,
                f"investigation.md validation errored — failing closed: {e!r}. "
                "Simplify the invlang and rewrite.",
            )
        if errors:
            return Decision(
                False,
                "investigation.md failed invlang validation — fix and rewrite:\n"
                + "\n".join(f"  - {e}" for e in errors),
            )
    return Decision(True)
