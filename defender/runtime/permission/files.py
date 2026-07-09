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


def _is_within(p: Path, root: Path) -> bool:
    """True iff resolved path `p` is `root` or below it."""
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False


def _denylisted(rp: Path) -> bool:
    """True iff a resolved path hits the secret/ground-truth denylist — a denied
    filename substring (`.env` / `cases.json` / `ground_truth` / `credentials`) or a
    denied path component (`.ssh`). Belt-and-suspenders that applies INSIDE every
    allowed root, on BOTH read surfaces: the read tool (`decide_read`) and the judge's
    bash `jq` lane (`read_allowed_path`) — so the two surfaces can't disagree about a
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
    `RuntimeError` from `resolve()` (a symlink cycle) — every caller FAILS CLOSED."""
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
    containment half of `decide_read`, reused by the judge's bash-lane `jq`
    path-gate (`permission.bash`). FAILS CLOSED: a `resolve()` error (a symlink
    cycle) OR a missing root context (`run_dir`/`defender_dir` `None`) returns
    `False`, never raises. The secret/ground-truth denylist IS applied (parity with
    `decide_read`, so `jq` can't read a denied file the read tool refuses — the
    held-out `ground_truth.yaml`, a captured `.env`); the gather_raw RAW clamp is
    NOT — a `jq` reader that may read raw (the judge, `raw_reads=True`) legitimately
    names a gather_raw path, and the bash gate owns the raw clamp for agents that
    may not."""
    if run_dir is None or defender_dir is None:
        return False  # no root context to gate against — fail closed
    try:
        rp = Path(path).resolve()
        roots = _resolved_read_roots(policy, run_dir, defender_dir)
    except (OSError, RuntimeError):
        return False
    if _denylisted(rp):
        return False  # a secret / ground-truth file is denied even inside a root
    return any(_is_within(rp, root) for root in roots)


def decide_read(
    path: Path, *, run_dir: Path, defender_dir: Path, policy: AgentPolicy
) -> Decision:
    """Allow/deny a file read — a **deny-by-default allowlist**, matching the shape
    `decide_write` already uses for writes. A read must resolve INSIDE one of the
    allowed roots: the run dir (the agent's own case artifacts + gather payloads),
    the defender corpus (`defender_dir` — skills / lessons / scripts / SKILL.md) OR,
    when the policy declares a `read_confine`, that confine set IN PLACE of the
    corpus (the gray-box actor sees only its lesson dirs), plus any of the agent's
    declared `policy.read_roots` (e.g. the judge's comparison dir under
    `learning_run_dir`). Everything outside them fails closed. `resolve()` collapses
    `..` and symlinks, so an allowed-root prefix can't be escaped (the structural
    close for the `cat …/.env` / basename-only / case-sensitivity gaps a denylist
    alone left); a `resolve()` error (a symlink cycle) FAILS CLOSED rather than
    propagating out of a blocking gate.

    On top of the allowlist, the declarative secret/ground-truth denylist
    (`bash_policy.json`) still denies a sensitive file that lands INSIDE a root — a
    captured `.env` in the run dir, the eval `cases.json`/`ground_truth.yaml` — cheap
    belt-and-suspenders that applies to every agent regardless of policy.

    The gather_raw clamp is now a policy bit: the main loop (raw_reads=False)
    consumes the gather summary, never the raw payload; the gather subagent and the
    judge (raw_reads=True) read their own gather_raw to verify / refute.

    On top of the roots, a reader agent (main/gather) carries a `read_shapes` filename
    filter (#545): the resolved path must additionally `fullmatch` one of those anchored
    grammars — the read-tool twin of the bash `cat` lane's file-operand grammar, so a
    non-`.md` corpus file readable by neither surface. The run-dir branch of that grammar
    keeps run-dir scratch unfiltered; empty `read_shapes` (every non-reader agent) leaves
    the gate root-only."""
    p = Path(path)
    try:
        rp = p.resolve()
        roots = _resolved_read_roots(policy, run_dir, defender_dir)
    except (OSError, RuntimeError):
        return Decision(False, f"Blocked: {p} could not be resolved (failing closed).")
    if not any(_is_within(rp, root) for root in roots):
        return Decision(
            False,
            "Blocked: reads are limited to the run dir, the defender corpus (or "
            "this agent's read confine), and its declared roots; "
            f"{p} is outside them.",
        )
    # Read-tool↔bash-lane filename parity (#545): a reader agent's `read_shapes` admits
    # exactly the filename set its bash `cat` lane does, so a corpus file the bash lane
    # rejects (a non-`.md` under defender/) is not readable via the read tool either. Run-dir
    # paths match the grammar's own run-dir branch, so scratch stays unfiltered; an empty
    # `read_shapes` (non-reader agents / the legacy API) applies no filter.
    if policy.read_shapes and not any(pat.fullmatch(str(rp)) for pat in policy.read_shapes):
        return Decision(
            False,
            f"Blocked: {rp.name} is not a readable file for this agent — corpus reads are "
            "limited to the tight filename grammar the bash cat lane enforces (a .md file "
            "under lessons/skills/examples); read your run dir for anything else.",
        )
    # Belt-and-suspenders: a secret / ground-truth file INSIDE an allowed root is
    # still denied (substrings match the filename, dirs match any path component).
    # Shared with the bash `jq` lane (`read_allowed_path`) so both surfaces agree.
    if _denylisted(rp):
        return Decision(False, f"Blocked: {rp.name} is a denied read (secrets / ground truth).")
    # No gather-payload-tool exemption here: that exemption is about a Bash
    # *command* invoking record-query (which legitimately names a gather_raw
    # path). block_main_loop_raw_access never applies it to a Read
    # (its `cmd` is "" for non-Bash), so a read of any gather_raw path by an agent
    # that may not read raw (raw_reads=False, e.g. the main loop) is clamped.
    if RAW_MARKER in str(rp) and not policy.raw_reads:
        return Decision(False, RAW_DENY_REASON)
    return Decision(True)


def is_untrusted_read(path: Path) -> bool:
    """True for reads of attacker-influenced data that must be tag-wrapped:
    the alert payload and (slice 2) raw gather payloads."""
    p = Path(path)
    return p.name == "alert.json" or RAW_MARKER in str(p)


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
    a `resolve()` error (a symlink cycle) FAILS CLOSED rather than propagating out of the gate.

    `run_dir`/`defender_dir` are the OPTIONAL run roots (uniform with `decide_read`/`decide_bash`):
    when both are supplied, a write target must ALSO resolve within the agent's read CONTAINMENT
    — its read roots (`read_confine`/`read_roots`/run dir/`defender_dir`) minus the secret/ground-
    truth denylist (`read_allowed_path`), the `write_allow ⊆ read roots` invariant `edit_file`
    relies on. NOTE this is containment + denylist, NOT the full `decide_read` gate: it does not
    apply the gather_raw RAW clamp (shared with the judge's `jq` lane, which legitimately reads
    raw), so a `raw_reads=False` writer whose `write_allow` admits a `gather_raw/` path is not
    additionally blocked here — no real writer's `write_allow` reaches there. Skipped when omitted
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
    except (OSError, RuntimeError):
        return Decision(False, f"Blocked: {path} could not be resolved (failing closed).")
    if not any(pat.fullmatch(str(rp)) for pat in policy.write_allow):
        return Decision(
            False,
            "Blocked: writes are limited to this agent's declared paths "
            f"(its write allowlist); {path} is not one of them.",
        )
    # Defense-in-depth (write ⊆ read roots): when the run roots are supplied, the write target
    # must also sit inside the agent's read CONTAINMENT — its read roots minus the secret/ground-
    # truth denylist (`read_allowed_path`), fails closed on a resolve error. This is containment +
    # denylist, NOT the full `decide_read` (no gather_raw RAW clamp — that lane is shared with the
    # judge's jq, which may read raw). A no-op for every real writer (its write_allow already sits
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
