"""The file gates: deny-by-default read allowlist + write/invlang validation.

Both return a plain `Decision`. Reads must resolve inside the run dir or the
defender corpus (with a belt-and-suspenders secret/ground-truth denylist on top);
writes must stay inside the run dir, and an `investigation.md` write must pass the
structural invlang validator. `is_untrusted_read` flags attacker-influenced data
the caller must tag-wrap."""

from __future__ import annotations

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


def _resolved_write_roots(policy: AgentPolicy, run_dir: Path) -> tuple[Path, ...]:
    """The resolved roots a WRITE must land within for `policy`: the run dir always (every
    agent authors its own case artifacts), plus the agent's `write_confine` (the corpus
    subtree a writer may author — the lead author's `defender/skills`). Empty confine (the
    default) is run-dir-only — inert for every read-only/predictor agent and the main loop.
    The mirror of `_resolved_read_roots`; may raise `OSError`/`RuntimeError` from `resolve()`
    (a symlink cycle) — the caller FAILS CLOSED."""
    return tuple(r.resolve() for r in (Path(run_dir), *policy.write_confine))


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
    judge (raw_reads=True) read their own gather_raw to verify / refute."""
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
    path: Path, proposed_text: str, *, run_dir: Path, policy: AgentPolicy
) -> Decision:
    """Allow/deny a write of `proposed_text` to `path` — a **deny-by-default allowlist** (the
    write mirror of `decide_read`). A write must resolve INSIDE one of the allowed roots: the
    run dir (every agent's own case artifacts) OR, when the policy declares a `write_confine`,
    that corpus subtree (the lead author's `defender/skills`). Empty `write_confine` keeps
    writes run-dir-only — the legacy behavior, inert for the main loop / read-only stages.
    `resolve()` collapses `..`/symlinks so an allowed-root prefix can't be escaped; a
    `resolve()` error (a symlink cycle) FAILS CLOSED rather than propagating out of the gate.

    For `investigation.md`, run the structural invlang validator against the
    full proposed text (current on-disk text supplies the append-only baseline);
    any error denies with the validator's messages so the model can fix its
    invlang — the in-process equivalent of the hook's exit-2 feedback.
    """
    path = Path(path)
    try:
        rp = path.resolve()
        roots = _resolved_write_roots(policy, run_dir)
    except (OSError, RuntimeError):
        return Decision(False, f"Blocked: {path} could not be resolved (failing closed).")
    if not any(_is_within(rp, root) for root in roots):
        return Decision(
            False,
            "Blocked: writes must stay inside the run dir or this agent's write "
            f"confine; {path} is outside them.",
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
