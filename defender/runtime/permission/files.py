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
from defender.runtime.agent_role import AgentRole
from defender.skills.invlang.validate import validate_companion

from .decision import Decision


def _is_within(p: Path, root: Path) -> bool:
    """True iff resolved path `p` is `root` or below it."""
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False


def decide_read(
    path: Path, *, run_dir: Path, defender_dir: Path, role: AgentRole
) -> Decision:
    """Allow/deny a file read — a **deny-by-default allowlist**, matching the shape
    `decide_write` already uses for writes. A read must resolve INSIDE one of two
    roots: the run dir (the agent's own case artifacts + gather payloads) or the
    defender corpus (`defender_dir` — skills / lessons / scripts / SKILL.md). Past
    runs read essentially nothing else (alert.json, SKILLs, lessons, run artifacts);
    everything outside both roots fails closed. `resolve()` collapses `..` and
    symlinks, so an allowed-root prefix can't be escaped (the structural close for
    the `cat …/.env` / basename-only / case-sensitivity gaps a denylist alone left).

    On top of the allowlist, the declarative secret/ground-truth denylist
    (`bash_policy.json`) still denies a sensitive file that lands INSIDE a root — a
    captured `.env` in the run dir, the eval `cases.json` — cheap belt-and-suspenders.

    The main-loop gather_raw clamp is unchanged: the main loop consumes the gather
    summary, never the raw payload; the gather subagent (a non-MAIN role) reads
    its own gather_raw to verify its query result."""
    p = Path(path)
    rp = p.resolve()
    roots = (Path(run_dir).resolve(), Path(defender_dir).resolve())
    if not any(_is_within(rp, root) for root in roots):
        return Decision(
            False,
            "Blocked: reads are limited to the run dir and the defender corpus "
            f"(skills/lessons/scripts); {p} is outside both.",
        )
    # Belt-and-suspenders: a secret / ground-truth file INSIDE an allowed root is
    # still denied (substrings match the filename, dirs match any path component).
    name = rp.name
    parts = set(rp.parts)
    if any(d in parts for d in bash_policy.read_deny_dirs()) or any(
        s in name for s in bash_policy.read_deny_substrings()
    ):
        return Decision(False, f"Blocked: {name} is a denied read (secrets / ground truth).")
    # No gather-payload-tool exemption here: that exemption is about a Bash
    # *command* invoking record-query (which legitimately names a gather_raw
    # path). block_main_loop_raw_access never applies it to a Read
    # (its `cmd` is "" for non-Bash), so a main-loop read of any gather_raw path is
    # unconditionally clamped.
    if RAW_MARKER in str(rp) and role is AgentRole.MAIN:
        return Decision(False, RAW_DENY_REASON)
    return Decision(True)


def is_untrusted_read(path: Path) -> bool:
    """True for reads of attacker-influenced data that must be tag-wrapped:
    the alert payload and (slice 2) raw gather payloads."""
    p = Path(path)
    return p.name == "alert.json" or RAW_MARKER in str(p)


def decide_write(path: Path, proposed_text: str, *, run_dir: Path) -> Decision:
    """Allow/deny a write of `proposed_text` to `path`, porting the
    `Write(<run_dir>/**)` path allow + `invlang_validate`.

    For `investigation.md`, run the structural invlang validator against the
    full proposed text (current on-disk text supplies the append-only baseline);
    any error denies with the validator's messages so the model can fix its
    invlang — the in-process equivalent of the hook's exit-2 feedback.
    """
    path = Path(path)
    run_dir = Path(run_dir).resolve()
    if not _is_within(path.resolve(), run_dir):
        return Decision(
            False,
            f"Blocked: writes must stay inside the run dir ({run_dir}); "
            f"{path} is outside it.",
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
