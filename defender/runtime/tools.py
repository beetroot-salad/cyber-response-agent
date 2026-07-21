"""Generic agent tools: bash, read_file, write_file, edit_file.

These four small tools are the agent's whole surface — stable across every
future adapter (a new data source is a shim + skill, never a new tool). They
mirror Claude Code's Read/Write/Edit/Bash so SKILL.md transfers verbatim. Each
tool enforces its own contract by calling the single `permission` gate and
raising `ModelRetry` on a deny (the in-process equivalent of a PreToolUse hook's
exit-2 feedback). Untrusted reads are wrapped in the salted tag in-process — the
in-process quarantine delimiter (`runtime/untrusted.wrap`).
"""

from __future__ import annotations

import subprocess
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Self

from defender._clock import now_iso
from defender._paths import PATHS

from pydantic_ai import RunContext
from pydantic_ai.exceptions import ModelRetry

from defender._io import append_jsonl, read_text_utf8
from . import box as box_mod
from . import permission
from .agent_definition import ToolSet
from .agent_role import AgentRole

# Reuse the hook/wrapper helpers in-process (the clean version of the claude -p
# PreToolUse hooks + the gather capture core). The workspace root is on sys.path
# via the entry-point bootstrap (run.py) / pytest's `pythonpath = [".."]`.
from defender.runtime.untrusted import wrap as _wrap
from defender.scripts.gather_tools.record_query import (
    _passthrough_max_bytes as _read_char_cap,
)
from defender.hooks.record_lesson_load import (
    RUNTIME_LESSON_CORPORA as _RUNTIME_LESSON_CORPORA,
    lesson_name as _lesson_name,
)

_BASH_TIMEOUT_S = 120

# read_file char ceiling: the SAME source that caps the gather capture's
# passthrough (record_query._passthrough_max_bytes, imported here as
# _read_char_cap).
# A gather payload is persisted whole on disk, but the in-context VIEW of it —
# whether seen through the capture passthrough OR a later read_file of the same
# file — must stay bounded, or a multi-MB dump overflows the model's context
# window (#303). Sharing one source is the point: the on-disk read can never
# defeat the passthrough cap. Compared against str length (chars), matching
# record_query's own check.


def _lane_admits(policy: permission.AgentPolicy, probe: str) -> bool:
    """Whether the agent's bash lane would accept `probe` — asked through the REAL decide seam,
    so the hint can never disagree with the gate. (Reaching into `bash_allow` and matching it
    directly is how this went wrong before: the tuple's element type is the gate's business, and
    a probe matched against a `Grant` is an `AttributeError` in production, in the overflow
    path.) The probes name no file, so the gate needs no roots to decide them."""
    return permission.decide_bash(probe, policy=policy).allow


def _overflow_filter_hint(
    path: str, policy: permission.AgentPolicy, read_tool: str = "read_file"
) -> str:
    """The "this file is too big — here's how to reduce it" advice, derived from the
    agent's ACTUAL bash lane. A hint naming a program the agent cannot run, or a step it
    cannot take, is worse than no hint — and every part of it here is load-bearing:

      - the reducer is always PIPED (`cat <path> | …`), never handed the file.
        `defender-sql` is stdin-compute-only, so naming an operand form would teach a
        dead command;
      - `defender-sql` for every lane carrying the SQL shim. `jq` was the other branch
        until #540 removed it from the reader lanes: it predated #611's typed `query`
        tool, nothing taught it, and gather's own SKILL counter-taught it;
      - the write-the-result-to-a-file step ONLY for an agent with a writer: gather has
        the shim but no write tool, so it reads the filtered text straight back;
      - a lane with neither reducer (actor / oracle / verify / curators) gets pointed at
        its read tool's `pattern=` substring fold, the only reduction it actually has —
        and named by `read_tool`, NOT a hardcoded `read_file`. The same rule that bans a
        dead PROGRAM bans a dead TOOL: the curators traded `read_file` for the scoped
        `lesson_read` (#559), so a constant here would hand the one agent that reaches
        this branch with a writer an instruction it cannot execute.
    """
    sql_shim = permission.command_shape.SQL_SHIM
    if _lane_admits(policy, f"{sql_shim} 'SELECT 1'"):
        reducer = f'{sql_shim} "SELECT count(*) FROM data"'
    else:
        return (
            "You have no bash reducer for this. Narrow it with the read tool's substring "
            f"search instead:\n  {read_tool}({path!r}, pattern='<substring>')"
        )
    sink = ", write the result to a file, then read that" if policy.write_allow else ""
    return f"Reduce it in a pipe{sink}:\n  cat {path} | {reducer}"


def _bounded_read(
    text: str, path: str, *, filter_hint: str, read_tool: str = "read_file"
) -> str:
    """Bound a file read to the shared char cap (read at call time via
    `_read_char_cap()`). Under the cap → verbatim (the common case: every
    SKILL/lesson/doc fits with room to spare). Over it → the head, plus a notice
    carrying the FULL size (chars + lines, so the model knows the true scale it
    can't see) and `filter_hint` — the only resolution that works on a payload this
    big, spelled in the caller's own bash lane (`_overflow_filter_hint`). No paging —
    the files that overflow are single-document JSON dumps (one giant line), so an
    offset/limit window is a no-op. Slices by char, not byte, so a multibyte
    sequence is never split.

    The notice is tagged with `read_tool` — the tool that actually produced this view — so
    it agrees with the tool named in `filter_hint` (`lesson_read` for a curator, `read_file`
    for every other reader) instead of both claiming a `read_file` the caller may not have."""
    cap = _read_char_cap()
    if len(text) <= cap:
        return text
    total_lines = text.count("\n") + 1
    note = (
        f"\n\n[{read_tool}] {len(text)} chars / {total_lines} line(s); showing the "
        f"first {cap}. This file is too large to read whole — do not "
        f"treat this head as complete. {filter_hint}"
    )
    return text[:cap] + note


def _format_bash_result(exit_code: int, stdout: str, stderr: str, note: str = "") -> str:
    """The bash tool's result envelope, shared by the plain shell path and the
    transparent adapter-capture path so both surface results in one shape."""
    out = stdout if stdout else ""
    err = f"\n--- stderr ---\n{stderr}" if stderr.strip() else ""
    return f"exit={exit_code}\n--- stdout ---\n{out}{err}{note}"


# Per-agent gate policy is DATA, not a role branch: the gate keys on `deps.policy`.
# Every agent's policy is compiled PER-RUN through the single `bind`/`compile_policy`
# seam (#551) from its `AgentDefinition`: the runtime agents via `bind(MAIN_DEF/GATHER_DEF,
# run_dir, defender_dir=…)` (#535 anchors the reader lane to the run's roots — there is no
# module-level MAIN/GATHER default to inherit unconfined), the learning stages via
# `bind(<ROLE>_DEF, …)` in their own engine modules.


@dataclass(frozen=True)
class AgentDeps:
    """Per-run state threaded into every tool via `ctx.deps`. This base type is
    the main orchestrator's deps; each subagent gets an `AgentDeps` subtype. The
    permission gate keys on `policy` (the agent's declared capability, DATA — not a
    role branch), so adding an agent is a new policy value, not a new gate method.
    `role` remains only as an identity label (observability + the gather-capture
    `isinstance` narrow). Code that needs a subtype's fields narrows with
    `isinstance`.

    `policy` is REQUIRED (keyword-only, no inheritable default): a security-critical
    subtype can no longer be born MAIN-shaped by omitting it. Every subtype's `policy` is
    compiled at its construction site through the single `bind` seam (#551) — the per-run
    runtime agents (`GatherDeps`, and the main loop's bare `AgentDeps`) via
    `bind(MAIN_DEF/GATHER_DEF, run_dir, defender_dir=…)` (#535 anchors their reader lane
    per-run, so there is no static default), and the learning stages (`JudgeDeps`,
    `ActorDeps`, …) via `bind(<ROLE>_DEF, …)` in their engines. A subtype supplying none is a
    construction-time `TypeError`, not a silent MAIN."""

    run_dir: Path
    defender_dir: Path
    run_id: str
    salt: str
    policy: permission.AgentPolicy = field(kw_only=True)
    #: The bash lane's execution boundary (#540). Every bash-enabled role carries one, so
    #: "is this agent boxed" is never a role branch — the same question the gate answers from
    #: `policy` rather than from identity. The default is an INERT executor that refuses on
    #: first use: binding a role can never be the thing that silently opens an unboxed lane,
    #: and only `start_box` attaches a live container.
    box: box_mod.BoxExecutor = field(kw_only=True, default_factory=box_mod.BoxExecutor)
    #: The directory a RELATIVE file operand anchors on (#540) — read by the gate's rebase,
    #: `_resolve_operand`, and the executor's cwd, so all three name one directory and no
    #: validator/executor differential can open. Defaults to `run_dir` (the boxed lane's rw
    #: bind); a tree-anchored role carries its worktree root instead. Set once, at `bind`,
    #: from the role's `anchors_on_tree` bit — never recomputed per call site.
    cwd_anchor: Path = field(kw_only=True, default=Path())

    role: ClassVar[AgentRole] = AgentRole.MAIN

    @classmethod
    def _for_run(
        cls, run_dir: Path, policy: permission.AgentPolicy,
        *, defender_dir: Path = PATHS.defender_dir, salt: str | None = None,
        box: box_mod.BoxExecutor | None = None,
        cwd_anchor: Path | None = None,
        **subtype_fields: Any,
    ) -> Self:
        """Build a per-run deps of this subtype: wire the identity fields (run_id as the
        run dir's basename, the salt) and stamp the caller's `policy`. The shared spine
        behind each subtype's `for_scope` and `bind`. `salt` is the untrusted-data trust
        token: `None` mints a FRESH uuid4 (the stages' behaviour, distinct per call), a
        carried value is threaded verbatim — the MAIN/GATHER reroute passes the run's ONE
        minted salt so the tool-output wrapper and orient's alert wrapper stay coherent
        (a fresh uuid4 would split the tag and fail the injection defence open). `defender_dir`
        defaults to the `PATHS` primitive (the MAIN checkout's `<repo>/defender` — the
        read-only predictors + main loop), but a writer that edits a throwaway git WORKTREE
        (the lead author) overrides it with its worktree `<wt>/defender` so the gate resolves
        reads/writes against the right tree.

        `subtype_fields` are a subtype's OWN required fields (the curator's corpus, bound check,
        roots and verify transport), passed straight to the constructor so every deps — base
        and subtype alike — is still born through this one spine. An unknown name is the
        constructor's TypeError, which is the point: a subtype cannot be built half-configured."""
        resolved_salt = salt if salt is not None else uuid.uuid4().hex
        return cls(
            run_dir=run_dir, defender_dir=defender_dir,
            run_id=run_dir.name, salt=resolved_salt, policy=policy,
            box=box if box is not None else box_mod.BoxExecutor(),
            cwd_anchor=cwd_anchor if cwd_anchor is not None else run_dir,
            **subtype_fields,
        )


@dataclass(frozen=True)
class GatherDeps(AgentDeps):
    """Gather subagent deps: an AgentDeps + the lead being gathered. The harness reads
    `lead_id` here to attribute captured queries (it is never model-supplied to
    the capture path). The `GATHER` role drives the permission policy; code that
    needs the gather-only fields narrows with `isinstance(deps, GatherDeps)`.

    There is no `query_id` field: it was never assigned anywhere (the finder/executor split it
    belonged to has been gone since #340), and the `query` tool takes the id as a real param
    (#611). A dead fallback that no writer ever set was a fallback that could only ever mislead
    its reader."""

    role: ClassVar[AgentRole] = AgentRole.GATHER

    # Since #535 the gather reader lane is anchored PER-RUN, so gather has no static
    # policy default (like the per-scope judge/actor): `policy` is REQUIRED from the
    # base (kw_only), built via `bind(GATHER_DEF, run_dir, defender_dir=…)` (#551)
    # at the construction site. A bare `GatherDeps(run_dir, defender_dir, run_id, salt)`
    # is now a construction-time TypeError, not a silent unconfined MAIN/GATHER.
    #
    # `lead_id` is the PER-DISPATCH capture id — UNSET (None) until the dispatch stamps it
    # (#538): `bind(GATHER_DEF, run_dir)` yields a per-run gather deps with `lead_id=None`
    # (bind is scope-only, no lead param), and the gather dispatch (`register_gather_tool`)
    # constructs/stamps the real id before any query capture runs. The capture path
    # asserts it is stamped.
    lead_id: str | None = None


def _record_lesson_load(
    deps: AgentDeps, path: Path, corpora: frozenset[str] = _RUNTIME_LESSON_CORPORA
) -> None:
    """Append a `lessons_loaded.jsonl` row when a lesson from one of `corpora` is read into
    context — the in-process equivalent of the `record_lesson_load` PostToolUse hook (reusing
    its `lesson_name` matcher), feeding learning/trace_lesson.py's lesson→outcome surface.
    Records loads into context, not demonstrable influence (same caveat as the hook).
    Best-effort — never breaks a read.

    `corpora` defaults to the RUNTIME corpus (`defender/lessons/`) alone. Only the curator's
    `lesson_read` widens it to all three (#559 F3): every other reader's `run_dir` IS its
    durable per-case bundle, so an author-corpus row written there would masquerade as a
    defender lesson load in `trace_lesson` — the gray-box actor reads `lessons-actor/`
    tradecraft on every run."""
    name = _lesson_name(str(path), corpora)
    if name is None:
        return
    try:
        row = {"lesson_name": name, "ts": now_iso()}
        append_jsonl(deps.run_dir / "lessons_loaded.jsonl", [row])
    except Exception:  # noqa: BLE001 — best-effort observability
        pass


def _bash_env(deps: AgentDeps) -> dict[str, str]:
    """The runtime agent's shell environment — defined once in run_common.py."""
    from defender import run_common
    return run_common.run_env(deps.defender_dir, deps.run_dir)


def _tool_bash(deps: AgentDeps, command: str) -> str:
    """Logic for the `bash` tool (see the closure's docstring). Module-level so the
    tool closure stays thin; the gather-vs-main adapter-capture path lives here."""
    decision = permission.decide_bash(
        command, policy=deps.policy,
        run_dir=deps.run_dir, defender_dir=deps.defender_dir,
        cwd_anchor=deps.cwd_anchor,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    # The gate parsed the command exactly once and stashed the `Pipeline` list the executor runs
    # on the decision (#456), so execution never re-decomposes the string.
    #
    # There is no adapter branch here any more (#611). A data source is reached through the
    # typed `query` tool, and the bash lane keeps only the local-computation half: gather's lane
    # has no other network-capable program (`python3` is never granted to it), so removing the
    # adapter route IS "take the network off bash". The sanctioned aggregation pipe survives as
    # two steps — `query(...)`, then `cat <payload> | defender-sql '<SQL>'`.
    #
    # Execute the *validated* command without a shell: run the token structure the
    # gate already decomposed (shell=False) instead of re-handing the string to
    # bash. This collapses the validator/executor parser differential — `$VAR`,
    # globs, `$(...)`, and fused redirects never expand, because bash never
    # re-parses. See bash_exec for the rationale.
    #
    # Execution happens INSIDE THE BOX (#540) and nowhere else. There is no in-process
    # fallback on any failure path: a box that cannot be reached is a tool error the model
    # sees, never a quiet downgrade to running the command on the host. `deps.box` is the
    # only route, so a role whose box was never attached fails closed on first use rather
    # than executing unconfined.
    #
    # The cwd is `deps.run_dir` — the same anchor the gate rebased against and the box's rw
    # bind — and it is re-applied on every call, because a cwd does not persist across the
    # boundary.
    try:
        result = deps.box.run_parsed(
            list(decision.pipelines or ()),
            command=command,
            cwd=deps.cwd_anchor,
            timeout=_BASH_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired as e:
        raise ModelRetry(f"command timed out after {_BASH_TIMEOUT_S}s: {command}") from e
    except box_mod.BoxFault as e:
        # An infrastructure fault has no program result: the frame never arrived, so there is
        # no exit code and no stdout to report. It is labelled as the box's own failure rather
        # than dressed in the result envelope, so the model cannot read daemon text as though
        # the command had run and produced it.
        raise ModelRetry(f"the sandbox could not run this command: {e}") from e
    return _format_bash_result(
        result.rc, result.out.decode("utf-8", "replace"), result.err.decode("utf-8", "replace"),
    )


def _grep_lines(text: str, pattern: str) -> str:
    """The grep fold behind `read_file(pattern=)`: the lines of `text` that CONTAIN
    `pattern` (a plain substring match, like the read-only `grep` it replaces for a
    confined agent), newline-joined. Zero matches → `''` — a valid "nothing here"
    outcome, NOT an error (the caller returns it as-is)."""
    return "\n".join(line for line in text.splitlines() if pattern in line)


def _resolve_operand(deps: AgentDeps, path: str) -> Path:
    """Resolve a file-tool operand against the run dir (`deps.run_dir`), matching the bash lane's
    cwd (`_tool_bash` runs the executor at `deps.run_dir`) and the gate's own rebase. One anchor
    at all three sites, or a relative operand names different files to the validator, the file
    tools and the executor — the differential this lane exists to close.

    The anchor moved off the repo root (`defender_dir.parent`) in #540. Two reasons, both
    load-bearing: that directory holds `.env`, `.ssh/` and every sibling worktree, so a relative
    operand used to anchor one `..` away from the tree's credentials; and `run_dir` is the box's
    rw bind, the only anchor that still names the same directory inside the container. An
    absolute operand is unchanged (the read-only stages and the main loop pass absolute run-dir
    paths, so this is inert for them). The gate still `resolve()`s the result, so a `..` escape
    past the confine is still denied."""
    p = Path(path)
    return p if p.is_absolute() else deps.cwd_anchor / p


def _gated_read(
    deps: AgentDeps, path: str, *, lesson_corpora: frozenset[str] = _RUNTIME_LESSON_CORPORA
) -> tuple[Path, str]:
    """The shared front half of every read tool (`read_file`, the curator's `lesson_read`):
    resolve → gate → existence → read → lesson-load trace. The gate runs FIRST, before any
    existence check, so a denied read raises the policy denial for an existing and an absent
    path alike — no existence oracle. `_record_lesson_load` fires once, here, for whichever
    tool did the read — over `lesson_corpora`, the runtime corpus by default and all three only
    for the curator's `lesson_read`. Returns the resolved path (for the trust check) and the
    raw text."""
    p = _resolve_operand(deps, path)
    decision = permission.decide_read(
        p, run_dir=deps.run_dir, defender_dir=deps.defender_dir,
        policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    if not p.is_file():
        raise ModelRetry(f"file not found: {path}")
    # Pinned utf-8, and an undecodable file is a ModelRetry, not a stage kill (#588). The pin
    # alone is not enough: `read_text` under the ambient locale mangles a lesson's em-dash, and
    # `read_text(encoding="utf-8")` on a genuinely undecodable file raises UnicodeDecodeError —
    # a ValueError no gate converts, so it escapes the tool and takes the run down. The agent
    # can act on "this file isn't text"; the run cannot act on a traceback.
    try:
        text = read_text_utf8(p)
    except UnicodeDecodeError:
        raise ModelRetry(f"{path} is not valid UTF-8 text (binary or corrupt)") from None
    except OSError as e:
        # The OTHER half of TEXT_READ_ERRORS, and it escapes for the same reason the decode
        # error did. `is_file()` above is not a read-permission check — the gate is a policy
        # gate, not a filesystem one — and it races the read: an unreadable mode, a symlink
        # loop, a file deleted between the two syscalls all land here. Same rule: the agent can
        # act on "couldn't read it"; the run cannot act on a traceback.
        raise ModelRetry(f"could not read {path}: {e}") from None
    _record_lesson_load(deps, p, lesson_corpora)  # lesson→outcome traceability (best-effort)
    return p, text


def _bound_and_wrap(
    deps: AgentDeps, p: Path, path: str, text: str, *, read_tool: str
) -> str:
    """The shared back half of every read tool: bound the in-context view to the char cap,
    then salt-wrap it iff the source is attacker-influenced. Bound BEFORE wrapping — an
    oversized payload read whole would overflow the model's window (#303), and capping first
    means the head is what gets tag-wrapped (injected text in it stays inert), not the full
    dump. A trusted read (`is_untrusted_read` False — every lesson, a SKILL, a doc) skips the
    wrap and returns the (bounded) text raw.

    `read_tool` is REQUIRED (no default): it is the name the overflow notice + hint tell the
    model to call, so an agent whose read tool is not `read_file` (the curators' `lesson_read`,
    #559) must state it rather than inherit a constant that would teach it a dead tool."""
    text = _bounded_read(
        text, path,
        filter_hint=_overflow_filter_hint(path, deps.policy, read_tool),
        read_tool=read_tool,
    )
    if permission.is_untrusted_read(p):
        # Attacker-influenced data — wrap so injected instructions inside it
        # are inert. Same delimiter as the rest of the system.
        return _wrap(text, "untrusted", deps.salt)
    return text


def _tool_read_file(deps: AgentDeps, path: str, pattern: str | None = None) -> str:
    """Logic for the `read_file` tool: permission → (optional grep fold) → bound →
    untrusted-wrap, over the shared `_gated_read`/`_bound_and_wrap` core. An optional
    `pattern` folds grep into the read (return only the matching lines): search never widens
    the read surface — `_gated_read` gates the PATH before any scan — so a `pattern` over a
    denied path still raises."""
    p, text = _gated_read(deps, path)
    if pattern is not None:
        # grep fold: only the matching lines reach the model (the read-only bash
        # grep viewer a confined agent no longer has). No-match → '' (not an error).
        text = _grep_lines(text, pattern)
    return _bound_and_wrap(deps, p, path, text, read_tool="read_file")


def _tool_write_file(deps: AgentDeps, path: str, content: str) -> str:
    """Logic for the `write_file` tool: a validated write against the policy's
    `write_allow` (the agent's declared paths — the main loop's run dir, the
    lead-author writer's `defender/skills/**.md` corpus)."""
    p = _resolve_operand(deps, path)
    decision = permission.decide_write(
        p, content, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    # Mirror Claude Code's Write (which the claude -p stages used): create missing
    # parent dirs so a write into a not-yet-existing corpus subtree (the lead author
    # promoting/lifting into a new system dir) succeeds instead of raising an uncaught
    # FileNotFoundError — which run_stage maps to RunUnprocessable, quarantining the
    # whole run and discarding every valid in-tree edit already made. The gate ran
    # first, so we only ever mkdir under an allowed (write_allow) path.
    p.parent.mkdir(parents=True, exist_ok=True)
    # Pinned to match the read (#588). An ambient-locale WRITE beside a utf-8-pinned READ is the
    # silent-loss half: a lesson containing `café` is written as latin-1 bytes, committed, and
    # then warn-skipped as "malformed" by every corpus walk that reads it back.
    p.write_text(content, encoding="utf-8")
    return f"wrote {path} ({len(content)} bytes)"


def _tool_edit_file(deps: AgentDeps, path: str, old_string: str, new_string: str) -> str:
    """Logic for the `edit_file` tool: gate the READ first, then the create-only /
    not-found / non-unique guards, then a validated write.

    The read gate (`decide_read`) runs BEFORE `p.read_text()` — parity with `read_file`.
    Without it, edit_file's differential `ModelRetry`s ("old_string not found" vs "not
    unique (N)") plus `p.is_file()` would be an existence / substring / occurrence-count
    oracle over ANY path the process can read (a `.env`, the eval `ground_truth.yaml`),
    bypassing the read confine + secret denylist that `read_file` enforces. Every path an
    agent may WRITE it may also READ (write_allow ⊆ read roots), so this denies no legit
    edit — it only closes the probe of files outside the agent's read surface."""
    p = _resolve_operand(deps, path)
    read_decision = permission.decide_read(
        p, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy
    )
    if not read_decision.allow:
        raise ModelRetry(read_decision.reason)
    try:
        current = read_text_utf8(p) if p.is_file() else ""
    except UnicodeDecodeError:
        raise ModelRetry(f"{path} is not valid UTF-8 text (binary or corrupt)") from None
    if not old_string and p.is_file():
        # Empty old_string against an existing file would replace the WHOLE
        # file with new_string (silent clobber). Mirror Claude Code's Edit:
        # empty old_string is create-only. Use write_file for a full replace.
        raise ModelRetry(
            f"{path} already exists; an empty old_string would overwrite it. "
            "Pass a unique old_string to edit, or use write_file to replace it."
        )
    if old_string and old_string not in current:
        raise ModelRetry(f"old_string not found in {path}")
    if old_string and current.count(old_string) > 1:
        # Mirror Claude Code's Edit: a non-unique old_string is ambiguous.
        # Replacing the first match silently would edit the wrong occurrence
        # (e.g. a repeated invlang row marker) and can pass invlang validation.
        raise ModelRetry(
            f"old_string is not unique in {path} ({current.count(old_string)} "
            "occurrences); include enough surrounding context to match exactly "
            "one, or use write_file to replace the whole file."
        )
    new_text = current.replace(old_string, new_string, 1) if old_string else new_string
    decision = permission.decide_write(
        p, new_text, run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    if not decision.allow:
        raise ModelRetry(decision.reason)
    # Create-into-a-new-subtree parity with write_file (and Claude Code's Edit): mkdir
    # the parents of an approved path so a create edit into a fresh dir doesn't raise an
    # uncaught FileNotFoundError that quarantines the run. No-op on the common in-place
    # edit (parent already exists); only runs after the gate approved the path.
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(new_text, encoding="utf-8")  # pinned to match the read (#588)
    return f"edited {path} ({len(new_text)} bytes)"


def register_tools(agent, tools: ToolSet, verbs: Any = None) -> None:
    """Register EXACTLY the tools `tools` declares present on `agent` (deps_type must
    be AgentDeps) — the single toolset-registration site (#538). There is no always-on
    pair: a tool exists iff its `ToolSet` bit is set, so the pure-prediction stages
    (`ToolSet()`) register NOTHING (structural tool-freeness, not a runtime gate), while
    main keeps all four. Registration order is fixed — `bash, read_file, write_file,
    edit_file, forward_check, lesson_read, template_search, query` — independent of the `ToolSet`
    field order, so the pinned tool ordering the e2e suite asserts is stable. `bash` is present
    iff `tools.bash` (an agent may hold the tool and be granted no program — the gate then denies
    every command; tool PRESENCE and PERMISSION are two facts); the file writers are the
    `tools.write` opt-in.

    `verbs` is the data-source registry the `query` tool validates + dispatches against, threaded
    down the build chain from `run_investigation` exactly like `make_model` (#611). Required iff
    `tools.query`; a def that declares the tool and is handed no registry fails LOUD at build
    rather than at the first query."""

    if tools.bash:
        @agent.tool
        async def bash(ctx: RunContext[AgentDeps], command: str) -> str:
            """Run a shell command. Use the `defender-*` shims (defender-invlang,
            defender-lessons, …) for first-party tooling. Data-source adapters are
            not runnable from the main loop — dispatch gather instead."""
            return _tool_bash(ctx.deps, command)

    if tools.read:
        @agent.tool
        async def read_file(
            ctx: RunContext[AgentDeps], path: str, pattern: str | None = None
        ) -> str:
            """Read a file's contents (e.g. alert.json, a SKILL, a lesson). Pass
            `pattern` to return only the lines containing that substring — the grep
            fold, for scanning a large file (or when the read-only bash grep/cat
            viewers are not available to this agent)."""
            return _tool_read_file(ctx.deps, path, pattern)

    if tools.write:
        @agent.tool
        async def write_file(ctx: RunContext[AgentDeps], path: str, content: str) -> str:
            """Write a file in the run dir (investigation.md, report.md). Writes of
            investigation.md are validated against the invlang schema."""
            return _tool_write_file(ctx.deps, path, content)

        @agent.tool
        async def edit_file(
            ctx: RunContext[AgentDeps], path: str, old_string: str, new_string: str
        ) -> str:
            """Replace the first occurrence of old_string with new_string in a run-dir
            file. The resulting full text is validated (invlang for investigation.md)."""
            return _tool_edit_file(ctx.deps, path, old_string, new_string)

    _register_deferred_tools(agent, tools, verbs)


def _register_deferred_tools(agent, tools: ToolSet, verbs: Any = None) -> None:
    """The tools whose BODY lives in the owning agent's own package rather than here, and which
    therefore have to be imported at registration time instead of at module top.

    Every one of them reaches back into this module's core (the read/bash foundation, or the
    re-exported gather surface at the bottom of this file), so a module-scope import would close a
    cycle. Registration runs at agent-build time, long after both modules are loaded, so it never
    does. Same shape as `register_gather_tool`. Split out of `register_tools` so the presence
    checks it composes stay one flat table rather than pushing the caller over its complexity
    budget — the ORDER here is the tail of `register_tools`' fixed order."""
    if tools.forward_check:
        # The curators' author-time forward check (#558): pulls the verify transport, and the
        # pydantic-ai graph under it.
        from defender.learning.author.verify_forward.tool import register_forward_check_tool

        register_forward_check_tool(agent)

    if tools.lesson_read:
        # The curators' scoped read tool (#559): lives in the author package (it pulls
        # `_frontmatter` for the body/full split) and reuses this module's read core.
        from defender.learning.author.lesson_read import register_lesson_read_tool

        register_lesson_read_tool(agent)

    if tools.template_search:
        # Gather's query-catalog search (#585): `tools_gather` imports this module's foundation,
        # and this module re-exports its surface at the bottom.
        from defender.runtime.tools_gather import register_template_search_tool

        register_template_search_tool(agent)

    if tools.query:
        # Gather's typed data-source access (#611). Deferred like the others: `query_tool` reaches
        # back into this module's result envelope + run-env core, so a module-scope import would
        # close a cycle. The registry is REQUIRED here — a `query` tool with no registry has no
        # allowlist to validate against, which is the fail-open shape this whole change exists to
        # close, so it fails at BUILD rather than shipping a tool that admits everything.
        from defender.runtime.query_tool import register_query_tool

        if verbs is None:
            raise ValueError(
                "ToolSet(query=True) needs a verb registry — thread one from "
                "run_investigation(verbs=…); a query tool with no registry has no allowlist."
            )
        register_query_tool(agent, verbs)


# --- gather dispatch ---------------------------------------------------------
# Lives in tools_gather.py (imports the foundation above). Re-exported here so
# the historical public surface holds: driver.py imports `register_gather_tool`
# from `.tools`, and tests reach `tools._run_gather` as an attribute of THIS
# module (the e2e replay test monkeypatches it). Imported at the BOTTOM, after
# the foundation is defined, so the tools_gather → tools import resolves without
# a cycle.
from .tools_gather import (  # noqa: E402, F401  (re-exported — public surface)
    GatherRequest,
    _gather_prompt,
    _payload_note,
    _persist_gather_summary,
    _run_gather,
    _tripped_message,
    register_gather_tool,
)
