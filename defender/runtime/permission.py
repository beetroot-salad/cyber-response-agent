"""Single in-process permission/validation gate for the PydanticAI runtime.

This is the simplified port of the four Claude Code PreToolUse hooks
(`approve_shim_invocations`, `block_main_loop_raw_access`,
`block_unwrapped_adapter_calls`, `invlang_validate`). Instead of four
subprocesses reading stdin-JSON and exiting 2, one module exposes pure decision
functions that the driver calls in-process and raises `ModelRetry` on a deny.

**Functionality parity:** the *logic* is the existing logic — we import the same
`hooks/_cmd_segments.py` taxonomy and the same gate predicates, so a newly
onboarded `defender-*` adapter auto-gates here too, exactly as in the `claude -p`
runtime. We do not re-implement the rules; we re-host them.

Decisions are pure (`command`/`text` in, `Decision` out) so they unit-test for
free, with no model call.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

# Reuse the same hook taxonomy + gate predicates verbatim (`defender.hooks.*`) —
# these are pure (no stdin/exit), so the in-process gate and the subprocess hooks
# can never disagree. The workspace root is on sys.path via the entry-point
# bootstrap (run_pai.py) / pytest's `pythonpath = [".."]`.
from defender.hooks._cmd_segments import (
    ADAPTER_CLI_RE,
    NON_ADAPTER_SHIMS,
    split_segments,
    unwrap,
)
from defender.hooks.approve_shim_invocations import (
    GATHER_READONLY_TOOLS,
    READONLY_TOOLS,
    _all_segments_safe,
)
from defender.hooks.block_main_loop_raw_access import (
    ADAPTER_DENY_REASON,
    RAW_DENY_REASON,
    RAW_MARKER,
    _adapter_shim_re,
)
from defender.skills.invlang.validate import validate_companion

# Fall-through in `claude -p` meant "ask the user"; headless we have no prompt,
# so an unrecognized main-loop command fails closed (deny), matching the net
# effect of the static allowlist (only defender-* shims + jq/ls/cat were ever
# permitted without a prompt).
FALLTHROUGH_DENY_REASON = (
    "Blocked: only the defender-* shims and read-only viewers (jq/ls/cat/…) are "
    "permitted from the main loop. Dispatch gather for data-source access; do not "
    "run arbitrary shell."
)

# The gather subagent IS the data-access layer, so the main-loop "dispatch gather"
# advice is nonsensical here — it would tell gather to dispatch itself. Gather may
# run a data-source adapter (`defender-<system> …`) directly as a standalone
# command (captured automatically) plus read-only viewers; everything else fails
# closed. Give it that lane verbatim instead of the main-loop reason.
GATHER_FALLTHROUGH_DENY_REASON = (
    "Blocked: gather may only run a data-source adapter (`defender-<system> …`) as "
    "a standalone command — it is captured automatically — plus read-only viewers "
    "(jq/grep/ls/cat/…). To read data, run the adapter directly; don't run "
    "arbitrary shell (no curl/rm/python3, no pipes or redirects into writes)."
)

# The finder finds the query and delegates execution to the assay tool — it has
# NO direct data-source access (the hard boundary that makes the finder/executor
# split worth its cost: the iterating executor carries a tiny context, the finder
# never runs a query). Adapters are denied here (pointed at assay); only read-only
# viewers/find are allowed, for scanning templates during orientation.
FINDER_NO_ADAPTER_REASON = (
    "Blocked: the finder has no direct data-source access. Call "
    "assay(system, verb, template_id|coined_query, query_id, params, dim_hints) to "
    "run a query — the executor runs it in a clean context and returns the computed "
    "characterization. Only read-only viewers (grep/ls/cat/jq/find) are available "
    "here, for scanning templates during orientation."
)

# The finder must reason from the executor's returned ## Summary, never from the
# raw payloads the executor persists — reading those dumps re-floods the finder's
# context (the cost problem the split exists to kill) and undoes the boundary. The
# finder has no gather_raw access at all (unlike the executor, which jq-summarizes
# its own payload).
FINDER_RAW_REASON = (
    "Blocked: the finder reasons from the executor's returned ## Summary, not from "
    "raw payloads — it has no gather_raw access. If an assay's summary is too thin, "
    "run another assay with tighter dim_hints; never read the dump."
)

# Gather may run a data-source adapter directly — it's captured transparently —
# but only as a standalone command (a pipeline/compound makes "the payload"
# ambiguous). Run it solo, then filter the persisted payload file.
ADAPTER_STANDALONE_REASON = (
    "Blocked: run the data-source adapter as a standalone command (it is captured "
    "automatically — no wrapper needed), then filter the persisted payload file "
    "with jq/grep/Read. Don't pipe or chain the adapter call."
)

# The gather-payload tools legitimately name `gather_raw` paths on the command
# line (data-source-debug reads one, record-query writes one) — exempt them from
# the raw clamp. Mirrors block_main_loop_raw_access.main's exemption.
_GATHER_PAYLOAD_TOKENS = (
    "data_source_debug", "defender-data-source-debug",
    "record_query", "defender-record-query",
)


@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str = ""


def _names_a_gather_payload_tool(cmd: str) -> bool:
    return any(tok in cmd for tok in _GATHER_PAYLOAD_TOKENS)


# The bin/ roster and the adapter regex are constant for this process's lifetime
# (under `claude -p` each hook was a fresh subprocess, so per-call rebuild was
# unavoidable; in-process it's wasted work + a per-call dir scan). Memoize both.
@lru_cache(maxsize=1)
def _cached_adapter_re():
    return _adapter_shim_re()


@lru_cache(maxsize=1)
def _safe_main_tokens() -> frozenset:
    return frozenset(set(READONLY_TOOLS) | set(NON_ADAPTER_SHIMS))


@lru_cache(maxsize=1)
def _safe_gather_tokens() -> frozenset:
    # Gather gets the main safe set plus its discovery tools (find). The
    # find action-flag guard lives in _all_segments_safe, so a `-exec`/`-delete`
    # find is still denied here.
    return frozenset(_safe_main_tokens() | GATHER_READONLY_TOOLS)


@lru_cache(maxsize=1)
def _safe_finder_tokens() -> frozenset:
    # The finder gets ONLY read-only viewers + find (to scan templates) — not the
    # non-adapter shims (record-query/data-source-debug), because those would let
    # it capture a query and circumvent the assay boundary, and never an
    # adapter. Its only data path is the assay tool.
    return frozenset(set(READONLY_TOOLS) | set(GATHER_READONLY_TOOLS))


def _segment_is_adapter(toks: list[str]) -> bool:
    """True iff the segment's COMMAND (first token) is a data-source adapter — a
    `defender-<system>` shim or a `<system>_cli.py` script. `toks` is one command's
    token list from `split_segments`. Anchored to command position: an adapter name
    appearing as an *argument* (`which defender-elastic`, `cat …/defender-elastic`)
    is NOT a query and must not be captured."""
    if not toks:
        return False
    # split_segments hands back the whole script as one opaque token when it can't
    # parse it (a quote spanning a newline). A real command's head is a single
    # whitespace-free word, so a head carrying whitespace IS that opaque fallback —
    # never an adapter. Refusing it routes the command to the fail-closed deny in
    # decide_bash/_all_segments_safe instead of the capture path (which would only
    # error on an unrunnable argv).
    if any(c.isspace() for c in toks[0]):
        return False
    cmd = toks[0]
    if cmd in ("python", "python3") and len(toks) > 1:
        cmd = toks[1]  # raw `python3 …/<system>_cli.py` form
    if cmd.startswith("defender-"):
        return cmd not in NON_ADAPTER_SHIMS
    return bool(ADAPTER_CLI_RE.search(cmd))


def adapter_argv(command: str) -> list[str] | None:
    """If `command` is a STANDALONE adapter invocation (the gather-captured case),
    return its argv; else None. Standalone = a single shell segment whose command
    is an adapter, after unwrapping a leading `timeout`/`bash -c`. The gather bash
    tool uses this to route the call through the transparent capture path."""
    inner = unwrap(command.strip())
    if inner is None:
        return None
    segs = [s for s in split_segments(inner) if s]
    if len(segs) != 1 or not _segment_is_adapter(segs[0]):
        return None
    return segs[0]  # the command's token list IS the argv (shlex-resolved)


def decide_bash(command: str, *, is_main_session: bool, is_finder: bool = False,
                executor_system: str | None = None) -> Decision:
    """Allow/deny a Bash command, porting the three Bash gate hooks.

    `is_main_session=True` → the orchestrator (slice 1 is always this): no
    adapter calls, no gather_raw reads, only safe shims/viewers.
    `is_main_session=False` → a gather subagent (slice 2). `is_finder=True` is the
    finder: read-only viewers/find only, NO adapter access (data goes through the
    assay tool). `is_finder=False` is the executor: adapters allowed and
    captured transparently. `executor_system` set marks the finder/executor split's
    executor: it gets NO `find` (no filesystem crawl — it works from its query's
    payload). Cross-system adapter scope is enforced in the bash tool (which has the
    canonical system deriver + the assay's system). `executor_system=None` is the
    legacy single-agent gather, which keeps the looser surface.
    """
    cmd = command.strip()
    if not cmd:
        return Decision(True)

    if is_finder:
        # Finder: finds + delegates. assay is its only path to data.
        # Allow read-only viewers + find for orientation; deny adapters (point at
        # assay), gather_raw reads (reason from the summary), and
        # arbitrary shell, fail-closed.
        if RAW_MARKER in cmd:
            return Decision(False, FINDER_RAW_REASON)
        inner = unwrap(cmd)
        if inner is None:
            return Decision(False, FINDER_NO_ADAPTER_REASON)
        segs = [s for s in split_segments(inner) if s]
        if any(_segment_is_adapter(s) for s in segs):
            return Decision(False, FINDER_NO_ADAPTER_REASON)
        if not _all_segments_safe(inner, _safe_finder_tokens()):
            return Decision(False, FINDER_NO_ADAPTER_REASON)
        return Decision(True)

    if not is_main_session:
        # Gather subagent. A standalone adapter call is allowed directly — the
        # harness captures it (queries table + payload), so no record-query
        # wrapper is needed. But only solo: capturing one adapter inside a
        # pipeline/compound is ambiguous, so a compound containing an adapter is
        # denied (run it standalone, then filter the payload). Non-adapter
        # commands must be read-only viewers / non-adapter shims, so arbitrary
        # shell (`rm`, `curl|bash`, `python3 …`) still fails closed.
        inner = unwrap(cmd)
        if inner is None:
            return Decision(False, GATHER_FALLTHROUGH_DENY_REASON)
        segs = [s for s in split_segments(inner) if s]
        if any(_segment_is_adapter(s) for s in segs):
            if len(segs) != 1:
                return Decision(False, ADAPTER_STANDALONE_REASON)
            return Decision(True)
        # The scoped executor (executor_system set) gets the main safe set — no
        # `find` (no filesystem crawl; it works from its query's payload). The
        # legacy single-agent gather (executor_system=None) keeps `find`.
        toks = _safe_main_tokens() if executor_system else _safe_gather_tokens()
        if not _all_segments_safe(inner, toks):
            return Decision(False, GATHER_FALLTHROUGH_DENY_REASON)
        return Decision(True)

    # --- main loop (block_main_loop_raw_access + approve_shim_invocations) ---
    if RAW_MARKER in cmd and not _names_a_gather_payload_tool(cmd):
        return Decision(False, RAW_DENY_REASON)

    shim_re = _cached_adapter_re()
    is_adapter = bool(ADAPTER_CLI_RE.search(cmd)) or bool(shim_re and shim_re.search(cmd))
    wrapped = "record_query.py" in cmd or "defender-record-query" in cmd
    if is_adapter and not wrapped:
        return Decision(False, ADAPTER_DENY_REASON)

    # Allow iff composed entirely of safe tokens (readonly viewers + non-adapter
    # shims), after unwrapping a leading `timeout`/`bash -c`. Else fail closed.
    inner = unwrap(cmd)
    if inner is None:
        return Decision(False, FALLTHROUGH_DENY_REASON)
    if not _all_segments_safe(inner, _safe_main_tokens()):
        return Decision(False, FALLTHROUGH_DENY_REASON)
    return Decision(True)


# Read denylist — mirrors run-settings.json `permissions.deny` (creds, ssh,
# ground truth, the held-out manifest). Matched on any path component / suffix.
_READ_DENY_SUBSTR = (".env", "credentials", "ground_truth", "ground-truth", "cases.json")
_READ_DENY_DIR = ".ssh"


def decide_read(path: Path, *, is_main_session: bool, is_finder: bool = False) -> Decision:
    """Allow/deny a file read, porting the Read deny rules + the gather_raw clamp
    (`block_main_loop_raw_access` on Read). The clamp applies to the main loop AND
    the finder (`is_finder`): both consume the summary, never the raw payload. Only
    the executor (is_main_session=False, is_finder=False) reads gather_raw, to
    jq-summarize its own payload."""
    p = Path(path)
    name = p.name
    parts = set(p.parts)
    if _READ_DENY_DIR in parts or any(s in name for s in _READ_DENY_SUBSTR):
        return Decision(False, f"Blocked: {name} is a denied read (secrets / ground truth).")
    # No gather-payload-tool exemption here: that exemption is about a Bash
    # *command* invoking record-query/data-source-debug (which legitimately name
    # gather_raw paths). block_main_loop_raw_access never applies it to a Read
    # (its `cmd` is "" for non-Bash), so a main-loop / finder read of any gather_raw
    # path is unconditionally clamped.
    if RAW_MARKER in str(p):
        if is_main_session:
            return Decision(False, RAW_DENY_REASON)
        if is_finder:
            return Decision(False, FINDER_RAW_REASON)
    return Decision(True)


def is_untrusted_read(path: Path) -> bool:
    """True for reads of attacker-influenced data that must be tag-wrapped:
    the alert payload and (slice 2) raw gather payloads."""
    p = Path(path)
    return p.name == "alert.json" or RAW_MARKER in str(p)


def decide_write(path: Path, proposed_text: str, *, run_dir: Path) -> Decision:
    """Allow/deny a write of `proposed_text` to `path`, porting the
    `Write(/tmp/defender-runs/**)` path allow + `invlang_validate`.

    For `investigation.md`, run the structural invlang validator against the
    full proposed text (current on-disk text supplies the append-only baseline);
    any error denies with the validator's messages so the model can fix its
    invlang — the in-process equivalent of the hook's exit-2 feedback.
    """
    path = Path(path)
    run_dir = Path(run_dir).resolve()
    try:
        path.resolve().relative_to(run_dir)
    except ValueError:
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
