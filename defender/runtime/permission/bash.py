"""The Bash gate: allow/deny a command for a given agent role.

**Structured around the no-shell executor (#379).** The read-only Bash lane runs
`shell=False` (`runtime/bash_exec.py`), so the gate does not parse a shell string and predict
what bash will do — it validates the SAME `Pipeline` decomposition the executor runs
(`bash_exec.parse`). What the gate approves is exactly what executes; there is no
validator/executor parser differential to bypass.

**The decision is a per-agent list of `Grant`s over the TOKENIZED argv (#575).** A stage is
claimed by a grant when it `fullmatch`es that grant's SHAPE — program + flags + arity, and no
path anywhere in it. Everything the stage then OPENS (per `PROGRAMS[grant.program]`, the one
global table of what each program opens) is `resolve()`d and must land in that grant's SCOPE,
an anchored regex over the RESOLVED path. A non-adapter command is allowed iff EVERY stage is
claimed and every operand it opens is in scope.

Matching the parsed argv rather than the raw string is what makes the shape half safe (a
raw-string pattern would have to encode bash's quoting/expansion grammar: `jq "$(cmd)"`
matches `^jq "[^"]*"$` yet expands under a shell). Resolving the operand is what makes the
scope half safe: the old lane baked the roots textually INTO the argv regex, so a symlink out
of the run dir was closed only by a side invariant (no sanctioned writer creates one) rather
than by a check. Now it collapses at `resolve()` and lands outside every scope.

Two consequences worth naming, because they REPLACE mechanisms rather than adding one:

  - **there is no raw clamp.** `gather_raw` is denied to the main loop because that shape is
    not in main's grant list — positive enumeration, not a `RAW_MARKER in cmd` substring scan
    over the unparsed command string (which denied `… | grep gather_raw`, where `gather_raw`
    is a search PATTERN and no such path is ever opened);
  - **there is no adapter route.** Since #611 a data source is reached through the typed `query`
    tool, so no grant on any lane carries an adapter route and no bash command captures a
    payload. The structural adapter CLASSIFICATION survives (`command_shape`, shared with
    dispatch) for exactly one purpose: an adapter-shaped command earns a deny that names the
    tool that DOES work, instead of the generic fall-through.

**The command is parsed exactly once (#456).** `decide_bash` unwraps + parses, then returns a
`BashDecision` carrying that parse: the verdict, the `Pipeline` list (for the executor's
`run_parsed`), and the grants that claimed it (for `defender-policy explain`) — so neither
dispatch nor execution re-decomposes the string."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from defender.hooks._cmd_segments import unwrap
from defender.runtime import bash_exec

from . import command_shape
from .decision import Decision
from .files import RESOLVE_ERRORS, denylisted
from .grant import OPENS_NOTHING, PROGRAMS, Grant, Route
from .policy import AgentPolicy

# The main / gather fall-through deny reasons live with their policies
# (`policies/main.py`, `policies/gather.py`); the gate reads `policy.deny_reason`.

# There is no adapter route on ANY bash lane since #611 — a data source is reached through the
# typed `query` tool. This reason is what an adapter-SHAPED command gets, and it must point at
# the route that exists rather than the one that does not: a reason naming a dead command teaches
# a dead command, which this codebase treats as an enforced invariant (the deny reasons are
# checked against the live grant list) and not a cosmetic string.
ADAPTER_RETIRED_REASON = (
    "Blocked: data-source adapters are not runnable from bash. Reach the system through the "
    "`query` tool instead — `query(system=…, verb=…, params={…}, query_id=…)`; it validates the "
    "verb's params against the registry, captures the payload to the queries table, and hands "
    "you the path. To aggregate that payload afterwards: "
    "`cat <ABSOLUTE payload path> | defender-sql '<SQL>'`."
)

# A leading `VAR=value` env-assignment prefix (the credential-groping vector) — matched
# against the first token of a stage only.
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


@dataclass(frozen=True)
class BashDecision(Decision):
    """A Bash verdict that carries the gate's single parse, so dispatch and execution don't
    re-decompose the command (#456):

      - `pipelines` — the parsed `Pipeline` list, handed to `bash_exec.run_parsed` (None on a
        deny; empty tuple for an empty command).
      - `grants` — the `Grant` that claimed each stage (the adapter grant, for a structurally
        routed adapter). `defender-policy explain` reports it, which is what makes the audit
        CLI a second CONSUMER of the gate rather than a second implementation of it.

    Since #611 there are no routing fields: the adapter route the capture layer read
    (`adapter_argv` / `sql_pipe`) is gone with the capture-from-bash path itself, so an allowed
    command always runs through the plain executor."""

    pipelines: tuple[bash_exec.Pipeline, ...] | None = None
    grants: tuple[Grant, ...] = ()


def _stage_unsafe(argv: list[str]) -> bool:
    """A stage carrying a construct we refuse to auto-approve even though the no-shell executor
    renders it inert: a subshell / command substitution (`(`/`)`/`$(`/backtick), an `export`,
    or a leading `VAR=` assignment. With shell=False these expand to literal bytes (no security
    risk), but we keep the deny as cheap defense-in-depth — the last line if `shell=True` is
    ever reintroduced anywhere downstream — and so the agent gets a clear deny rather than a
    confusing literal-`$(...)`-as-filename error."""
    for i, t in enumerate(argv):
        if t in ("(", ")"):
            return True
        if "$(" in t or "`" in t:
            return True
        if t == "export":
            return True
        if i == 0 and _ENV_ASSIGN_RE.match(t):
            return True
    return False


# The deny for a command that does not LEX. Every other deny means "your command is not a shape
# you may run"; this one means "your command may well be fine, but its line breaks are not" —
# and the agent cannot tell those apart from the generic reason. It is worth its own text
# because the failure is invisible in the command as written: the SQL and ES|QL the agents are
# shown are rendered multi-line, and flattening is on them.
UNTOKENIZABLE_REASON = (
    "Blocked: the command could not be tokenized — an unbalanced quote or a trailing "
    "`\\`. Each PHYSICAL LINE is lexed on its own (there is no shell to join them), so "
    "a `\\` line-continuation and a newline inside a quoted argument both fail here, "
    "even when the command is otherwise allowed. Rewrite it as a SINGLE line."
)


def _parse(cmd: str) -> list[bash_exec.Pipeline] | None:
    """Unwrap + parse `cmd` (already stripped) once into the `Pipeline` list, or None to fail
    closed — when `unwrap` rejects the wrapper, or the executor's decomposition raises on an
    operator/redirect it does not model (the shared `bash_exec.parse`, the whole point of #379:
    gate and executor decompose identically). This is the single decomposition every branch
    below routes off.

    `UntokenizableCommand` PROPAGATES rather than flattening to None: it is the one parse
    failure whose cause the caller can explain (`UNTOKENIZABLE_REASON`)."""
    inner = unwrap(cmd)
    if inner is None:
        return None
    try:
        return bash_exec.parse(inner)
    except bash_exec.UntokenizableCommand:
        raise
    except bash_exec.BashExecError:
        return None


def require_anchor_root(what: str, p: Path) -> None:
    """The ONE per-run anchor-root guard for `bind` / `compile_policy_for` (agent_definition),
    so the security check never drifts between call sites. `p` must be ABSOLUTE, not the
    filesystem root, `..`-free, and whitespace-free; `what` names the offending input in the
    error.

    A grant's scope is `re.escape(root.resolve())` + a tight tail, so an empty (`Path('')`→`.`)
    or `/` root would anchor the shape to the cwd / the whole filesystem (= read anything). A
    `..`-laden root (`/x/../..`, parts len 4) passes a raw parts count yet resolves to `/` — the
    same hazard, so it is rejected too. A root containing whitespace cannot be represented
    either: a scope shape's path segments admit no space (a gate-approved path must be a safe
    token downstream), so EVERY in-root read would silently deny. Fail LOUD in every case rather
    than mint an unconfined — or silently-bricked — policy."""
    p = Path(p)
    if not p.is_absolute() or len(p.parts) < 2 or ".." in p.parts:
        raise ValueError(
            f"{what} must be an absolute non-root path with no '..' segment, got {p!r} — a "
            "relative, filesystem-root, or ..-collapsing anchor would open reads to the CWD / "
            "whole filesystem."
        )
    if any(ch.isspace() for ch in str(p)):
        raise ValueError(
            f"{what} must not contain whitespace (a path shape's segments admit none), got {p!r}"
        )


def _allow(
    pipelines: list[bash_exec.Pipeline], *, grants: tuple[Grant, ...] = (),
) -> BashDecision:
    return BashDecision(True, pipelines=tuple(pipelines), grants=grants)


# Sentinel replacing a token's OWN spaces before the argv is joined for shape matching. A plain
# `" ".join(argv)` is many-to-one: a quoted token carrying a space (`"a b"`) is
# indistinguishable from two tokens (`a b`), so a shape that asserts an inner token (a pinned
# script's argv, an actor flag) or the program name could be spoofed by smuggling that text
# inside a NEIGHBOURING quoted argument — which argparse/exec then binds as a value, not the
# token the gate matched (the gate would approve a shape the executed argv does not have).
# Mapping each token's own spaces to a byte that cannot occur in a shell token keeps every space
# in the joined string a TRUE token boundary, so the regex reasons over the same boundaries
# execution has. `[^ ]` in the shapes still matches the sentinel, so a quoted SQL/jq filter
# (one token, spaces inside) still matches its free-text slot.
_TOKEN_SPACE = "\x00"


def _claim(argv: list[str], policy: AgentPolicy) -> Grant | None:
    """The `Route.PLAIN` grant whose SHAPE claims this stage, or None (→ the caller tries
    adapter routing). Matched with `fullmatch` against the tokens joined on a real space, each
    token's own spaces mapped to `_TOKEN_SPACE` (see above) — the WHOLE stage must be an
    approved shape, not merely a prefix.

    The two adapter grants are skipped: their route is classified structurally, and a reader
    lane that claimed an adapter command would strip it of its capture payload."""
    joined = " ".join(t.replace(" ", _TOKEN_SPACE) for t in argv)
    for g in policy.bash_allow:
        if g.route is Route.PLAIN and g.pattern.fullmatch(joined):
            return g
    return None


def _in_scope(argv: list[str], grant: Grant, *, run_dir: Path | None) -> bool:
    """Whether every file this stage OPENS resolves into the claiming grant's scope.

    The extractor is looked up by the matched GRANT's program, never by `argv[0]`: a grant
    naming an untabled program raised at policy construction (`AgentPolicy.__post_init__`), so
    there is no "unknown program → nothing to check" branch left to fail open through. An
    `OPENS_NOTHING` program opens nothing this gate must check and passes untouched — its SHAPE
    is then its sole containment, which is why every such shape is a positive flag allowlist.

    A RELATIVE operand is rebased onto `run_dir` — the cwd `tools._tool_bash` hands the executor
    — before it is resolved. Without that the gate would resolve against the ambient process cwd
    while the program opens the file from the executor's, so the two could name different files:
    the validator/executor differential this package exists to eliminate.

    `run_dir` is the anchor at all THREE coupled sites (#540): here, `tools._resolve_operand`,
    and the `cwd=` the executor runs under. It moved off `defender_dir.parent` — the repo root —
    because that directory holds `.env`, `.ssh/` and the sibling worktrees: a relative operand
    used to anchor one `..` away from every credential in the tree. It is also the only anchor
    that survives the box, whose rw bind IS `run_dir`.

    FAILS CLOSED on everything hostile: an argv the extractor cannot decide (`None`), a
    `resolve()` error (a symlink LOOP raises `RuntimeError`; an embedded NUL, `ValueError`), a
    denylisted secret/ground-truth file inside an otherwise in-scope path, or a resolved path no
    scope shape admits — where an ESCAPING symlink lands, because it resolves to where it
    POINTS, which is the whole reason containment resolves."""
    extract = PROGRAMS[grant.program]
    if extract is OPENS_NOTHING:
        return True
    files = extract(argv)
    if files is None:
        return False
    if run_dir is None:
        return False  # no cwd to rebase a relative operand against — fail closed
    cwd = run_dir
    for f in files:
        try:
            p = Path(f)
            rp = (p if p.is_absolute() else cwd / p).resolve()
        except RESOLVE_ERRORS:
            return False
        if denylisted(rp):
            return False
        if not any(shape.fullmatch(str(rp)) for shape in grant.scope):
            return False
    return True


def _decide_readers(
    pipelines: list[bash_exec.Pipeline], policy: AgentPolicy, *, run_dir: Path | None,
) -> BashDecision | None:
    """The non-adapter reader lane, driven by `policy.bash_allow`. Returns:

      - `None` when the command is NOT a reader command (some stage is claimed by no grant) —
        the caller then tries adapter classification;
      - an ALLOW when every stage is claimed AND every operand it opens is in that grant's
        scope;
      - a DENY when a claimed command carries an unsafe construct (`$(...)`/backtick/`export`/
        `VAR=`) or opens a path outside the claiming grant's scope.

    Requiring EVERY stage to be claimed is what makes a pipe safe without a single-stage
    restriction: the judge's `cat … | defender-sql …` is fine, but a downstream `head` matches
    no judge grant and is denied. Each stage is scope-checked against the grant that claimed
    IT, so `cat {run}/x.md | cat /etc/passwd` denies on the second stage."""
    stages = command_shape.flat_stages(pipelines)
    if not stages:
        return None
    claimed: list[Grant] = []
    for st in stages:
        g = _claim(st, policy)
        if g is None:
            return None  # not a reader command → let the caller try adapter routing
        claimed.append(g)
    if any(_stage_unsafe(s) for s in stages):
        return BashDecision(False, policy.deny_reason)
    pairs = zip(stages, claimed, strict=True)   # one grant per stage, by construction
    if not all(_in_scope(st, g, run_dir=run_dir) for st, g in pairs):
        return BashDecision(False, policy.deny_reason)
    return _allow(pipelines, grants=tuple(claimed))


def decide_bash(
    command: str, *, policy: AgentPolicy,
    run_dir: Path | None = None, defender_dir: Path | None = None,
    cwd_anchor: Path | None = None,
) -> BashDecision:
    """Allow/deny a Bash command for an agent, driven entirely by its `AgentPolicy` (no
    per-role method): the per-agent grant lane (shape ∧ scope), then structural adapter routing.

    `run_dir` supplies the executor's cwd, against which a RELATIVE file operand is rebased
    before it resolves; a policy whose grants open no file never consults it. It anchors here,
    in `tools._resolve_operand`, and in the `cwd=` the executor runs under — one directory at
    all three sites, or a relative operand names different files to the validator and the
    executor (#540). The run's roots still reach the gate baked into the grants' SCOPES,
    resolved at compile time (#575), so this rebase cannot widen what a policy admits: an
    operand that rebases out of scope still fails the scope check.

    `cwd_anchor` overrides that anchor for a role whose relative operands are NOT run-relative —
    the curators and the lead author address a throwaway worktree, and their `run_dir` is only a
    trace anchor. It defaults to `run_dir`, so the boxed runtime lane needs no extra argument and
    a caller that forgets it cannot silently widen anything: the anchor only decides which file a
    relative operand NAMES, and the resolved path still has to satisfy the grant's scope.

    `defender_dir` is accepted for call-shape uniformity with `decide_read`/`decide_write`; the
    bash lane no longer rebases on it.

    Returns a `BashDecision` carrying the single parse (see the class): callers read
    `.allow`/`.reason` as before, and execute off `.pipelines` without re-parsing (#456)."""
    cmd = command.strip()
    if not cmd:
        return BashDecision(True)

    try:
        pipelines = _parse(cmd)
    except bash_exec.UntokenizableCommand:
        # A lexing failure, not a policy one. Saying so is the difference between the model
        # re-emitting its command on one line and the model concluding the program is forbidden
        # and hunting for another (`policy.deny_reason` would say e.g. "gather may only run an
        # adapter standalone" for a standalone adapter call whose only sin was a line break
        # inside its quoted query).
        return BashDecision(False, UNTOKENIZABLE_REASON)
    if pipelines is None:
        return BashDecision(False, policy.deny_reason)

    # Reader lane FIRST: the per-agent grants claim any command whose every stage matches an
    # approved shape — including the actor's pinned scripts, adapter-SHAPED commands that must
    # win over adapter classification (the job the old custom matchers did). A claimed command
    # that fails the scope check / carries an unsafe construct denies HERE rather than falling
    # through.
    reader = _decide_readers(
        pipelines, policy, run_dir=cwd_anchor if cwd_anchor is not None else run_dir,
    )
    if reader is not None:
        return reader

    # Not a reader command. An adapter-SHAPED command still gets its OWN reason rather than the
    # generic fall-through: the model that typed it is trying to reach a data source, and the
    # cheapest possible correction is the name of the tool that does. The classification survives
    # (`command_shape`) precisely so the deny can say that; what died is the route behind it.
    if command_shape.has_adapter(pipelines):
        return BashDecision(False, ADAPTER_RETIRED_REASON)

    return BashDecision(False, policy.deny_reason)
