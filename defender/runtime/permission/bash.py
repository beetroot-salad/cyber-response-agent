"""The Bash gate: allow/deny a command for a given agent role.

**Structured around the no-shell executor (#379).** The read-only Bash lane runs
`shell=False` (`runtime/bash_exec.py`), so the gate does not parse a shell string
and predict what bash will do — it validates the SAME `Pipeline` decomposition the
executor runs (`bash_exec.parse`). What the gate approves is exactly what executes;
there is no validator/executor parser differential to bypass.

**The decision is a per-agent regex allowlist over the TOKENIZED argv.** Each
agent's policy carries `bash_allow` — anchored `re.Pattern`s matched per stage
against `" ".join(argv)` (the de-quoted, expansion-free tokens from
`command_shape.flat_stages`). A non-adapter command is allowed iff EVERY stage
matches some pattern. Matching the parsed argv (not the raw string) is what makes
this safe: a raw-string pattern would have to encode bash's quoting/expansion
grammar (`jq "$(cmd)"` matches `^jq "[^"]*"$` yet expands under a shell), whereas
the tokens are already normalized and `shell=False` keeps the args inert. Since #535
the main/gather patterns also ANCHOR their operands: a viewer's file/dir operand must
textually sit under `{run_dir}` or a tight corpus `.md`, and a `..` segment is rejected
literally (built by `policies._common.reader_patterns_for` from the run's roots — the bash
lane does no `resolve()`, so the symlink residual is closed by the no-symlink-writer
invariant, not the regex). The judge keeps the complementary `resolve()`-based
file-operand gate (`operand_gated` → `_operand_reads_within_roots`) because its
`cat` legitimately opens files OUTSIDE its own run dir: `gather_raw` reaches it only
as a `read_root`, which the textual anchors are blind to.

  - main / gather — the read-only viewers + non-adapter `defender-*` shims
    (`policies/main.py`, `policies/gather.py`); gather additionally routes a
    data-source adapter run either standalone (captured transparently) or as the
    sanctioned `adapter --raw | defender-sql '<SQL>'` pipe.
  - judge / actor — build their own `bash_allow` in their pipeline modules (the
    judge's operand-gated `cat` piped into the sandboxed `defender-sql`, plus the
    pinned closed-ticket read; the actor's pinned lesson scripts).

**The command is parsed exactly once (#456).** `decide_bash` unwraps + parses, then
returns a `BashDecision` carrying that parse: the verdict, the `Pipeline` list (for
the executor's `run_parsed`), and the adapter/pipe routing the dispatcher consumes —
so neither dispatch nor execution re-decomposes the string. The
adapter/non-adapter classification lives in `command_shape` (shared with dispatch),
the main-loop raw/adapter deny *reasons* in `hooks/block_main_loop_raw_access.py`."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from defender.hooks._cmd_segments import unwrap
from defender.hooks.block_main_loop_raw_access import (
    ADAPTER_DENY_REASON,
    RAW_DENY_REASON,
    RAW_MARKER,
)
from defender.runtime import bash_exec

from . import command_shape
from .decision import Decision
from .files import read_allowed_path
from .policy import AgentPolicy

# The main / gather fall-through deny reasons live with their policies now
# (`policies/main.py`, `policies/gather.py`); the gate reads `policy.deny_reason`.

# Gather may run a data-source adapter directly — it's captured transparently —
# but only solo, or as the sanctioned `adapter --raw | defender-sql '<SQL>'`
# aggregation pipe. Any other pipeline/compound makes "the payload" ambiguous.
ADAPTER_STANDALONE_REASON = (
    "Blocked: run the data-source adapter as a standalone command (it is captured "
    "automatically — no wrapper needed), then filter the persisted payload file "
    "with jq/grep/Read. The only adapter pipe allowed is "
    "`defender-<system> … --raw | defender-sql '<SQL>'`. Don't otherwise pipe or "
    "chain the adapter call."
)

# The gather-payload capture wrapper legitimately names `gather_raw` paths on the
# command line (record-query writes one) — exempt it from the raw clamp. Mirrors
# block_main_loop_raw_access.main's exemption.
_GATHER_PAYLOAD_TOKENS = (
    "record_query", "defender-record-query",
)

# A leading `VAR=value` env-assignment prefix (the credential-groping vector) —
# matched against the first token of a stage only.
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

# `cat`'s complete short-option set (coreutils). EVERY one is boolean — `cat` has no
# arg-taking flag at all, and no long option is admitted by the operand-gated stage
# grammars. That is the whole reason `cat` is the judge's file-opening program: "which
# files does this argv open?" is answerable without reimplementing an option parser
# (jq's `-f`/`-L`/`--slurpfile`/`--rawfile`/`--argfile` + short-bundle arg consumption
# needed ~60 lines and three fail-closed branches to answer the same question).
_CAT_BOOL_BUNDLE = re.compile(r"-[AbeEnstTuv]+")


@dataclass(frozen=True)
class BashDecision(Decision):
    """A Bash verdict that carries the gate's single parse, so dispatch and
    execution don't re-decompose the command (#456):

      - `pipelines` — the parsed `Pipeline` list, handed to `bash_exec.run_parsed`
        (None on a deny; empty tuple for an empty command).
      - `adapter_argv` — the standalone-adapter argv to capture (gather only).
      - `sql_pipe` — the `(adapter_argv, sql_argv)` split for the sanctioned
        `adapter --raw | defender-sql` pipe (gather only).

    `adapter_argv`/`sql_pipe` are mutually exclusive and set only when the verdict
    is allow; both None means the command runs through the plain executor."""

    pipelines: tuple[bash_exec.Pipeline, ...] | None = None
    adapter_argv: list[str] | None = None
    sql_pipe: tuple[list[str], list[str]] | None = None


def _names_a_gather_payload_tool(cmd: str) -> bool:
    return any(tok in cmd for tok in _GATHER_PAYLOAD_TOKENS)


def _stage_unsafe(argv: list[str]) -> bool:
    """A stage carrying a construct we refuse to auto-approve even though the
    no-shell executor renders it inert: a subshell / command substitution
    (`(`/`)`/`$(`/backtick), an `export`, or a leading `VAR=` assignment. With
    shell=False these expand to literal bytes (no security risk), but we keep the
    deny as cheap defense-in-depth — the last line if `shell=True` is ever
    reintroduced anywhere downstream — and so the agent gets a clear deny rather
    than a confusing literal-`$(...)`-as-filename error."""
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


def _parse(cmd: str) -> list[bash_exec.Pipeline] | None:
    """Unwrap + parse `cmd` (already stripped) once into the `Pipeline` list, or
    None to fail closed — when `unwrap` rejects the wrapper, or the executor's
    decomposition raises on an operator/redirect it does not model (the shared
    `bash_exec.parse`, the whole point of #379: gate and executor decompose
    identically). This is the single decomposition every branch below routes off."""
    inner = unwrap(cmd)
    if inner is None:
        return None
    try:
        return bash_exec.parse(inner)
    except bash_exec.BashExecError:
        return None


def require_anchor_root(what: str, p: Path) -> None:
    """The ONE per-run anchor-root guard for `bind` / `compile_policy_for` (agent_definition),
    so the security check never drifts between call sites. `p` must be ABSOLUTE, not the
    filesystem root, `..`-free, and whitespace-free; `what` names the offending input in the error.

    The anchored reader allowlist is baked from `root.resolve()`, so an empty (`Path('')`→`.`) or
    `/` root would anchor the pattern to the cwd / the whole filesystem (= read anything). A
    `..`-laden root (`/x/../..`, parts len 4) passes a raw parts count yet resolves to `/` — the
    same hazard, so it is rejected too. A root containing whitespace cannot be represented either:
    the shape matcher maps a token's own spaces to `_TOKEN_SPACE`, but the anchor embeds
    `re.escape(root)` with a literal space, so the two never align and EVERY in-root read would
    silently deny. Fail LOUD in every case rather than mint an unconfined — or silently-bricked —
    policy."""
    p = Path(p)
    if not p.is_absolute() or len(p.parts) < 2 or ".." in p.parts:
        raise ValueError(
            f"{what} must be an absolute non-root path with no '..' segment, got {p!r} — a "
            "relative, filesystem-root, or ..-collapsing anchor would open reads to the CWD / "
            "whole filesystem."
        )
    if any(ch.isspace() for ch in str(p)):
        raise ValueError(
            f"{what} must not contain whitespace (the textual bash reader anchor cannot "
            f"represent it), got {p!r}"
        )


def _allow(
    pipelines: list[bash_exec.Pipeline],
    *,
    adapter_argv: list[str] | None = None,
    sql_pipe: tuple[list[str], list[str]] | None = None,
) -> BashDecision:
    return BashDecision(
        True, pipelines=tuple(pipelines), adapter_argv=adapter_argv, sql_pipe=sql_pipe,
    )


def _decide_adapter(pipelines: list[bash_exec.Pipeline], policy: AgentPolicy) -> BashDecision:
    """Classify a command that contains a data-source adapter. Denied unless the agent
    may run adapters; when allowed, a standalone call is captured transparently and the
    only sanctioned multi-stage shape is `adapter --raw | defender-sql '<SQL>'` (gated on
    `adapter_sql_pipe`). Any other adapter compound is ambiguous. The adapter/sql payloads
    are NOT run through the substitution guard (they go straight to subprocess shell=False)."""
    if not policy.adapters:
        return BashDecision(False, ADAPTER_DENY_REASON)
    standalone = command_shape.standalone_adapter_argv(pipelines)
    if standalone is not None:
        return _allow(pipelines, adapter_argv=standalone)
    if policy.adapter_sql_pipe:
        split = command_shape.adapter_sql_split(pipelines)
        if split is not None:
            return _allow(pipelines, sql_pipe=split)
    return BashDecision(False, ADAPTER_STANDALONE_REASON)


def _cat_input_files(argv: list[str]) -> list[str] | None:
    """Every file path a `cat` invocation (`argv[0] == 'cat'`) will OPEN. `cat` has no
    arg-taking flag (`_CAT_BOOL_BUNDLE`), so every non-flag token is an input operand —
    no option parser needed. Returns `[]` for an inert stdin-only `cat` in a downstream
    pipe stage (nothing to gate), or `None` to FAIL CLOSED on any `-`-prefixed token
    that is not a known boolean bundle: the operand-gated stage grammar admits only
    those, so anything else means grammar and gate disagree, and a disagreement is the
    bug class this whole gate exists to prevent. A bare `-` is stdin; `--` ends options
    (every later token is an operand, even one starting with `-`)."""
    files: list[str] = []
    opts_done = False
    for t in argv[1:]:
        if opts_done or t == "-" or not t.startswith("-"):
            if t != "-":
                files.append(t)
        elif t == "--":
            opts_done = True
        elif not _CAT_BOOL_BUNDLE.fullmatch(t):
            return None
    return files


# The operand-gated programs: program name -> the extractor naming every file that
# program's argv OPENS. Keyed by PROGRAM (not applied to every stage) so a compute
# stage is never mistaken for a reader: `defender-sql 'SELECT …'` opens no file, and
# its SQL text is not a path — it is argument-inert because DuckDB is sealed
# (`enable_external_access=false` + `lock_configuration=true`, one-way) BEFORE the
# caller's SQL runs, so the sandbox bounds it rather than this gate. A stage whose
# program is absent here is shape-checked by `bash_allow` and nothing more.
_OPERAND_GATED_PROGRAMS: dict[str, Callable[[list[str]], list[str] | None]] = {
    "cat": _cat_input_files,
}


def _operand_reads_within_roots(
    argv: list[str], extract: Callable[[list[str]], list[str] | None],
    policy: AgentPolicy, *, run_dir: Path | None, defender_dir: Path | None,
) -> bool:
    """Whether every file an operand-gated stage opens resolves within `policy`'s read
    roots. Calls the SAME `read_allowed_path` routine `decide_read` uses, so the bash
    lane and the Read tool confine to one roots set through one mechanism — including
    `read_roots` (which the textual anchors cannot see) and the secret/ground-truth
    denylist. A stage with no file operands passes; an unparseable shape fails closed."""
    files = extract(argv)
    if files is None:
        return False
    return all(
        read_allowed_path(f, run_dir=run_dir, defender_dir=defender_dir, policy=policy)
        for f in files
    )


# Sentinel replacing a token's OWN spaces before the argv is joined for shape
# matching. A plain `" ".join(argv)` is many-to-one: a quoted token carrying a space
# (`"a b"`) is indistinguishable from two tokens (`a b`), so a pattern that asserts
# an inner token (the judge's `--require-closed` lookahead) or the program name could
# be spoofed by smuggling that text inside a NEIGHBOURING quoted argument — which
# argparse/exec then binds as a value, not the token the gate matched (the gate would
# approve a shape the executed argv does not have). Mapping each token's own spaces to
# a byte that cannot occur in a shell token keeps every space in the joined string a
# TRUE token boundary, so the regex reasons over the same boundaries execution has.
# `.`/`[^ ]` in the patterns still match the sentinel, so an approved shape's trailing
# `(?: .*)?` is unaffected.
_TOKEN_SPACE = "\x00"


def _stage_shape_ok(argv: list[str], policy: AgentPolicy) -> bool:
    """Whether a stage matches one of the policy's `bash_allow` patterns. Matched with
    `fullmatch` against the tokens joined on a real space, each token's own spaces
    mapped to `_TOKEN_SPACE` so a space in the joined string is ALWAYS a true token
    boundary (see `_TOKEN_SPACE`) — the WHOLE stage must be an approved shape (not
    merely a prefix), and an inner-token / program assertion can't be spoofed by a
    space-carrying quoted argument."""
    joined = " ".join(t.replace(" ", _TOKEN_SPACE) for t in argv)
    return any(p.fullmatch(joined) for p in policy.bash_allow)


def _decide_readers(
    pipelines: list[bash_exec.Pipeline], policy: AgentPolicy,
    *, run_dir: Path | None, defender_dir: Path | None,
) -> BashDecision | None:
    """The non-adapter reader lane, driven by `policy.bash_allow`. Returns:

      - `None` when the command is NOT a reader command (some stage matches no
        `bash_allow` pattern) — the caller then tries adapter classification;
      - an ALLOW when every stage matches an approved shape (and, when
        `operand_gated`, every operand-gated stage's file operands resolve in-roots);
      - a DENY when a shape-approved command carries an unsafe construct
        (`$(...)`/backtick/`export`/`VAR=`) or an operand escapes the read roots.

    Requiring EVERY stage to match the (narrow, per-agent) allowlist is what makes a
    pipe safe without a single-stage restriction: the judge's `cat … | defender-sql …`
    is fine, but a downstream `head` matches no judge pattern and is denied here."""
    stages = command_shape.flat_stages(pipelines)
    if not stages or not all(_stage_shape_ok(s, policy) for s in stages):
        return None  # not a reader command → let the caller try adapter routing
    if any(_stage_unsafe(s) for s in stages):
        return BashDecision(False, policy.deny_reason)
    if policy.operand_gated:
        for s in stages:
            extract = _OPERAND_GATED_PROGRAMS.get(s[0])
            if extract is not None and not _operand_reads_within_roots(
                s, extract, policy, run_dir=run_dir, defender_dir=defender_dir
            ):
                return BashDecision(False, policy.deny_reason)
    return _allow(pipelines)


def decide_bash(
    command: str, *, policy: AgentPolicy,
    run_dir: Path | None = None, defender_dir: Path | None = None,
) -> BashDecision:
    """Allow/deny a Bash command for an agent, driven entirely by its `AgentPolicy`
    (no per-role method): the raw-read clamp, then the per-agent `bash_allow` regex
    reader lane, then structural adapter routing.

    `run_dir`/`defender_dir` supply the read roots the judge's `cat` file-operand
    path-gate validates against; they are irrelevant to a policy with
    `operand_gated=False` (main/gather/actor), so those callers may omit them.

    Returns a `BashDecision` carrying the single parse (see the class): callers read
    `.allow`/`.reason` as before, and route capture/execution off
    `.adapter_argv`/`.sql_pipe`/`.pipelines` without re-parsing (#456).
    """
    cmd = command.strip()
    if not cmd:
        return BashDecision(True)

    # Raw-read clamp (a security invariant, first): a command naming a gather_raw/
    # path is denied unless the agent may read raw. The gather-payload-tool exemption
    # keeps the main loop's `defender-record-query … <gather_raw path>` wrapper
    # allowed (it legitimately names a raw path); an agent with raw_reads (gather,
    # judge) skips the clamp entirely.
    if (
        RAW_MARKER in cmd
        and not policy.raw_reads
        and not _names_a_gather_payload_tool(cmd)
    ):
        return BashDecision(False, RAW_DENY_REASON)

    pipelines = _parse(cmd)
    if pipelines is None:
        return BashDecision(False, policy.deny_reason)

    # Reader lane FIRST: the per-agent `bash_allow` allowlist claims any command whose
    # every stage matches an approved shape — including the judge's pinned `python3
    # <ticket_cli>` read and the actor's pinned scripts, adapter-SHAPED commands that
    # must win over adapter classification (the job the old custom matchers did). A
    # shape-approved command that fails the jq operand path-gate / carries an unsafe
    # construct denies HERE rather than falling through.
    reader = _decide_readers(pipelines, policy, run_dir=run_dir, defender_dir=defender_dir)
    if reader is not None:
        return reader

    # Not a reader command: a data-source adapter routes structurally (capture / the
    # sanctioned adapter|defender-sql pipe / the adapter deny reasons).
    if command_shape.has_adapter(pipelines):
        return _decide_adapter(pipelines, policy)

    return BashDecision(False, policy.deny_reason)
