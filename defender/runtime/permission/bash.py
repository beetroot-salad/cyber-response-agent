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
invariant, not the regex). The judge keeps the complementary `resolve()`-based `jq`
file-operand gate (`jq_operand_gated` → `_jq_reads_within_roots`) because its `jq`
legitimately opens files; main/gather `jq` is stdin-compute-only.

  - main / gather — the read-only viewers + non-adapter `defender-*` shims
    (`policies/main.py`, `policies/gather.py`); gather additionally routes a
    data-source adapter run either standalone (captured transparently) or as the
    sanctioned `adapter --raw | defender-sql '<SQL>'` pipe.
  - judge / actor — build their own `bash_allow` in their pipeline modules (the
    judge's path-gated `jq` + pinned closed-ticket read; the actor's pinned
    lesson scripts).

**The command is parsed exactly once (#456).** `decide_bash` unwraps + parses, then
returns a `BashDecision` carrying that parse: the verdict, the `Pipeline` list (for
the executor's `run_parsed`), and the adapter/pipe routing the dispatcher consumes —
so neither dispatch nor execution re-decomposes the string. The
adapter/non-adapter classification lives in `command_shape` (shared with dispatch),
the main-loop raw/adapter deny *reasons* in `hooks/block_main_loop_raw_access.py`."""

from __future__ import annotations

import re
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

# jq option grammar for the file-arg path-gate (the judge's `jq_operand_gated`
# lane). jq OPENS a file for: its positional input operands (after the filter
# program) and the argument-taking flags below. The gate validates EVERY such path
# against the policy's read roots — closing the flag-injection escape where a
# `--slurpfile <out-of-roots>` loads a file while the trailing operand looks clean.
#
# Each entry: flag -> (tokens consumed INCLUDING the flag, index of the FILE arg
# within that span or None, supplies-the-filter). `-f`/`--from-file` load the filter
# program FROM a file, so their arg is both a gated file AND fills the filter slot
# (the next bare positional is then an input, not the filter).
_JQ_ARG_FLAGS: dict[str, tuple[int, int | None, bool]] = {
    "-f": (2, 1, True), "--from-file": (2, 1, True),
    "--slurpfile": (3, 2, False), "--rawfile": (3, 2, False), "--argfile": (3, 2, False),
    "--arg": (3, None, False), "--argjson": (3, None, False),       # <name> <value>
    "--indent": (2, None, False),
    # `-L`/`--library-path <dir>` is DELIBERATELY absent → it fails closed (below).
    # It adds a jq MODULE search dir, and an `include`/`import` in the filter then
    # opens `<dir>/<mod>.jq` — files the operand gate can't enumerate (they come from
    # the filter body, not the argv), so gating the dir alone would miss them and a
    # compile error echoes a module file's source line to stderr (an out-of-roots
    # read oracle). The judge has no legitimate use for jq module paths, so any `-L`
    # (standalone or bundled/attached) is denied rather than decoded ungated.
}
_JQ_ARGS_MODES = frozenset({"--args", "--jsonargs"})  # trailing positionals become strings, not files
# The arg-taking SHORT flags (`-f`/`-L`). jq bundles short options AND lets a
# bundle's trailing arg-taking flag consume the next token (`jq -nf FILE` opens
# FILE as the `-f` filter program) or an attached value (`-L<dir>`). `-f` is decoded
# as a STANDALONE token (in `_JQ_ARG_FLAGS`); `-L` is decoded NOWHERE (it opens files
# the gate can't enumerate — see above). Either appearing in a bundle/attached form,
# and `-L` in ANY form, desyncs the positional count or hides an ungated read, so the
# gate FAILS CLOSED on it instead (see `_jq_flag_step`).
_JQ_SHORT_ARG_FLAGS = frozenset("fL")


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
    """The ONE per-run anchor-root guard, shared by `bind` (agent_definition) and `policy_for`
    (this module) so the security check never drifts between them. `p` must be ABSOLUTE, not the
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


def _require_read_root(name: str, p: Path) -> None:
    """`policy_for`'s per-run root guard: delegates to the shared `require_anchor_root` (the ONE
    root-anchor validator — see there for the absolute/`..`/whitespace rationale) with the
    `policy_for {name!r}` framing, so `policy_for` can't mint an unconfined or silently-bricked
    policy and a future hardening lands in one place."""
    require_anchor_root(f"policy_for {name!r} root", p)


def policy_for(agent: str, *, run_dir: Path, defender_dir: Path) -> AgentPolicy:
    """Build the PER-RUN `AgentPolicy` for a runtime agent ('main' | 'gather') — a thin
    dispatcher to that agent's own policy file (`policies/main.py`,
    `policies/gather.py`), each of which bakes the anchored reader allowlist from
    `run_dir` + `defender_dir` (#535) plus its capability bits and deny reason.

    Both roots are REQUIRED and validated (`_require_read_root`): a runtime-agent
    policy can no longer be minted in the legacy unconfined state — there is no
    module-level MAIN/GATHER default and no silent `^cat .*$` fallback, so a missing
    or degenerate root is a construction-time error, not a `cat /etc/passwd` bypass.
    Learning-loop agents (judge, actor) build their own `AgentPolicy` in their
    pipeline modules rather than going through this runtime-agent factory."""
    _require_read_root("run_dir", run_dir)
    _require_read_root("defender_dir", defender_dir)
    from .policies import gather as _gather, main as _main

    if agent == "main":
        return _main.main_policy(run_dir, defender_dir)
    if agent == "gather":
        return _gather.gather_policy(run_dir, defender_dir)
    raise ValueError(f"no runtime Bash policy for agent {agent!r}")


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


def _jq_flag_step(argv: list[str], i: int) -> tuple[int, list[str], bool] | None:
    """Handle one jq OPTION token at `argv[i]` (a token starting with `-`, never a
    bare `-`). Returns `(next_i, files_loaded, supplies_filter)`, or `None` to FAIL
    CLOSED (a malformed arg-taking flag, or an unrecognized long option that might
    smuggle a file). A short boolean flag / bundle (`-s`, `-nr`, `-c`, …) opens no
    file and consumes only itself."""
    t = argv[i]
    spec = _JQ_ARG_FLAGS.get(t)
    if spec is not None:
        consume, file_off, supplies_filter = spec
        if i + consume > len(argv):
            return None  # arg-taking flag with its argument(s) missing
        loaded = [argv[i + file_off]] if file_off is not None else []
        return i + consume, loaded, supplies_filter
    if t.startswith("--"):
        return None  # unrecognized long option — fail closed (may take a file)
    if any(c in _JQ_SHORT_ARG_FLAGS for c in t[1:]):
        return None  # short bundle carrying an arg-taking flag (`-nf FILE`, `-L<dir>`)
    return i + 1, [], False  # boolean short flag / bundle


def _jq_input_files(argv: list[str]) -> list[str] | None:
    """Every file path a `jq` invocation (`argv[0] == 'jq'`) will OPEN — its
    positional input operands plus the `--slurpfile`/`--rawfile`/`--argfile`/`-f`
    file targets. Returns `[]` for an inert stdin-only `jq '.'` (nothing to gate), or
    `None` when the argv uses a shape we won't reason about (FAIL CLOSED). `-`
    operands (stdin) are skipped; after `--args`/`--jsonargs` the trailing positionals
    are string args, not files."""
    files: list[str] = []
    filter_seen = False
    i, n = 1, len(argv)
    while i < n:
        t = argv[i]
        if t in _JQ_ARGS_MODES:
            break  # `--args`/`--jsonargs`: every remaining positional is a string arg, never a file
        if t.startswith("-") and t != "-":
            step = _jq_flag_step(argv, i)
            if step is None:
                return None
            i, loaded, supplies_filter = step
            files.extend(loaded)
            filter_seen = filter_seen or supplies_filter
        elif not filter_seen:
            filter_seen = True  # the first bare positional is the filter program
            i += 1
        else:
            if t != "-":
                files.append(t)  # a subsequent bare positional is an input file
            i += 1
    return files


def _jq_reads_within_roots(
    argv: list[str], policy: AgentPolicy, *, run_dir: Path | None, defender_dir: Path | None
) -> bool:
    """Whether every file a `jq` stage opens resolves within `policy`'s read roots.
    An inert stdin `jq '.'` (no file operands) passes; an unparseable jq shape fails
    closed."""
    files = _jq_input_files(argv)
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
        `jq_operand_gated`, every `jq` stage's file operands resolve in-roots);
      - a DENY when a shape-approved command carries an unsafe construct
        (`$(...)`/backtick/`export`/`VAR=`) or a `jq` operand escapes the read roots.

    Requiring EVERY stage to match the (narrow, per-agent) allowlist is what makes a
    pipe safe without a single-stage restriction: the judge's `jq … | jq …` is fine,
    but a downstream `cat`/`head` matches no judge pattern and is denied here."""
    stages = command_shape.flat_stages(pipelines)
    if not stages or not all(_stage_shape_ok(s, policy) for s in stages):
        return None  # not a reader command → let the caller try adapter routing
    if any(_stage_unsafe(s) for s in stages):
        return BashDecision(False, policy.deny_reason)
    if policy.jq_operand_gated:
        for s in stages:
            if s[0] == "jq" and not _jq_reads_within_roots(
                s, policy, run_dir=run_dir, defender_dir=defender_dir
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

    `run_dir`/`defender_dir` supply the read roots the judge's `jq` file-arg
    path-gate validates against; they are irrelevant to a policy with
    `jq_operand_gated=False` (main/gather/actor), so those callers may omit them.

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
