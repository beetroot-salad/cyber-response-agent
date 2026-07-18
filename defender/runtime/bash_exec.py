"""Shell=`False` executor for the read-only Bash lane.

The permission gate (`runtime/permission.py`) validates a command by decomposing
it with `shlex` and checking every segment head against a read-only allowlist.
Historically the *validated* command string was then handed straight back to
bash via `subprocess.run(cmd, shell=True)` — a second, more powerful parser.
Any divergence between shlex's view and bash's was a bypass: `$VAR` expansion
(`echo $SECRET`), globbing, `$(...)`/backtick substitution, fused redirect
operators (`>|`, `|&`). The gate became a string matcher playing whack-a-mole
against bash's grammar — exactly the trail the gate's own commit history shows.

This module closes that gap. It executes the *already-validated* token
structure directly as a `shell=False` process pipeline: what the gate validated
is exactly what runs. Bash never re-parses the string, so `$VAR`, `~`, globs,
`$(...)`, brace expansion, and process substitution simply do not happen. That
is a deliberate capability cut — the read-only viewers never needed shell
expansion — and it is the security win: an injected `echo $SECRET` now prints
the literal token `$SECRET`, not the secret.

The executor only honors the constructs the gate *approves*: a sequence of
pipelines joined by `&&`/`||`/`;`/newline, each pipeline a chain of
`|`-connected stages, each stage optionally carrying a benign stderr redirect
(`2>/dev/null` / `2>&1`). Every other redirect/operator is denied upstream, so
there is no general redirect engine here — an unexpected operator token means
the validator and this executor have diverged, and we fail closed.

Tokenization reuses the SAME `tokenize` the gate validates against
(`defender.hooks._cmd_segments`), so validator and executor share one lexer and
cannot disagree about word boundaries. Unwrapping a leading `timeout`/`bash -c`
happens in the gate (`permission/bash.py`), which then hands its parse here — so
this module never unwraps a raw string itself.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from defender.hooks._cmd_segments import tokenize

# Shell-operator characters. After splitting on the separators below, the only
# operator tokens a *validated* command can still carry are the two benign stderr
# redirects; anything else here is a divergence and fails closed.
_OPERATOR_CHARS = frozenset("<>|&;")
_PIPELINE_SEPARATORS = frozenset({"||", "&&", ";"})


class BashExecError(Exception):
    """The validated command carries a shape this executor does not model — i.e.
    the gate and the executor have diverged. Raised rather than silently mis-running."""


class UntokenizableCommand(BashExecError):
    """A physical line does not lex: an unbalanced quote or a dangling `\\` escape.

    Split out from its parent because it is the ONE parse failure with a cause worth
    explaining to the caller. `parse` lexes each physical line independently (an
    unquoted newline is a command separator, so splitting first is what stops a second
    command hiding behind one), which means it does not model bash's line-JOINING
    rules: a `\\`-continuation and a newline inside a quoted string both leave line 1
    unbalanced and land here. That is a deliberate capability cut — reimplementing
    line-joining is the validator/executor differential this module exists to close —
    so the gate turns this into a deny that says so, rather than the generic
    "not an approved shape" reason, which would send the model hunting for a different
    program when its command was fine and only its LINE BREAKS were not."""


@dataclass(frozen=True)
class Stage:
    """One command in a pipeline: its argv plus how its stderr is wired.
    `stderr` is "capture" (default), "devnull" (`2>/dev/null`), or "stdout"
    (`2>&1`, merge into this stage's stdout)."""

    argv: list[str]
    stderr: str = "capture"


@dataclass
class Pipeline:
    """A `|`-chain of stages, plus the connector relating it to the PREVIOUS
    pipeline: "first" | "&&" | "||" | ";" (newline is treated as ";").

    `Stage`/`Pipeline` are the public parsed representation `parse()` returns —
    the single decomposition the gate validates and the executor runs (#379), so
    a command is decomposed exactly once per tool call (#456)."""

    connector: str
    stages: list[Stage] = field(default_factory=list)


@dataclass
class _PipelineBuilder:
    """Accumulates the `Pipeline` structure token by token. Holds the in-progress
    stage/pipeline + the pending inter-pipeline connector — the nonlocal state the
    original `end_stage`/`end_pipeline` closures mutated, made explicit so the
    per-token dispatch stays under the complexity gate."""

    pipelines: list[Pipeline] = field(default_factory=list)
    pending_connector: str = "first"
    cur_stages: list[Stage] = field(default_factory=list)
    cur_argv: list[str] = field(default_factory=list)
    cur_stderr: str = "capture"

    def end_stage(self) -> None:
        if self.cur_argv:
            self.cur_stages.append(Stage(self.cur_argv, self.cur_stderr))
        self.cur_argv = []
        self.cur_stderr = "capture"

    def end_pipeline(self, next_connector: str) -> None:
        self.end_stage()
        if self.cur_stages:
            self.pipelines.append(Pipeline(self.pending_connector, self.cur_stages))
            self.cur_stages = []
            self.pending_connector = next_connector
        # If nothing flushed, KEEP pending_connector — preserves a line-trailing
        # `&&`/`||` whose right operand sits on the next physical line.

    def feed_token(self, toks: list[str], i: int) -> int:
        """Fold token `toks[i]` into the in-progress structure; return the next
        index. Raises `BashExecError` on any operator/redirect the gate wouldn't
        have approved (validator and executor diverged → fail closed)."""
        t, n = toks[i], len(toks)
        if t == "|":
            self.end_stage()
            return i + 1
        if t in _PIPELINE_SEPARATORS:
            self.end_pipeline(t)
            return i + 1
        if t == ">":
            # Benign stderr discard: `2>/dev/null`, tokenized `2` `>` `/dev/null`.
            if self.cur_argv and self.cur_argv[-1] == "2" and i + 1 < n and toks[i + 1] == "/dev/null":
                self.cur_argv.pop()
                self.cur_stderr = "devnull"
                return i + 2
            raise BashExecError(f"unexpected redirect token in validated command: {t!r}")
        if t == ">&":
            # Benign stderr merge: `2>&1`, tokenized `2` `>&` `1`.
            if self.cur_argv and self.cur_argv[-1] == "2" and i + 1 < n and toks[i + 1] == "1":
                self.cur_argv.pop()
                self.cur_stderr = "stdout"
                return i + 2
            raise BashExecError(f"unexpected redirect token in validated command: {t!r}")
        if t and set(t) <= _OPERATOR_CHARS:
            raise BashExecError(f"unexpected operator token in validated command: {t!r}")
        self.cur_argv.append(t)
        return i + 1


def parse(inner: str) -> list[Pipeline]:
    """Decompose an already-unwrapped command into the `Pipeline` structure to run.

    The single public seam shared by the gate and the executor (#379): the gate
    parses once to validate, hands the result into the BashDecision, and the
    executor runs that same structure via `run_parsed` — so a command is never
    re-decomposed (#456). The structure preserves the `|`-vs-`&&`/`||`/`;`/newline
    boundary (`a | b` is one pipeline of two stages, `a ; b` is two pipelines) so
    the gate can tell the sanctioned single `|` pipe apart from a sequence/
    short-circuit compound. Shares `tokenize` with the gate, so word boundaries
    match. Raises `BashExecError` on any operator/redirect the executor does not
    model, which the gate maps to a fail-closed deny."""
    builder = _PipelineBuilder()
    # Tokenize per physical line so an unquoted newline stays a command boundary.
    # A quote spanning a newline makes the line untokenizable → fail closed.
    for line in inner.split("\n"):
        toks = tokenize(line)
        if toks is None:
            raise UntokenizableCommand("untokenizable command reached the executor")
        i, n = 0, len(toks)
        while i < n:
            i = builder.feed_token(toks, i)
        builder.end_pipeline(";")  # the physical newline ends the current command
    return builder.pipelines


def _do_cd(cwd: Path, argv: list[str]) -> tuple[Path, int, str]:
    """`cd` is a shell builtin with no binary — model it directly so a `cd x && …`
    sequence runs its tail in the right directory. A bare `cd` is a no-op here (the
    read-only agent has no $HOME to chase); a missing dir mirrors bash's rc=1."""
    if len(argv) == 1:
        return cwd, 0, ""
    raw = argv[1]
    target = Path(raw) if os.path.isabs(raw) else cwd / raw
    target = target.resolve()
    if target.is_dir():
        return target, 0, ""
    return cwd, 1, f"cd: {raw}: No such file or directory\n"


def _kill_all(procs: list[subprocess.Popen]) -> None:
    """Tear down a partially- or fully-started pipeline: SIGKILL every process,
    then reap, so a timeout or a mid-pipe spawn failure never leaks a child."""
    for p in procs:
        p.kill()
    for p in procs:
        p.wait()


def _stage_stderr(stage: Stage, errfile):
    """Map a stage's stderr wiring to its Popen `stderr` target: `2>/dev/null` →
    DEVNULL, `2>&1` → STDOUT (merge into this stage's stdout pipe), otherwise the
    shared capture file."""
    if stage.stderr == "devnull":
        return subprocess.DEVNULL
    if stage.stderr == "stdout":
        return subprocess.STDOUT
    return errfile


def _reap_upstream(
    procs: list[subprocess.Popen], deadline: float, command: str, timeout: float
) -> None:
    """Reap the upstream stages (all but the last), bounded by the SAME deadline as
    the last stage. The last stage can exit before an upstream one (e.g.
    `tail -f f | head -1`: head reads one line and exits, while tail blocks on the
    file and never writes again, so it never receives SIGPIPE). With no outer shell
    to bound the pipeline, an unbounded `wait()` would hang the read-only lane past
    the caller's timeout — so wait against the remaining budget and tear the group
    down if it elapses."""
    for p in procs[:-1]:
        try:
            p.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            _kill_all(procs)
            raise subprocess.TimeoutExpired(command, timeout) from None


def _run_one_pipeline(
    stages: list[Stage], *, env: dict[str, str], cwd: Path, timeout: float, command: str
) -> tuple[int, str, str]:
    """Spawn a `|`-chain with shell=False, wiring each stdout into the next stdin.
    Only the last stage's stdout is captured; all non-merged stderr lands in one
    temp file (no pipe-buffer deadlock). Returns (rc, stdout, stderr); rc is the
    last stage's (bash pipeline semantics, no pipefail)."""
    import tempfile

    procs: list[subprocess.Popen] = []
    with tempfile.TemporaryFile(mode="w+b") as errfile:
        prev_stdout = None  # None → first stage reads from /dev/null
        try:
            for stage in stages:
                stderr = _stage_stderr(stage, errfile)
                try:
                    proc = subprocess.Popen(
                        stage.argv,
                        stdin=prev_stdout if prev_stdout is not None else subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=stderr,
                        cwd=str(cwd),
                        env=env,
                        text=True,
                        encoding="utf-8",  # the lane's own pin — never the ambient locale
                        errors="replace",  # a viewer emitting non-UTF-8 bytes must
                                           # not crash communicate() with a decode error
                    )
                except FileNotFoundError:
                    # bash prints "command not found" and returns 127. Match that
                    # rather than crashing the run; tear down anything started.
                    _kill_all(procs)
                    return 127, "", f"{stage.argv[0]}: command not found\n"
                # The parent's copy of the previous stage's read end must close so
                # EOF propagates when that stage exits.
                if prev_stdout is not None:
                    prev_stdout.close()
                prev_stdout = proc.stdout
                procs.append(proc)

            last = procs[-1]
            deadline = time.monotonic() + timeout
            try:
                out, _ = last.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                _kill_all(procs)
                raise subprocess.TimeoutExpired(command, timeout) from None
            _reap_upstream(procs, deadline, command, timeout)
            rc = last.returncode
        finally:
            # Close any dangling pipe fds the parent still holds.
            for p in procs:
                if p.stdout is not None:
                    with contextlib.suppress(OSError):
                        p.stdout.close()
        errfile.seek(0)
        err = errfile.read().decode("utf-8", "replace")
    return rc, out or "", err


def _short_circuit(pl, rc: int) -> bool:
    """True if this pipeline's `&&`/`||` connector short-circuits given the
    previous pipeline's `rc` — i.e. it should be SKIPPED. `&&` runs only after a
    success, `||` runs only after a failure; `;` (and a bare first pipeline)
    never short-circuits."""
    return (pl.connector == "&&" and rc != 0) or (pl.connector == "||" and rc == 0)


def _is_cd_pipeline(pl) -> bool:
    """True for a standalone `cd …` pipeline — handled inline (it updates the cwd
    threaded into later stages) rather than executed as a subprocess."""
    return len(pl.stages) == 1 and bool(pl.stages[0].argv) and pl.stages[0].argv[0] == "cd"


def run_parsed(
    pipelines: list[Pipeline], *, command: str, env: dict[str, str], cwd: str | Path,
    timeout: float,
) -> tuple[int, str, str]:
    """Execute an already-parsed `Pipeline` list (from `parse`) without a shell.

    The executor entrypoint: the gate parses once and `tools._tool_bash` hands
    that `BashDecision.pipelines` straight here, so the command is decomposed
    exactly once per tool call (#456). To run a raw string with no pre-parse,
    unwrap then `parse` it first: `run_parsed(parse(unwrap(s)), command=s, …)`.
    `command` is the original string, used only as the label in
    `TimeoutExpired`/error messages. An empty `pipelines` (e.g. an empty command)
    is a no-op → `(0, "", "")`. Honors `&&`/`||`/`;` short-circuiting and a shared
    wall-clock `timeout`; raises `subprocess.TimeoutExpired`.
    """
    cwd = Path(cwd)
    out_parts: list[str] = []
    err_parts: list[str] = []
    rc = 0
    deadline = time.monotonic() + timeout

    ran_any = False
    for pl in pipelines:
        if ran_any and _short_circuit(pl, rc):
            continue
        ran_any = True

        # `cd` as a standalone pipeline updates the cwd threaded into later stages.
        if _is_cd_pipeline(pl):
            cwd, rc, cd_err = _do_cd(cwd, pl.stages[0].argv)
            if cd_err:
                err_parts.append(cd_err)
            continue

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout)
        prc, pout, perr = _run_one_pipeline(
            pl.stages, env=env, cwd=cwd, timeout=remaining, command=command
        )
        rc = prc
        if pout:
            out_parts.append(pout)
        if perr:
            err_parts.append(perr)

    return rc, "".join(out_parts), "".join(err_parts)


def _run_box_entrypoint() -> int:
    """The in-box entrypoint: `python3 -m defender.runtime.bash_exec` (#540).

    Reads ONE framed request from stdin, runs the gate-approved pipelines, and writes ONE
    framed response to stdout. This is new, security-relevant surface, so it is deliberately
    the thinnest thing that can work: it accepts NO argv, so there is no command string for
    anything in the box to influence, and it reads structure rather than text, so there is no
    second parse on this side of the boundary. What the gate approved on the host is what runs
    here — the executor's whole reason for existing survives the move into a container.

    The environment is the container's own (a positive allowlist baked into the create), never
    anything the frame carries: a request that could set variables would be a channel for the
    host's secrets to be requested back.

    Stdout carries the frame and NOTHING else. Any unframed byte on this stream would be read
    by the host as an infrastructure fault, which is exactly what it would be."""
    from defender.runtime import box

    frame = sys.stdin.buffer.read()
    try:
        pipelines = box.decode_request(frame)
    except ValueError as e:
        # A frame we cannot decode is never guessed at: failing closed here is what stops a
        # corrupted request from becoming a different, still-executable command.
        print(f"box entrypoint: undecodable request frame: {e}", file=sys.stderr)
        return 2

    # The environment handed to the program is filtered to the box's positive allowlist. The
    # container's own env is NOT the allowlist on its own: a rootfs bakes its own variables in
    # (`python:3.11-slim` ships GPG_KEY, PYTHON_VERSION, PYTHON_SHA256), and `docker run` has no
    # way to clear an image's ENV. Filtering here — the one place every boxed program is
    # launched from — is what makes the allowlist true of what the model's code actually sees,
    # regardless of which rootfs the spec names.
    box_env = {k: v for k, v in os.environ.items() if k in box.BOX_ENV_ALLOWLIST}

    try:
        rc, out, err = run_parsed(
            pipelines,
            command="",
            env=box_env,
            cwd=Path.cwd(),
            timeout=float(os.environ.get("DEFENDER_BOX_TIMEOUT", "120")),
        )
    except subprocess.TimeoutExpired:
        print("box entrypoint: the pipeline exceeded its wall-clock deadline", file=sys.stderr)
        return 3

    sys.stdout.buffer.write(box.encode_response(box.BoxResult(
        rc=rc, out=out.encode("utf-8"), err=err.encode("utf-8"),
    )))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(_run_box_entrypoint())
