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

Tokenization reuses the SAME `tokenize`/`unwrap` the gate validates against
(`defender.hooks._cmd_segments`), so validator and executor share one lexer and
cannot disagree about word boundaries.
"""

from __future__ import annotations

import contextlib
import os
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from defender.hooks._cmd_segments import tokenize, unwrap

# Shell-operator characters. After splitting on the separators below, the only
# operator tokens a *validated* command can still carry are the two benign stderr
# redirects; anything else here is a divergence and fails closed.
_OPERATOR_CHARS = frozenset("<>|&;")
_PIPELINE_SEPARATORS = frozenset({"||", "&&", ";"})


class BashExecError(Exception):
    """The validated command carries a shape this executor does not model — i.e.
    the gate and the executor have diverged. Raised rather than silently mis-running."""


@dataclass(frozen=True)
class _Stage:
    """One command in a pipeline: its argv plus how its stderr is wired.
    `stderr` is "capture" (default), "devnull" (`2>/dev/null`), or "stdout"
    (`2>&1`, merge into this stage's stdout)."""

    argv: list[str]
    stderr: str = "capture"


@dataclass
class _Pipeline:
    """A `|`-chain of stages, plus the connector relating it to the PREVIOUS
    pipeline: "first" | "&&" | "||" | ";" (newline is treated as ";")."""

    connector: str
    stages: list[_Stage] = field(default_factory=list)


@dataclass
class _PipelineBuilder:
    """Accumulates the `_Pipeline` structure token by token. Holds the in-progress
    stage/pipeline + the pending inter-pipeline connector — the nonlocal state the
    original `end_stage`/`end_pipeline` closures mutated, made explicit so the
    per-token dispatch stays under the complexity gate."""

    pipelines: list[_Pipeline] = field(default_factory=list)
    pending_connector: str = "first"
    cur_stages: list[_Stage] = field(default_factory=list)
    cur_argv: list[str] = field(default_factory=list)
    cur_stderr: str = "capture"

    def end_stage(self) -> None:
        if self.cur_argv:
            self.cur_stages.append(_Stage(self.cur_argv, self.cur_stderr))
        self.cur_argv = []
        self.cur_stderr = "capture"

    def end_pipeline(self, next_connector: str) -> None:
        self.end_stage()
        if self.cur_stages:
            self.pipelines.append(_Pipeline(self.pending_connector, self.cur_stages))
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


def _build_pipelines(inner: str) -> list[_Pipeline]:
    """Decompose an already-unwrapped, already-validated command into the pipeline
    structure to execute. Shares `tokenize` with the gate, so word boundaries match."""
    builder = _PipelineBuilder()
    # Tokenize per physical line so an unquoted newline stays a command boundary.
    # A quote spanning a newline makes the line untokenizable → fail closed.
    for line in inner.split("\n"):
        toks = tokenize(line)
        if toks is None:
            raise BashExecError("untokenizable command reached the executor")
        i, n = 0, len(toks)
        while i < n:
            i = builder.feed_token(toks, i)
        builder.end_pipeline(";")  # the physical newline ends the current command
    return builder.pipelines


def stage_argvs(inner: str) -> list[list[str]]:
    """Public seam for the permission gate: the flat list of per-stage argvs the
    executor would run for an already-unwrapped command. Shares `_build_pipelines`,
    so the gate validates EXACTLY the structure the executor runs — there is no
    validator/executor differential to bypass (#379). Raises `BashExecError` on any
    operator/redirect the executor does not model, which the gate maps to a
    fail-closed deny."""
    return [st.argv for pl in _build_pipelines(inner) for st in pl.stages if st.argv]


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


def _stage_stderr(stage: _Stage, errfile):
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
    stages: list[_Stage], *, env: dict[str, str], cwd: Path, timeout: float, command: str
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


def run_pipeline(
    command: str, *, env: dict[str, str], cwd: str | Path, timeout: float
) -> tuple[int, str, str]:
    """Execute an already-gate-approved Bash command without a shell.

    Unwraps a leading `timeout`/`bash -c` (the same `unwrap` the gate validates
    against), decomposes the inner into pipelines, and runs them with shell=False
    honoring `&&`/`||`/`;` short-circuiting and a shared wall-clock `timeout`.
    Returns (returncode, stdout, stderr). Raises `subprocess.TimeoutExpired` so the
    caller's existing timeout handling is unchanged.
    """
    stripped = command.strip()
    if not stripped:
        return 0, "", ""
    inner = unwrap(stripped)
    if inner is None:
        # The gate denies un-unwrappable commands; reaching here means a caller
        # skipped validation. Fail closed rather than guess.
        raise BashExecError("command could not be unwrapped for execution")

    pipelines = _build_pipelines(inner)
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
