
from __future__ import annotations

import contextlib
import errno
import os
import selectors
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path


#: Operator runs `feed_token` refuses outright. Narrower than `_SHLEX_PUNCTUATION`: a run
#: containing `(`/`)` is not refused here and crosses as a literal argv word
#: (`parse('cat <(id)')` is `['cat','<(','id',')']`). `permission/bash.py::_stage_unsafe`
#: refuses bare paren tokens, but by exact equality, so a fused run like the `)|` in
#: `cat <(id)|grep y` passes both checks and swallows the pipe; today it fails closed only
#: because no grant pattern admits a `)|` operand. Nothing expands either way: no shell
#: re-parses downstream.
_OPERATOR_CHARS = frozenset("<>|&;")
_PIPELINE_SEPARATORS = frozenset({"||", "&&", ";"})

#: Characters that end a word and start an operator run (`shlex`'s punctuation set). Wider
#: than `_OPERATOR_CHARS`: `(`/`)` split a word but are not refused by `feed_token`; the
#: downstream token shape is pinned on this split.
_SHLEX_PUNCTUATION = frozenset("();<>|&")

#: Bash's word separators: space and tab (`\n` never reaches the scanner; `parse` splits on
#: it). Not `str.isspace()` (true for NBSP, `\x0b`, `\x85`, ...) and not `shlex.whitespace`
#: (includes `\r`, which bash keeps in the word). Splitting on a wider set hands the executor
#: an argv the model did not write, e.g. `w a\r2>/dev/null` losing its `2` operand and having
#: a stdout redirect read as fd 2. `test_bash_fd_prefix.py::_NOT_SHELL_BLANKS` pins it.
_BLANKS = frozenset(" \t\n")

#: `_BLANKS` as a string, for `str.strip` and membership tests. Public so anything that needs
#: to know where a bash word ends imports it rather than spelling its own copy. `sorted`
#: because frozenset iteration order is not guaranteed.
BLANKS = "".join(sorted(_BLANKS))

#: Bash's comment character: starts a comment only unquoted and where a word begins (`a#b`,
#: `'#'` and `\#` are literal). Decided against the raw text, because once a word is resolved
#: a literal `#` and a comment `#` look the same; otherwise `cat a # ; rm -rf b` would be two
#: stages here while bash runs one command plus a comment.
_COMMENT = "#"

#: The only fd this executor routes; any other IO_NUMBER is refused.
_STDERR_FD = "2"

#: The fd-2 redirects this executor implements: `operator -> (required target, stderr mode)`.
#: One table so the shared fd-prefix condition exists in one place.
_FD2_REDIRECTS = {">": ("/dev/null", "devnull"), ">&": ("1", "stdout")}

#: Tokens that leave a line incomplete when they close it (`A |`, `A &&`). `;` is absent:
#: `A;` is a finished command.
_DANGLING_CONNECTORS = frozenset({"|", "&&", "||"})

#: Token kinds. `2>` (an IO_NUMBER redirect) and `2 >` (the word `2`, then a stdout redirect)
#: have the same token text, so the kind tells them apart: `FD_OPERATOR` marks the bare `2`
#: glued to a following `>`/`>&`; the operator itself stays `OPERATOR`.
WORD = "word"
OPERATOR = "operator"
FD_OPERATOR = "fd-operator"


@dataclass(frozen=True)
class Token:
    """One scanned token: resolved value, start/end code-point offsets of its raw spelling
    (quoting and glue intact), and kind."""

    value: str
    start: int
    end: int
    kind: str


def _literal_mask(line: str) -> list[bool] | None:
    """Which characters of `line` stand as themselves — unquoted, unescaped, and not a quote
    or escape character of the syntax. `None` if a quote never closes.

    `_scan` uses it to decide whether an operator character is an operator and whether it was
    glued to the word on its left; neither is recoverable from resolved word values."""
    mask = [False] * len(line)
    quote: str | None = None
    i = 0
    while i < len(line):
        c = line[i]
        if quote is None:
            if c == "\\":
                i += 2          # escaped: a literal CHARACTER, never an operator
                continue
            if c in ("'", '"'):
                quote = c
                i += 1
                continue
            mask[i] = True
            i += 1
            continue
        if c == "\\" and quote == '"':
            i += 2
            continue
        if c == quote:
            quote = None
        i += 1
    return None if quote is not None else mask


def _double_quoted_value(span: str, start: int) -> tuple[str, int] | None:
    """The resolved content of a double-quoted run starting at `span[start] == '"'`, and the
    index just past its closing quote — or `None` if it never closes. Only `"`, `\\`, `$` and
    a backtick are escapable inside double quotes (POSIX)."""
    j, n = start + 1, len(span)
    buf: list[str] = []
    while j < n:
        c = span[j]
        if c == '"':
            return "".join(buf), j + 1
        if c == "\\" and j + 1 < n and span[j + 1] in ('"', "\\", "$", "`"):
            buf.append(span[j + 1])
            j += 2
            continue
        buf.append(c)
        j += 1
    return None


def _word_value(span: str) -> str | None:
    r"""One word's raw text — quotes and escapes intact — resolved to the value it stands for.

    `_scan` bounds the span so it has no unquoted blank or operator, so this never re-splits.
    `None` on a dangling escape or unclosed quote (defensive; `_literal_mask` already checked
    the line's balance).

    Hand-rolled rather than `shlex` because bash resolves `\$` and an escaped backtick inside
    double quotes, and `shlex` leaves the backslash on; the gate must resolve words as bash
    does. The quote-free fast path matters: most spans have no `'`, `"` or `\`, and `parse`
    runs on every Bash tool call."""
    if not ("'" in span or '"' in span or "\\" in span):
        return span
    out: list[str] = []
    i, n = 0, len(span)
    while i < n:
        c = span[i]
        if c == "\\":
            if i + 1 >= n:
                return None
            out.append(span[i + 1])
            i += 2
            continue
        if c == "'":
            j = span.find("'", i + 1)
            if j == -1:
                return None
            out.append(span[i + 1:j])
            i = j + 1
            continue
        if c == '"':
            resolved = _double_quoted_value(span, i)
            if resolved is None:
                return None
            value, i = resolved
            out.append(value)
            continue
        out.append(c)
        i += 1
    return "".join(out)


def _is_fd_prefix(line: str, mask: list[bool], at: int, toks: list[Token]) -> bool:
    """Whether the operator run starting at `at` is bash's IO_NUMBER — an unquoted `2` glued
    to its left that starts its own word. Bash reads `foo2>` and `"2">` as stdout redirects."""
    if at == 0 or not mask[at - 1] or line[at - 1] != _STDERR_FD:
        return False
    if not toks or toks[-1].value != _STDERR_FD:
        return False
    if at == 1:
        return True
    before = line[at - 2]
    # Not `_SHLEX_PUNCTUATION`: an IO_NUMBER cannot follow `(`/`)` in any line bash runs, and
    # accepting `w a)2>/dev/null` as an fd-2 redirect would accept a line bash rejects.
    return mask[at - 2] and (before in _BLANKS or before in _OPERATOR_CHARS)


def _scan(line: str) -> list[Token] | None:
    r"""The line's tokens, or `None` if a quote never closes.

    Structure is decided against the raw text; only word values go through `_word_value`.
    That is the only place two questions can be answered: was an operator glued to the word
    on its left (`2>` vs `2 >`), and was it an operator at all (a quoted/escaped `\;` for
    `find -exec` is a word, not a separator)."""
    mask = _literal_mask(line)
    if mask is None:
        return None
    toks: list[Token] = []
    i, n = 0, len(line)
    while i < n:
        if mask[i] and line[i] in _BLANKS:
            i += 1
            continue
        if mask[i] and line[i] == _COMMENT:
            # A word starts here, so this is bash's comment. Dropping the rest (as bash does)
            # leaves an operator dangling before it (`A | # x`) to fail as it does in bash.
            break
        if mask[i] and line[i] in _SHLEX_PUNCTUATION:
            j = i
            while j < n and mask[j] and line[j] in _SHLEX_PUNCTUATION:
                j += 1
            if _is_fd_prefix(line, mask, i, toks):
                # Retroactively mark the preceding bare digit as the fd. Constructed directly
                # rather than via `dataclasses.replace`, which is ~2x slower on a hot path.
                prev = toks[-1]
                toks[-1] = Token(prev.value, prev.start, prev.end, FD_OPERATOR)
            toks.append(Token(line[i:j], i, j, OPERATOR))
            i = j
            continue
        j = i
        while j < n and not (mask[j] and (line[j] in _BLANKS or line[j] in _SHLEX_PUNCTUATION)):
            j += 1
        word = _word_value(line[i:j])
        if word is None:
            return None
        toks.append(Token(word, i, j, WORD))
        i = j
    return toks


class BashExecError(Exception):
    pass


class UntokenizableCommand(BashExecError):
    pass


@dataclass(frozen=True)
class Stage:

    argv: list[str]
    stderr: str = "capture"


@dataclass
class Pipeline:

    connector: str
    stages: list[Stage] = field(default_factory=list)


@dataclass
class _PipelineBuilder:

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
        if self.cur_stages and not self.cur_argv:
            # A `|` with nothing complete after it would silently vanish (`A | ; B`,
            # `A | 2>/dev/null`). Checked where a pipeline closes, since the exposing token
            # is not always a connector.
            raise UntokenizableCommand(
                "pipeline token '|' has nothing to its right"
            )
        self.end_stage()
        if self.cur_stages:
            self.pipelines.append(Pipeline(self.pending_connector, self.cur_stages))
            self.cur_stages = []
            self.pending_connector = next_connector

    def feed_token(self, tokens: list[Token], i: int) -> int:
        tok, n = tokens[i], len(tokens)
        t = tok.value
        if tok.kind == WORD:
            # Quoted/escaped operator text (`find … {} \;`, `echo ';'`) is an argument; every
            # arm below dispatches on text.
            self.cur_argv.append(t)
            return i + 1
        if t in _DANGLING_CONNECTORS and not self.cur_argv:
            # A connector with no complete command to its left; across lines (`A\n| B`) it
            # would be dropped and `A | B` become `A ; B`. `cur_stages` is not consulted so
            # `A | | B` is caught too. A leading `;` drops nothing and is allowed, matching
            # `permission/bash.UNTOKENIZABLE_REASON`, which names only `|`/`&&`/`||`.
            raise UntokenizableCommand(
                f"pipeline/connector token {t!r} has no command to its left"
            )
        if t == "|":
            self.end_stage()
            return i + 1
        if t in _PIPELINE_SEPARATORS:
            self.end_pipeline(t)
            return i + 1
        if t in _FD2_REDIRECTS:
            # The fd test is the preceding token's `FD_OPERATOR` kind; `cur_argv[-1] == "2"`
            # only confirms it. Testing the text alone would read the operand in
            # `head -c 2 >/dev/null` as an fd and run `head -c`.
            target, stderr = _FD2_REDIRECTS[t]
            if (
                i > 0 and tokens[i - 1].kind == FD_OPERATOR
                and self.cur_argv and self.cur_argv[-1] == _STDERR_FD
                and i + 1 < n and tokens[i + 1].value == target
            ):
                self.cur_argv.pop()
                self.cur_stderr = stderr
                return i + 2
            raise BashExecError(f"unexpected redirect token in validated command: {t!r}")
        if t and set(t) <= _OPERATOR_CHARS:
            raise BashExecError(f"unexpected operator token in validated command: {t!r}")
        self.cur_argv.append(t)
        return i + 1


def parse(cmd: str) -> list[Pipeline]:
    """The pipelines in `cmd` (the model's raw command text). Each physical line is scanned on
    its own and each stage becomes a bare argv.

    No word is special (`bash -c`, `timeout` are ordinary argv words): unwrapping a command
    deletes text ahead of the gate's decision, so a misparse could only widen what it allows.
    Only punctuation is special: connectors, the two stderr redirects, newlines, quoting."""
    builder = _PipelineBuilder()
    tokens: list[Token] | None
    for line in cmd.split("\n"):
        tokens = _scan(line)
        if tokens is None:
            raise UntokenizableCommand("untokenizable command reached the executor")
        i, n = 0, len(tokens)
        while i < n:
            i = builder.feed_token(tokens, i)
        if (
            tokens and tokens[-1].value in _DANGLING_CONNECTORS
            and tokens[-1].kind != WORD
        ):
            # `A |` / `A &&` closing a line: nothing joins lines, so the next line would run
            # as an independent command.
            raise UntokenizableCommand(
                f"pipeline/connector token {tokens[-1].value!r} closes a line with nothing to "
                "its right"
            )
        builder.end_pipeline(";")
        if builder.pending_connector in _DANGLING_CONNECTORS:
            # `A && ;`: the connector got no right side within its line. Checked per line
            # because `pending_connector` outlives the line; otherwise `A && ;\nB` would run B
            # conditionally on A.
            raise UntokenizableCommand(
                f"pipeline/connector token {builder.pending_connector!r} has no command "
                "to its right"
            )
    return builder.pipelines


def _do_cd(cwd: Path, argv: list[str]) -> tuple[Path, int, bytes]:
    if len(argv) == 1:
        return cwd, 0, b""
    raw = argv[1]
    target = Path(raw) if os.path.isabs(raw) else cwd / raw
    target = target.resolve()
    if target.is_dir():
        return target, 0, b""
    return cwd, 1, f"cd: {raw}: No such file or directory\n".encode()


#: The signals that end a stage as a kill or a crash, as a return code: the memory cap's kill
#: and the crashes of a process that ran out of room. Not -13: `head` ends its producer that way
#: as a matter of course.
KILL_OR_CRASH = (-9, -11, -6, -7)


def is_kill_or_crash(rc: int | None) -> bool:
    """Whether a stage's return code says a kill or crash signal ended it. The one owner of the
    set; the blame mapping reuses it. A kill the helper sends itself never reaches this: it
    stops the command and returns before the codes are read."""
    return rc in KILL_OR_CRASH


#: A stage's wait, once its stdout is done: how often to look for the stages' exit.
_POLL_SECONDS = 0.05
_CHUNK = 256 * 1024


def _codec():
    """`box_codec` (function-local: it imports this module)."""
    from defender.execution import box_codec

    return box_codec


class _Stopped(Exception):
    """The command ends here with this code and this one line, and nothing else is returned."""

    def __init__(self, rc: int, line: bytes) -> None:
        super().__init__(line)
        self.rc = rc
        self.line = line


class _Budget:
    """What the whole command may still print: charged by everything entering the frame."""

    def __init__(self, limit: int) -> None:
        self.left = limit

    def charge(self, size: int) -> None:
        self.left -= size
        if self.left < 0:
            codec = _codec()
            raise _Stopped(codec.OVER_BUDGET_RC, codec.OVER_BUDGET_LINE)


@dataclass
class _Deadline:
    at: float
    command: str
    timeout: float

    def left(self) -> float:
        left = self.at - time.monotonic()
        if left <= 0:
            raise subprocess.TimeoutExpired(self.command, self.timeout)
        return left


def _kill_all(procs: list[subprocess.Popen]) -> None:
    for p in procs:
        p.kill()
    for p in procs:
        p.wait()


def _stage_stderr(stage: Stage, shared: int):
    if stage.stderr == "devnull":
        return subprocess.DEVNULL
    if stage.stderr == "stdout":
        return subprocess.STDOUT
    return shared


def _spawn(
    stages: list[Stage], procs: list[subprocess.Popen], stderr_fd: int, *,
    env: dict[str, str], cwd: Path,
) -> None:
    prev_stdout = None
    for stage in stages:
        proc = subprocess.Popen(
            stage.argv,
            stdin=prev_stdout if prev_stdout is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=_stage_stderr(stage, stderr_fd),
            cwd=str(cwd),
            env=env,
        )
        if prev_stdout is not None:
            prev_stdout.close()
        prev_stdout = proc.stdout
        procs.append(proc)


def _start_failure(argv0: str, exc: OSError) -> tuple[int, bytes, bytes]:
    """What a stage that could not start leaves: keyed on `errno`. Out of processes or memory
    ends the command naming the process cap; anything else is the system's own text."""
    if isinstance(exc, FileNotFoundError):
        return 127, b"", f"{argv0}: command not found\n".encode()
    if isinstance(exc, PermissionError):
        return 126, b"", f"{argv0}: Permission denied\n".encode()
    if exc.errno in (errno.EAGAIN, errno.ENOMEM):
        raise _Stopped(126, _codec().PROCESS_CAP_LINE)
    why = os.strerror(exc.errno) if exc.errno else str(exc)
    return 126, b"", f"{argv0}: {why}\n".encode()


def _reap_upstream(procs: list[subprocess.Popen]) -> bool:
    """Collect every stage that has exited (the upstream ones end when the last stage stops
    reading, or on their own); whether all of them have."""
    return all(p.poll() is not None for p in procs)


class _Pump:
    """Reads the last stage's stdout and the one stderr pipe the stages share, in one loop, so
    both count against the budget as they arrive."""

    def __init__(self, procs: list[subprocess.Popen], err_fd: int, budget: _Budget) -> None:
        assert procs[-1].stdout is not None
        self.procs = procs
        self.budget = budget
        self.out_fd = procs[-1].stdout.fileno()
        self.err_fd = err_fd
        self.sinks = {self.out_fd: bytearray(), err_fd: bytearray()}
        self.open = {self.out_fd, err_fd}
        self.sel = selectors.DefaultSelector()
        for fd in self.open:
            self.sel.register(fd, selectors.EVENT_READ)

    def _read(self, fd: int) -> bool:
        """One chunk of `fd`; whether it held data."""
        try:
            chunk = os.read(fd, _CHUNK)
        except BlockingIOError:
            return False
        if not chunk:
            self.open.discard(fd)
            self.sel.unregister(fd)
            return False
        self.budget.charge(len(chunk))
        self.sinks[fd] += chunk
        return True


    def run(self, deadline: _Deadline) -> tuple[bytes, bytes]:
        # A forked daemon can hold the stderr pipe open for good, so the loop ends at the last
        # stdout's EOF with every stage exited, then drains what is there without blocking.
        while self.out_fd in self.open or not _reap_upstream(self.procs):
            left = deadline.left()
            if not self.open:
                time.sleep(min(left, 0.01))
                continue
            wait = left if self.out_fd in self.open else min(left, _POLL_SECONDS)
            for key, _ in self.sel.select(wait):
                self._read(key.fd)
        while self.err_fd in self.open and self._read(self.err_fd):
            pass
        return bytes(self.sinks[self.out_fd]), bytes(self.sinks[self.err_fd])


def _run_one_pipeline(
    stages: list[Stage], *, env: dict[str, str], cwd: Path, deadline: _Deadline, budget: _Budget,
) -> tuple[int, bytes, bytes]:
    procs: list[subprocess.Popen] = []
    err_r, err_w = os.pipe()
    os.set_blocking(err_r, False)
    try:
        try:
            _spawn(stages, procs, err_w, env=env, cwd=cwd)
        except OSError as exc:
            _kill_all(procs)
            return _start_failure(stages[len(procs)].argv[0], exc)
        finally:
            os.close(err_w)
        try:
            pump = _Pump(procs, err_r, budget)
            try:
                out, err = pump.run(deadline)
            finally:
                pump.sel.close()
        except BaseException:
            _kill_all(procs)
            raise
        for p in procs:
            if is_kill_or_crash(p.returncode):
                raise _Stopped(p.returncode, _codec().KILLED_LINE)
        return procs[-1].returncode, out, err
    finally:
        os.close(err_r)
        for p in procs:
            if p.stdout is not None:
                with contextlib.suppress(OSError):
                    p.stdout.close()


def _short_circuit(pl, rc: int) -> bool:
    return (pl.connector == "&&" and rc != 0) or (pl.connector == "||" and rc == 0)


def _is_cd_pipeline(pl) -> bool:
    return len(pl.stages) == 1 and bool(pl.stages[0].argv) and pl.stages[0].argv[0] == "cd"


def _run_all(
    pipelines: list[Pipeline], cwd: Path, env: dict[str, str], deadline: _Deadline,
    budget: _Budget,
) -> tuple[int, bytes, bytes]:
    out_parts: list[bytes] = []
    err_parts: list[bytes] = []
    rc = 0
    ran_any = False
    for pl in pipelines:
        if ran_any and _short_circuit(pl, rc):
            continue
        ran_any = True

        if _is_cd_pipeline(pl):
            cwd, rc, cd_err = _do_cd(cwd, pl.stages[0].argv)
            budget.charge(len(cd_err))
            if cd_err:
                err_parts.append(cd_err)
            continue

        deadline.left()
        rc, pout, perr = _run_one_pipeline(
            pl.stages, env=env, cwd=cwd, deadline=deadline, budget=budget
        )
        if pout:
            out_parts.append(pout)
        if perr:
            err_parts.append(perr)
    return rc, b"".join(out_parts), b"".join(err_parts)


def run_parsed(
    pipelines: list[Pipeline], *, command: str, env: dict[str, str], cwd: str | Path,
    timeout: float,
) -> tuple[int, bytes, bytes]:
    """Run the pipelines; the code, stdout and stderr as the programs wrote them (bytes).

    One output budget spans the whole command, and a stage ending on a kill or crash signal
    that this helper did not send ends it too: either returns the code, empty stdout and one
    fixed line, with everything captured dropped and no later pipeline run."""
    budget = _Budget(_codec().HELPER_OUTPUT_BUDGET)
    deadline = _Deadline(time.monotonic() + timeout, command, timeout)
    try:
        return _run_all(pipelines, Path(cwd), env, deadline, budget)
    except _Stopped as stop:
        return stop.rc, b"", stop.line


def _run_box_entrypoint() -> int:
    """The process that runs inside the sandbox, once per command an agent issues. Imports
    `box_codec` (stdlib only) rather than the `box` package, whose import pulls in pydantic and
    costs ~7x as much. Function-local because `box_codec` imports this module."""
    from defender.execution import box_codec

    frame = sys.stdin.buffer.read()
    try:
        pipelines = box_codec.decode_request(frame)
    except ValueError as e:
        print(f"box entrypoint: undecodable request frame: {e}", file=sys.stderr)
        return 2

    box_env = {k: v for k, v in os.environ.items() if k in box_codec.BOX_ENV_ALLOWLIST}

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
    except Exception:  # noqa: BLE001 — a helper fault on a model's command still answers with a frame
        traceback.print_exc()
        rc, out, err = 70, b"", box_codec.FAILED_LINE

    sys.stdout.buffer.write(box_codec.encode_response(box_codec.BoxResult(
        rc=rc, out=out, err=err,
    )))
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":  # lint-log-setup: ok — the box entrypoint: runs inside the sandbox, and its stderr is the host's channel from the box
    # Under `-m` this module is `__main__`; `box_codec` imports it by its real name, which would
    # execute it a second time (no bytecode cache on the read-only mount) and create a second
    # `Pipeline`/`Stage` pair. Alias it; `setdefault` so a normal import, if any, wins.
    if __spec__ is not None:  # `-m`/runpy set it; a bare `python bash_exec.py` does not
        sys.modules.setdefault(__spec__.name, sys.modules[__name__])
    sys.exit(_run_box_entrypoint())
