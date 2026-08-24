
from __future__ import annotations

import contextlib
import os
import shlex
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path


_OPERATOR_CHARS = frozenset("<>|&;")
_PIPELINE_SEPARATORS = frozenset({"||", "&&", ";"})

#: The characters that END a word and start an operator run — `shlex`'s own punctuation set
#: from the `punctuation_chars=True` lexing this module used to do, kept verbatim so the
#: scanner splits words exactly where that lexer split them. WIDER than `_OPERATOR_CHARS`:
#: `(`/`)` break a word here without being operators the grammar accepts. `feed_token` does
#: NOT refuse them — its operator arm tests `set(t) <= _OPERATOR_CHARS`, which they are not in
#: — so they land in argv as ordinary words, exactly as the `punctuation_chars` lexer left
#: them. That is inert here (no stage is run through a shell), and the guard that cares is
#: `permission/bash._stage_unsafe`, which reads argv. Kept verbatim so this scanner and that
#: guard see the same token stream they always did; it is not a licence to widen the set.
_SHLEX_PUNCTUATION = frozenset("();<>|&")

#: The whitespace that ENDS a word — `shlex`'s own set, not `str.isspace()`. The two differ on
#: U+00A0, `\v`, `\f`, U+2028 and every other Unicode space, and bash splits on none of them:
#: `str.isspace()` tore `cat /tmp/a\xa0b` into two operands and ran a command the model did not
#: write, on a path the gate then scope-checked instead of the one that was asked for.
_WORD_SEPARATORS = frozenset(" \t\r\n")

#: The only fd this executor knows how to route. Bash's IO_NUMBER admits any digit run; every
#: other one is refused, so the scan only has to recognise this one.
_STDERR_FD = "2"

#: The tokens that leave a line INCOMPLETE when they close it — `A |`, `A &&` need the next
#: line to mean anything. `;` is deliberately absent: `A;` is a finished command.
_DANGLING_CONNECTORS = frozenset({"|", "&&", "||"})


def _literal_mask(line: str) -> list[bool] | None:
    """Which characters of `line` stand as themselves — unquoted, unescaped, and not a quote
    or escape character of the syntax. `None` if a quote never closes.

    Everything `_scan` decides rests on this: whether an operator character IS an operator, and
    whether it was glued to the word on its left. Both are facts about the raw text, and both
    are gone by the time `shlex` has resolved a word to its value (#955 F-50)."""
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


def _word_value(span: str) -> str | None:
    """One word's raw text — quotes and escapes intact — reduced to the value it stands for.

    `shlex` again, but over a span that HAS no unquoted whitespace and no unquoted operator, so
    it is being asked only to resolve quoting and must hand back exactly one word. `comments`
    is off for the reason the line lexer always cleared `commenters`: `#` is an ordinary
    character in a filename or a pattern here, and the default would truncate the word at it."""
    try:
        parts = shlex.split(span, comments=False, posix=True)
    except ValueError:
        return None
    return parts[0] if len(parts) == 1 else None


def _scan(line: str) -> tuple[list[str], frozenset[int], frozenset[int]] | None:
    r"""The line's tokens, which of them are OPERATORS, and which operators carry an fd.

    Structure is decided against the RAW TEXT and only the values go through `shlex`, which is
    the whole of #955 F-50. Lexing the line with `punctuation_chars=True` — as this module did
    — hands back a stream in which the two questions the grammar turns on can no longer be
    asked:

      * WAS THE OPERATOR GLUED to the word on its left? `2>` is a single IO_NUMBER redirect
        and `2 >` is the word `2` followed by a redirect of stdout, and both arrive as
        `['2', '>']`. Reading the fd off the previous TOKEN accepted `head -c 2 >/dev/null`
        and ran `head -c` — the gate answering on an argument's VALUE, and the executor
        running a command the model did not write.
      * WAS IT AN OPERATOR AT ALL? A quoted or escaped one is an ordinary character: the `\;`
        that `find -exec` requires came back as a bare `;` token and was read as a pipeline
        separator, dropping the terminator `find` cannot run without.

    Both are answered here and neither can be answered downstream, so the tokenizer is the
    only place the fix fits."""
    mask = _literal_mask(line)
    if mask is None:
        return None
    toks: list[str] = []
    operators: set[int] = set()
    fd_prefixed: set[int] = set()
    i, n = 0, len(line)
    while i < n:
        if mask[i] and line[i] in _WORD_SEPARATORS:
            i += 1
            continue
        if mask[i] and line[i] in _SHLEX_PUNCTUATION:
            j = i
            while j < n and mask[j] and line[j] in _SHLEX_PUNCTUATION:
                j += 1
            if _is_fd_prefix(line, mask, i, toks):
                fd_prefixed.add(len(toks))
            operators.add(len(toks))
            toks.append(line[i:j])
            i = j
            continue
        j = i
        while j < n and not (
            mask[j] and (line[j] in _WORD_SEPARATORS or line[j] in _SHLEX_PUNCTUATION)
        ):
            j += 1
        word = _word_value(line[i:j])
        if word is None:
            return None
        toks.append(word)
        i = j
    return toks, frozenset(operators), frozenset(fd_prefixed)


def _is_fd_prefix(line: str, mask: list[bool], at: int, toks: list[str]) -> bool:
    """Whether the operator run starting at `at` is bash's IO_NUMBER — an unquoted `2` glued
    to its left that STARTS its own word.

    The last clause is not decoration: bash reads `foo2>` as the word `foo2` redirecting
    stdout, not as a redirect of fd 2, and a quoted `"2">` the same way. Only a bare digit run
    standing alone is the fd."""
    if at == 0 or not mask[at - 1] or line[at - 1] != _STDERR_FD:
        return False
    if not toks or toks[-1] != _STDERR_FD:
        return False
    if at == 1:
        return True
    before = line[at - 2]
    return mask[at - 2] and (before in _WORD_SEPARATORS or before in _SHLEX_PUNCTUATION)


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
            # A `|` banked a stage and nothing COMPLETE follows it, so this pipeline would
            # close holding only its left side and the `|` would vanish — `A | ; B` would run
            # B on /dev/null. The check lives here, where a pipeline closes, rather than
            # beside `feed_token`'s token checks, because the token that exposes it is not
            # always a connector (`;` is carved out below, and `A | 2>/dev/null` empties its
            # right side with no separator at all). The invariant — no pipeline banks a stage
            # list whose last `|` had an empty right side — covers every spelling, where
            # enumerating the tokens that may follow a pipe does not.
            raise UntokenizableCommand(
                "pipeline token '|' has nothing to its right"
            )
        self.end_stage()
        if self.cur_stages:
            self.pipelines.append(Pipeline(self.pending_connector, self.cur_stages))
            self.cur_stages = []
            self.pending_connector = next_connector

    def feed_token(
        self, toks: list[str], i: int,
        operators: frozenset[int], fd_prefixed: frozenset[int],
    ) -> int:
        t, n = toks[i], len(toks)
        if i not in operators:
            # A token whose TEXT is an operator but whose raw spelling was quoted or escaped —
            # `find … {} \;`, `echo ';'`. Every arm below dispatches on text, so without this
            # the `;` that `find -exec` requires was read as a pipeline separator and dropped,
            # leaving `find` to run a command it cannot complete (#955 F-50's other half).
            self.cur_argv.append(t)
            return i + 1
        if t in _DANGLING_CONNECTORS and not self.cur_argv:
            # A connector with no COMPLETE command to its left. Within a line that is a bash
            # syntax error; ACROSS lines (`A\n| B`) the token would be dropped and `A | B`
            # would silently become `A ; B` — a second stage on /dev/null, reported as the
            # last pipeline's rc. `cur_stages` is deliberately NOT consulted: `A | | B`
            # reaches here with a stage already banked, and the second `|` is just as dropped.
            #
            # Same set as the trailing check: a leading `;` drops NOTHING, so refusing it would
            # deny a harmless command under the only reason the agent is ever shown —
            # `permission/bash.UNTOKENIZABLE_REASON`, which names `|`/`&&`/`||` and not `;`.
            raise UntokenizableCommand(
                f"pipeline/connector token {t!r} has no command to its left"
            )
        if t == "|":
            self.end_stage()
            return i + 1
        if t in _PIPELINE_SEPARATORS:
            self.end_pipeline(t)
            return i + 1
        if t == ">":
            # `i in fd_prefixed` is the whole of the fd test; `cur_argv[-1] == "2"` only
            # confirms the token stream agrees with the raw text about which word that was.
            # Testing the TOKEN alone (as both arms did until #955 F-50) reads an ordinary
            # numeric operand as an fd: `head -c 2 >/dev/null` was accepted and ran
            # `head -c` — the gate's answer turning on an argument's VALUE, and the executor
            # running a command the model did not write.
            if (
                i in fd_prefixed and self.cur_argv and self.cur_argv[-1] == _STDERR_FD
                and i + 1 < n and toks[i + 1] == "/dev/null"
            ):
                self.cur_argv.pop()
                self.cur_stderr = "devnull"
                return i + 2
            raise BashExecError(f"unexpected redirect token in validated command: {t!r}")
        if t == ">&":
            if (
                i in fd_prefixed and self.cur_argv and self.cur_argv[-1] == _STDERR_FD
                and i + 1 < n and toks[i + 1] == "1"
            ):
                self.cur_argv.pop()
                self.cur_stderr = "stdout"
                return i + 2
            raise BashExecError(f"unexpected redirect token in validated command: {t!r}")
        if t and set(t) <= _OPERATOR_CHARS:
            raise BashExecError(f"unexpected operator token in validated command: {t!r}")
        self.cur_argv.append(t)
        return i + 1


def parse(inner: str) -> list[Pipeline]:
    builder = _PipelineBuilder()
    for line in inner.split("\n"):
        scanned = _scan(line)
        if scanned is None:
            raise UntokenizableCommand("untokenizable command reached the executor")
        toks, operators, fd_prefixed = scanned
        i, n = 0, len(toks)
        while i < n:
            i = builder.feed_token(toks, i, operators, fd_prefixed)
        if toks and toks[-1] in _DANGLING_CONNECTORS and len(toks) - 1 in operators:
            # `A |` / `A &&` closing a line. There is no shell to join the lines, so the
            # connector would be dropped and the implicit `;` below would run the next line
            # as an independent command.
            raise UntokenizableCommand(
                f"pipeline/connector token {toks[-1]!r} closes a line with nothing to its right"
            )
        builder.end_pipeline(";")
        if builder.pending_connector in _DANGLING_CONNECTORS:
            # An `&&`/`||` that banked its LEFT pipeline and never got a right one WITHIN ITS
            # OWN LINE, so the connector was consumed and dropped. The token check above cannot
            # see it: the line ends with the bare `;` that follows (`A && ;`), which the
            # carve-out lets through.
            #
            # PER LINE, not once after the loop: `pending_connector` is builder state that
            # outlives a line, so an end-of-parse check leaves `A && ;\nB` accepted — the `&&`
            # then reaches ACROSS the line boundary and runs B conditionally on A. The
            # connector's right side must arrive on its own line or not at all.
            raise UntokenizableCommand(
                f"pipeline/connector token {builder.pending_connector!r} has no command "
                "to its right"
            )
    return builder.pipelines


def _do_cd(cwd: Path, argv: list[str]) -> tuple[Path, int, str]:
    if len(argv) == 1:
        return cwd, 0, ""
    raw = argv[1]
    target = Path(raw) if os.path.isabs(raw) else cwd / raw
    target = target.resolve()
    if target.is_dir():
        return target, 0, ""
    return cwd, 1, f"cd: {raw}: No such file or directory\n"


def _kill_all(procs: list[subprocess.Popen]) -> None:
    for p in procs:
        p.kill()
    for p in procs:
        p.wait()


def _stage_stderr(stage: Stage, errfile):
    if stage.stderr == "devnull":
        return subprocess.DEVNULL
    if stage.stderr == "stdout":
        return subprocess.STDOUT
    return errfile


def _reap_upstream(
    procs: list[subprocess.Popen], deadline: float, command: str, timeout: float
) -> None:
    for p in procs[:-1]:
        try:
            p.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            _kill_all(procs)
            raise subprocess.TimeoutExpired(command, timeout) from None


def _run_one_pipeline(
    stages: list[Stage], *, env: dict[str, str], cwd: Path, timeout: float, command: str
) -> tuple[int, str, str]:
    import tempfile

    procs: list[subprocess.Popen] = []
    with tempfile.TemporaryFile(mode="w+b") as errfile:
        prev_stdout = None
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
                        encoding="utf-8",
                        errors="replace",
                    )
                except FileNotFoundError:
                    _kill_all(procs)
                    return 127, "", f"{stage.argv[0]}: command not found\n"
                except PermissionError:
                    _kill_all(procs)
                    return 126, "", f"{stage.argv[0]}: Permission denied\n"
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
            for p in procs:
                if p.stdout is not None:
                    with contextlib.suppress(OSError):
                        p.stdout.close()
        errfile.seek(0)
        err = errfile.read().decode("utf-8", "replace")
    return rc, out or "", err


def _short_circuit(pl, rc: int) -> bool:
    return (pl.connector == "&&" and rc != 0) or (pl.connector == "||" and rc == 0)


def _is_cd_pipeline(pl) -> bool:
    return len(pl.stages) == 1 and bool(pl.stages[0].argv) and pl.stages[0].argv[0] == "cd"


def run_parsed(
    pipelines: list[Pipeline], *, command: str, env: dict[str, str], cwd: str | Path,
    timeout: float,
) -> tuple[int, str, str]:
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
    from defender.runtime import box

    frame = sys.stdin.buffer.read()
    try:
        pipelines = box.decode_request(frame)
    except ValueError as e:
        print(f"box entrypoint: undecodable request frame: {e}", file=sys.stderr)
        return 2

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
