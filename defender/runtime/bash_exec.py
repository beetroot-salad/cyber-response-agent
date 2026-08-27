
from __future__ import annotations

import contextlib
import dataclasses
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path


_OPERATOR_CHARS = frozenset("<>|&;")
_PIPELINE_SEPARATORS = frozenset({"||", "&&", ";"})

#: The characters that END a word and start an operator run — kept verbatim so the scanner
#: splits words exactly where the old `punctuation_chars=True` lexer split them. WIDER than
#: `_OPERATOR_CHARS`: `(`/`)` break a word here without being operators the grammar accepts.
#: `feed_token` does NOT refuse them — its operator arm tests `set(t) <= _OPERATOR_CHARS`,
#: which they are not in — so they land in argv as ordinary words, exactly as before. That is
#: inert here (no stage is run through a shell), and the guard that cares is
#: `permission/bash._stage_unsafe`, which reads argv. Kept verbatim so this scanner and that
#: guard see the same token stream they always did; it is not a licence to widen the set.
_SHLEX_PUNCTUATION = frozenset("();<>|&")

#: The whitespace that ENDS a word — bash's own set, not `str.isspace()`, and NOT `\r` (#959
#: M6): bash does not split on a carriage return, and a `\r` inside or at the edge of an
#: operand used to be silently torn off by this constant. `str.isspace()` and a stray `\r` both
#: tore `cat /tmp/a\xa0b` / `cat /tmp/a\rb` into two operands and ran a command the model did
#: not write, on a path the gate then scope-checked instead of the one that was asked for.
_WORD_SEPARATORS = frozenset(" \t\n")


def is_word_separator(char: str) -> bool:
    """This module's own answer to "is `char` a word separator" — the one place that decides,
    so a caller elsewhere in the tree (`permission/bash._is_blank`, #959 M4/F1) asks THIS
    rather than re-deriving membership in `_WORD_SEPARATORS` on its own."""
    return char in _WORD_SEPARATORS


#: The only fd this executor knows how to route. Bash's IO_NUMBER admits any digit run; every
#: other one is refused, so the scan only has to recognise this one.
_STDERR_FD = "2"

#: The tokens that leave a line INCOMPLETE when they close it — `A |`, `A &&` need the next
#: line to mean anything. `;` is deliberately absent: `A;` is a finished command.
_DANGLING_CONNECTORS = frozenset({"|", "&&", "||"})

#: A token's KIND — the three cases the grammar turns on. `2>` is bash's IO_NUMBER redirect;
#: a spaced `>` is a redirect of stdout after the ordinary word `2`, and both arrive with the
#: same TEXT (#955 F-50), so the kind is what a reader must use to tell them apart. `FD_OPERATOR`
#: marks the bare digit token itself (`2`) that a following `>`/`>&` is GLUED to — the operator
#: that follows stays plain `OPERATOR` — because the two still arrive as separate tokens (their
#: raw spans and values differ) and it is the digit's own glue to what follows that makes it an
#: IO_NUMBER rather than an ordinary word.
WORD = "word"
OPERATOR = "operator"
FD_OPERATOR = "fd-operator"


@dataclass(frozen=True)
class Token:
    """One token of a scanned line: its resolved VALUE, the START/END offsets of its raw
    spelling in the line (code-point offsets, quoting and glue intact), and its KIND.

    One frozen record per token (#959 M1) — not three index-aligned collections, where
    alignment between the token stream and the raw text was exactly what #955 F-50 was about."""

    value: str
    start: int
    end: int
    kind: str


def _literal_mask(line: str) -> list[bool] | None:
    """Which characters of `line` stand as themselves — unquoted, unescaped, and not a quote
    or escape character of the syntax. `None` if a quote never closes.

    Everything `_scan` decides rests on this: whether an operator character IS an operator, and
    whether it was glued to the word on its left. Both are facts about the raw text, and both
    are gone by the time a word has been resolved to its value (#955 F-50)."""
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
    index just past its closing quote — or `None` if it never closes. Split out of
    `_word_value` purely to keep that function's branch count within the lint budget; the
    escaping rule (only `"`, `\\`, `$` and a backtick are meaningful after a backslash here) is
    the one POSIX double-quote carve-out the single-quote and bare-word cases don't need."""
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
    """One word's raw text — quotes and escapes intact — resolved to the value it stands for.

    A hand-rolled unquoter over a span that HAS no unquoted whitespace and no unquoted operator
    (`_scan` bounds it that way), so it never needs a notion of whitespace and can never
    re-split what it is handed — the whole of #959 M2. `None` on a dangling escape or a quote
    that never closes within the span (both indicate a line that `_literal_mask` already
    accepted as balanced overall but whose OWN token turned out not to be — practically
    unreachable given that guarantee, kept as a defensive `None` rather than an exception)."""
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
    to its left that STARTS its own word.

    The last clause is not decoration: bash reads `foo2>` as the word `foo2` redirecting
    stdout, not as a redirect of fd 2, and a quoted `"2">` the same way. Only a bare digit run
    standing alone is the fd."""
    if at == 0 or not mask[at - 1] or line[at - 1] != _STDERR_FD:
        return False
    if not toks or toks[-1].value != _STDERR_FD:
        return False
    if at == 1:
        return True
    before = line[at - 2]
    return mask[at - 2] and (before in _WORD_SEPARATORS or before in _SHLEX_PUNCTUATION)


def _scan(line: str) -> list[Token] | None:
    r"""The line's tokens, as one frozen record per token (#959 M1): resolved value, the
    start/end offsets of its raw spelling, and its kind.

    Structure is decided against the RAW TEXT and only the values go through `_word_value`,
    which is the whole of #955 F-50. Lexing the line with a punctuation-splitting shlex lexer —
    as this module used to — hands back a stream in which the two questions the grammar turns
    on can no longer be asked:

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
    toks: list[Token] = []
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
                # Retroactively mark the PRECEDING bare digit as the fd component — it is the
                # digit's glue to this operator that makes it an IO_NUMBER, not a property of
                # the operator token itself, which stays plain `OPERATOR` either way.
                toks[-1] = dataclasses.replace(toks[-1], kind=FD_OPERATOR)
            toks.append(Token(line[i:j], i, j, OPERATOR))
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
        toks.append(Token(word, i, j, WORD))
        i = j
    return toks


class BashExecError(Exception):
    pass


class UntokenizableCommand(BashExecError):
    pass


class NarrowedReason(UntokenizableCommand):
    """An `UntokenizableCommand` whose message IS the caller-facing reason, verbatim — used for
    the one narrowing (#959 F5) whose obligation is to explain itself rather than fall back to
    the generic parse-failure text `permission.bash.UNTOKENIZABLE_REASON` names everywhere
    else. Every other `UntokenizableCommand` in this module carries a short internal message
    for `test_959_frozen_baseline.py`'s arm sweep; the gate collapses those to the one constant."""


#: The `-c` argument sent to `bash`/`sh` may not contain a newline — there is no shell here to
#: run it as a script, so a multi-statement payload is refused rather than silently flattened
#: into one pipeline per line (#959 M3 + F5). Named as its own reason, not folded into the
#: generic parse-failure text, because F5's obligation is that the refusal EXPLAINS the
#: newline: a model that sent this payload yesterday got an allow, and needs to know what to
#: fix now — a generic "could not be parsed" sends it looking for the wrong mistake.
NEWLINE_IN_WRAPPER_ARGUMENT_REASON = (
    "Blocked: the `-c` argument given to `bash`/`sh` contains a newline (a `\\n` inside the "
    "quoted string). There is no shell here to run it as a multi-line script — collapse the "
    "payload onto ONE physical line before sending it, exactly as every other command here "
    "must be one line."
)


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

    def feed_token(self, tokens: list[Token], i: int) -> int:
        tok, n = tokens[i], len(tokens)
        t = tok.value
        if tok.kind == WORD:
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
            # The PRECEDING token carrying `fd-operator` kind is the whole of the fd test;
            # `cur_argv[-1] == "2"` only confirms the token stream agrees with the raw text
            # about which word that was. Testing the TOKEN alone (as both arms did before
            # #955 F-50) reads an ordinary numeric operand as an fd: `head -c 2 >/dev/null` was
            # accepted and ran `head -c` — the gate's answer turning on an argument's VALUE,
            # and the executor running a command the model did not write.
            if (
                i > 0 and tokens[i - 1].kind == FD_OPERATOR
                and self.cur_argv and self.cur_argv[-1] == _STDERR_FD
                and i + 1 < n and tokens[i + 1].value == "/dev/null"
            ):
                self.cur_argv.pop()
                self.cur_stderr = "devnull"
                return i + 2
            raise BashExecError(f"unexpected redirect token in validated command: {t!r}")
        if t == ">&":
            if (
                i > 0 and tokens[i - 1].kind == FD_OPERATOR
                and self.cur_argv and self.cur_argv[-1] == _STDERR_FD
                and i + 1 < n and tokens[i + 1].value == "1"
            ):
                self.cur_argv.pop()
                self.cur_stderr = "stdout"
                return i + 2
            raise BashExecError(f"unexpected redirect token in validated command: {t!r}")
        if t and set(t) <= _OPERATOR_CHARS:
            raise BashExecError(f"unexpected operator token in validated command: {t!r}")
        self.cur_argv.append(t)
        return i + 1


def _check_multiline_c_argument(value: str) -> None:
    """`value` (a resolved `-c` argument) contains a newline. If every LINE of it scans cleanly
    on its own, the newline itself is the only problem, and the refusal must explain it
    (#959 F5). If some line is independently broken (an unclosed quote, say), that failure is
    the real one and earns the generic parse-failure reason instead — the two must never be
    conflated (SB4)."""
    for line in value.split("\n"):
        if _scan(line) is None:
            # The SAME message the ordinary per-line scan failure raises (below, in `parse`) —
            # deliberately not a distinct one: this is the identical failure (an unclosed quote,
            # a dangling escape), just reached one call earlier because a `-c` argument is
            # checked before its lines are handed to the per-line loop.
            raise UntokenizableCommand("untokenizable command reached the executor")
    raise NarrowedReason(NEWLINE_IN_WRAPPER_ARGUMENT_REASON)


def _wrapper_span(tokens: list[Token]) -> str:
    """`tokens[0]` is a `bash`/`sh` token (#959 M3). Returns the inner command text when this
    is a complete, WHOLE-COMMAND `<wrapper> -c '<one argument>'` shape — the argument's own
    RESOLVED VALUE, re-scanned as the inner command (never a raw slice: a `-c` argument's raw
    span includes its quotes, and re-scanning THAT would parse the quotes into the program
    name). Raises `UntokenizableCommand` for every other shape a `bash`/`sh` first token can
    reach — a bare wrapper, a stray word after the argument, a second wrapper, a script path,
    `-lc`, a flag between the wrapper and `-c` — never falling through to treat it as an
    ordinary, ungranted word: none of those is a wrapper bash would run either.

    Takes the TOKENS and nothing else: the raw command text is deliberately out of scope here,
    so the "never a raw slice" rule above is enforced by the signature rather than by this
    paragraph."""
    if len(tokens) == 3 and tokens[1].kind == WORD and tokens[1].value == "-c":
        value = tokens[2].value
        if "\n" in value:
            _check_multiline_c_argument(value)
        return value
    raise UntokenizableCommand("bash/sh wrapper did not resolve to a single -c argument")


def _fold_wrapper(cmd: str) -> tuple[str, list[Token] | None]:
    """The wrapper recognition step (#959 M3, C1, C4): applied ONCE, at the top level, over
    the WHOLE (possibly multi-line) raw command — never inside the per-line loop, and never
    re-applied to the text it extracts (a fixed point would turn `bash -c 'bash -c "echo hi"'`
    into an allow, a deny->allow widening nobody enumerated).

    Returns the text that should actually be parsed — the extracted `-c` argument for a
    recognised `bash`/`sh` wrapper, or `cmd` unchanged when the command does not start with one
    — paired with the token stream ALREADY SCANNED for that text when the two are the same scan
    `parse` would do next (an unchanged single-line command, which is nearly every command), or
    `None` when they are not. Handing the stream back is what keeps the fold from costing a
    second full pass over every command that has no wrapper at all.

    A `timeout N` PREFIX IS NOT RECOGNISED HERE, and deliberately (#971). Folding one deleted
    text AHEAD OF the decision, so every way of mis-reading a prefix was a way of widening what
    the gate allows — `timeout\n5 cat x` and `timeout --foreground cat x` both reached an allow
    for a command real `timeout` never runs. And what the fold bought was only the APPEARANCE of
    honouring the bound: the prefix was discarded, never executed (there is no `timeout` binary
    in the box), and the command ran under the runtime's own deadline with nothing said. So
    `timeout` is now an ordinary ungranted word — no grant matches it, the lane's capability
    reason answers on the same turn, and no text is rewritten before the decision is made.
    Pass-through cannot widen; a fold can, which is the whole of the argument."""
    tokens = _scan(cmd)
    if tokens is None:
        # The whole text failed to scan — some quote never closes ANYWHERE. Let the normal
        # per-line parse discover and report exactly that, rather than answering it here.
        return cmd, None
    if tokens and tokens[0].kind == WORD and tokens[0].value in ("bash", "sh"):
        return _wrapper_span(tokens), None
    return cmd, _reusable(cmd, tokens)


def _reusable(cmd: str, tokens: list[Token]) -> list[Token] | None:
    """`tokens` if scanning `cmd` as ONE line is the same question `parse`'s per-line loop will
    ask, `None` otherwise. A newline makes them different questions: `_scan` treats it as a word
    separator and `parse` splits on it first, so a multi-line command has to be re-scanned line
    by line."""
    return None if "\n" in cmd else tokens


def parse(cmd: str) -> list[Pipeline]:
    """The pipelines `cmd` names — the model's raw command text, wrapper and all: there is no
    second function a caller must apply first (#959 D1/C3). Folds the wrapper once at the top
    (#959 M3) and then scans each physical line of whatever text results."""
    inner, scanned = _fold_wrapper(cmd)
    builder = _PipelineBuilder()
    tokens: list[Token] | None
    for line in inner.split("\n"):
        if scanned is not None:
            # The fold already scanned this exact text as one line and handed the stream back;
            # CONSUMED here, so a later line can never read a stream that is not its own.
            tokens, scanned = scanned, None
        else:
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
            # `A |` / `A &&` closing a line. There is no shell to join the lines, so the
            # connector would be dropped and the implicit `;` below would run the next line
            # as an independent command.
            raise UntokenizableCommand(
                f"pipeline/connector token {tokens[-1].value!r} closes a line with nothing to "
                "its right"
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
