
from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path


#: The operator runs `feed_token` REFUSES outright. Narrower than `_SHLEX_PUNCTUATION` on
#: purpose, and the gap is `(`/`)`: a run containing one is not refused here — it falls
#: through to `cur_argv` and crosses as a literal argv word. `parse('echo $(whoami)')` is
#: `['echo', '$', '(', 'whoami', ')']` and `parse('cat <(id)')` is `['cat','<(','id',')']`,
#: both accepted, and `test_540_exec_seam.py` pins that shape deliberately. What keeps them
#: off an authorised argv is `permission/bash.py::_stage_unsafe` — a layer up, not here — but
#: read what it actually tests before relying on it: `t in ("(", ")")` is EXACT equality, so a
#: paren FUSED into a wider operator run is not refused by it. `cat <(id)` is caught by its
#: own trailing `)` token; `cat <(id)|grep y` is not — the `|` is swallowed into a `)|` token
#: that neither this module's `set(t) <= _OPERATOR_CHARS` refusal nor `_stage_unsafe` rejects,
#: and the pipeline separator disappears. It fails closed at `_claim`/`_in_scope` today (no
#: grant pattern admits a `)|` operand), which is a second gate and not this claim. Nothing
#: expands either way, because no shell re-parses downstream.
_OPERATOR_CHARS = frozenset("<>|&;")
_PIPELINE_SEPARATORS = frozenset({"||", "&&", ";"})

#: The characters that END a word and start an operator run — `shlex`'s own punctuation set
#: from the `punctuation_chars=True` lexing this module used to do, kept verbatim so the
#: scanner splits words exactly where that lexer split them. WIDER than `_OPERATOR_CHARS`:
#: `(`/`)` break a word here without being operators the grammar accepts, and `feed_token`
#: does NOT refuse them — see `_OPERATOR_CHARS` for where that refusal actually lives. Kept
#: wide regardless, because splitting the word is what the lexer this replaced did, and the
#: shape downstream is pinned on it.
_SHLEX_PUNCTUATION = frozenset("();<>|&")

#: The characters that SEPARATE words — BASH's blank set, which is space and tab. (`\n` is
#: carried for completeness only: `parse` splits the command on it before a line reaches the
#: scanner, so it is never seen here.)
#:
#: Taken from bash rather than from `shlex`, and that is the whole of the distinction. Two
#: wider sets are both wrong, in the same direction:
#:
#:   * `str.isspace()` is a Unicode predicate — true for `\x0b`, `\x0c`, `\x1c`-`\x1f`,
#:     `\x85`, NBSP and every Unicode space, none of which bash splits on.
#:   * `shlex.whitespace` is `' \t\r\n'`, which is NOT bash's IFS: bash's default IFS is
#:     space/tab/newline and carries no `\r`. `cat a\rb` is ONE word to bash.
#:
#: Splitting on any of them cuts a word bash keeps whole — `cat 'a\xa0b'` reaching the
#: executor as `['cat', 'a', 'b']`, or `w a\r2>/dev/null` losing its `2` operand and having
#: its redirect read as an fd-2 one when bash redirects stdout. That is #955 F-50's own defect
#: (an argv that is not the one the model wrote, authorised by a gate reading the rewritten
#: one) one character class over, so the oracle here has to be bash and not the lexer this
#: scanner replaced. `test_955_bash_fd_prefix.py::_NOT_SHELL_BLANKS` pins every member.
_BLANKS = frozenset(" \t\n")

#: `_BLANKS` as a string, built ONCE — for `str.strip`, and for any membership test outside
#: this module. (It fed `shlex.whitespace` on main; #959 M2 removed the lexer this module used
#: to resolve a word with, so there is nothing left here to configure.)
#:
#: PUBLIC, and that is the point rather than a convenience. Every defect in #955 is two rules
#: where the code needs one: an fd read off the token stream vs the raw text, a word boundary
#: read off `str.isspace()` vs bash's set, a trim in the gate that undid the scanner's own
#: narrowing one call before it ran. A private name reached across a module boundary is how
#: the NEXT copy gets written instead of imported, so anything in this tree that has to know
#: where a bash word ends imports this and does not spell it again.
#:
#: `sorted` rather than a literal because `frozenset` iteration order is not a guaranteed
#: property; hoisted out of `_word_value` because building it per WORD put a `sorted()` on the
#: slow path of every quoted argument the gate sees.
BLANKS = "".join(sorted(_BLANKS))

#: Bash's comment character. It begins a comment only where a WORD begins — at the start of
#: the line, after a blank, or after an operator run — and only unquoted: `a#b` is the word
#: `a#b`, `'#'` and `\#` are the character. Everything from there to the end of the line is
#: not part of the command at all.
#:
#: Decided against the raw text for the same reason the fd prefix is (#955 F-50): by the time
#: `shlex` has resolved a word to its value, a `#` that stood for itself and a `#` that opened
#: a comment are one token. Reading it off the token stream is what made
#: `cat run/a.json # ; rm -rf run/b` TWO stages here and ONE command plus a comment in bash —
#: the executor running an argv the model's own text says is commented out, and the gate
#: authorising that one. A `#` INSIDE a word stays an ordinary character: `_word_value` simply
#: passes it through, where the lexer this replaced had to be told to (`commenters = ""`).
_COMMENT = "#"

#: The only fd this executor knows how to route. Bash's IO_NUMBER admits any digit run; every
#: other one is refused, so the scan only has to recognise this one.
_STDERR_FD = "2"

#: The two fd-2 redirects this executor implements: `operator -> (required target, stderr mode)`.
#: A table rather than two near-identical arms, because the condition they share is #955 F-50's
#: own fix and one copy of it is one place it can be got wrong.
_FD2_REDIRECTS = {">": ("/dev/null", "devnull"), ">&": ("1", "stdout")}

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
    r"""One word's raw text — quotes and escapes intact — resolved to the value it stands for.

    A hand-rolled unquoter over a span that HAS no unquoted whitespace and no unquoted operator
    (`_scan` bounds it that way), so it never needs a notion of whitespace and can never
    re-split what it is handed — the whole of #959 M2. `None` on a dangling escape or a quote
    that never closes within the span (both indicate a line that `_literal_mask` already
    accepted as balanced overall but whose OWN token turned out not to be — practically
    unreachable given that guarantee, kept as a defensive `None` rather than an exception).

    CHOSEN OVER CONFIGURING `shlex`, which is how main closed the same defect: pinning
    `lex.whitespace = BLANKS` stops the re-split too, and both readings were live at the merge.
    What decides it is bash, not speed. Inside double quotes bash resolves `\$` to `$` and a
    backslash-escaped backtick to a backtick; `shlex` hands both back with the backslash still
    on. A gate whose thesis is "mean what bash means" cannot resolve a word by a rule bash does
    not use. That difference is a verdict change on two spellings no corpus row carries, and it
    is enumerated here rather than left to be discovered.

    THE FAST PATH IS WHAT MAKES THE SPEED CLAIM TRUE, and it was missing when this landed. A
    span carrying none of the three characters that mean anything here — `'`, `"`, `\` — already
    IS its value, and three C-level `in` scans say so; the loop below costs one Python
    iteration, one `str` allocation and one list append PER CHARACTER to reach the same answer.
    82% of the spans in this change's own frozen corpus are quote-free, and `parse` runs on
    every Bash tool call, so the path this skips is the common one.

    MEASURED over every span of that corpus, three readings, so nobody has to take the
    adjective: `shlex` with its own fast path 0.237s, this loop WITHOUT one 0.184s, this loop
    with one 0.044s. The omission was not a regression — it was still marginally ahead — but
    the "~3x faster" this file used to claim was measured on a hand-picked span mix that was
    half quoted, where the real one is a fifth. Against `shlex` the honest numbers are ~1.3x
    without the fast path and ~5x with it."""
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
    # `_OPERATOR_CHARS`, NOT `_SHLEX_PUNCTUATION`: the wider set carries `(`/`)`, which end a
    # word for the scanner but are not characters an IO_NUMBER may follow in any line bash
    # will run. Reading them as one made `w a)2>/dev/null` an fd-2 redirect — the `2` popped
    # off argv and stderr rerouted — on a line `bash -n` refuses outright, which is the
    # accept-what-bash-rejects direction `test_bash_differential_897.py` exists to close.
    return mask[at - 2] and (before in _BLANKS or before in _OPERATOR_CHARS)


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
        if mask[i] and line[i] in _BLANKS:
            i += 1
            continue
        if mask[i] and line[i] == _COMMENT:
            # A word STARTS here (blanks are consumed above, and every other arm consumes its
            # whole token), so an unquoted `#` at this position is bash's comment and the rest
            # of the line is not command text. Dropping it here rather than refusing the line
            # is what bash does, and it keeps the operator that PRECEDES a comment answerable
            # by the arms that already handle it: `A |` / `A &&` / `2>` left dangling by the
            # comment still fail, as they do in bash, because the token they need is gone.
            break
        if mask[i] and line[i] in _SHLEX_PUNCTUATION:
            j = i
            while j < n and mask[j] and line[j] in _SHLEX_PUNCTUATION:
                j += 1
            if _is_fd_prefix(line, mask, i, toks):
                # Retroactively mark the PRECEDING bare digit as the fd component — it is the
                # digit's glue to this operator that makes it an IO_NUMBER, not a property of
                # the operator token itself, which stays plain `OPERATOR` either way.
                #
                # Constructed rather than `dataclasses.replace`d: `replace` re-derives the field
                # list and re-enters `__init__` through a kwargs splat for 2x the cost, on a
                # function that runs for every `2>` on every Bash tool call. Same frozen record
                # either way — a NEW Token, never a mutation.
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
        if t in _FD2_REDIRECTS:
            # ONE arm for both spellings, because the test they share is the one #955 F-50 got
            # wrong, and two copies of it is two places a later correction can be applied to
            # only one — which is the shape the original defect already had.
            #
            # The PRECEDING token carrying `fd-operator` kind is the whole of the fd test;
            # `cur_argv[-1] == "2"` only confirms the token stream agrees with the raw text
            # about which word that was. Testing the TOKEN alone (as both arms did until
            # #955 F-50) reads an ordinary numeric operand as an fd: `head -c 2 >/dev/null` was
            # accepted and ran `head -c` — the gate's answer turning on an argument's VALUE,
            # and the executor running a command the model did not write.
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
    """The pipelines `cmd` names — the model's raw command text, byte for byte: there is no
    wrapper step, and no second function a caller must apply first (#959 D1/C3, #971). Every
    PHYSICAL LINE is scanned on its own and each stage becomes a bare argv.

    NO WORD IS PARSED SPECIALLY HERE. `bash -c '<payload>'` used to be recognised and its
    payload extracted — the last of the two folds, after the `timeout` prefix went in #971 —
    and both are gone for the same reason: a fold DELETES TEXT AHEAD OF THE DECISION, so every
    way of mis-reading the shape is a way of WIDENING what the gate allows, while a
    pass-through can only refuse. `bash` and `sh` are ordinary ungranted words now; the lane's
    capability reason answers them like any other program it does not have. What is still
    special is punctuation, never a keyword: the connectors, the two stderr redirects, the
    newline that ends a line, and the quoting."""
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
