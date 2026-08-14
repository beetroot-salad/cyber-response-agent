
from __future__ import annotations

import contextlib
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from defender.hooks._cmd_segments import tokenize

_OPERATOR_CHARS = frozenset("<>|&;")
_PIPELINE_SEPARATORS = frozenset({"||", "&&", ";"})

#: The tokens that leave a line INCOMPLETE when they close it — `A |`, `A &&` need the next
#: line to mean anything. `;` is deliberately absent: `A;` is a finished command.
_DANGLING_CONNECTORS = frozenset({"|", "&&", "||"})


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
            # close holding only its left side and the `|` would vanish — `A | ; B` runs B on
            # /dev/null exactly as #854 F-22's line-boundary spellings did. The check lives
            # here, where a pipeline closes, rather than in `feed_token` where the two
            # existing halves live, because the token that exposes it is not always a
            # connector: `;` is not in `_DANGLING_CONNECTORS` (the leading-`;` carve-out
            # below), and `A | 2>/dev/null` empties its right side with no separator at all.
            # Stating the invariant once — no pipeline banks a stage list whose last `|` had
            # an empty right side — covers every spelling instead of naming the tokens that
            # can follow a pipe, which is the enumeration that let this survive #854 (#884).
            raise UntokenizableCommand(
                "pipeline token '|' has nothing to its right"
            )
        self.end_stage()
        if self.cur_stages:
            self.pipelines.append(Pipeline(self.pending_connector, self.cur_stages))
            self.cur_stages = []
            self.pending_connector = next_connector

    def feed_token(self, toks: list[str], i: int) -> int:
        t, n = toks[i], len(toks)
        if t in _DANGLING_CONNECTORS and not self.cur_argv:
            # A connector with no COMPLETE command to its left. Within a line that is a bash
            # syntax error; ACROSS lines (`A\n| B`) it is the half of #854 F-22 where the
            # token was dropped and `A | B` silently became `A ; B` — a second stage on
            # /dev/null, reported as the last pipeline's rc.
            #
            # `cur_stages` is deliberately NOT consulted: `A | | B` reaches here with a stage
            # already banked, and the second `|` is just as dropped as a leading one (it used
            # to collapse into the single pipe `A | B`, which bash rejects outright) (#884).
            #
            # Same set as the trailing check, and for the same reason: a leading `;` drops
            # NOTHING (`A` then `; B` already means the two commands it runs), so refusing it
            # would deny a harmless command under a reason — this module's docstring, the
            # gate's UNTOKENIZABLE_REASON, SKILL.md — that names `|`/`&&`/`||` and not `;`.
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
            if self.cur_argv and self.cur_argv[-1] == "2" and i + 1 < n and toks[i + 1] == "/dev/null":
                self.cur_argv.pop()
                self.cur_stderr = "devnull"
                return i + 2
            raise BashExecError(f"unexpected redirect token in validated command: {t!r}")
        if t == ">&":
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
    builder = _PipelineBuilder()
    for line in inner.split("\n"):
        toks = tokenize(line)
        if toks is None:
            raise UntokenizableCommand("untokenizable command reached the executor")
        i, n = 0, len(toks)
        while i < n:
            i = builder.feed_token(toks, i)
        if toks and toks[-1] in _DANGLING_CONNECTORS:
            # The other half of #854 F-22: `A |` / `A &&` closing a line. There is no shell
            # to join the lines, so the connector would be dropped and the implicit `;` below
            # would run the next line as an independent command.
            raise UntokenizableCommand(
                f"pipeline/connector token {toks[-1]!r} closes a line with nothing to its right"
            )
        builder.end_pipeline(";")
    if builder.pending_connector in _DANGLING_CONNECTORS:
        # An `&&`/`||` that banked its LEFT pipeline and never got a right one, so the
        # connector was consumed and then dropped. The line-end check above cannot see this:
        # the line does not END with the connector, it ends with whatever bare `;` follows it
        # (`A && ;`), which the carve-out lets through. Without this the module refuses `A &&`
        # but accepts `A && ;` and runs A — an inconsistency with no rule behind it.
        #
        # Found by #897's differential sweep against `bash -n`, which is the entire argument
        # for that test: this spelling is in nobody's list of things to check.
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
