
from __future__ import annotations

from pathlib import Path

from defender.hooks._cmd_segments import NON_ADAPTER_SHIMS
from defender.runtime.permission.grant import (
    SEG,
    PathShapes,
    STDIN_VIEWERS,
    Grant,
    program_shape,
    under,
)

_CORPUS_SUBDIRS = ("lessons", "skills", "examples")

_INERT = ("echo", "true")


def read_shapes(
    run_dir: Path, defender_dir: Path, *, raw: bool
) -> PathShapes:
    run, dfn = run_dir.resolve(), defender_dir.resolve()
    corpus = "|".join(_CORPUS_SUBDIRS)
    shapes = [
        # `SEG` is ONE segment, so this admits every file at the run ROOT and nothing below
        # it — which makes "where a run-dir stream is written" a gate decision, not a layout
        # preference. A stream that replays another agent's context (the wire log: gather's
        # tool returns and MAIN's transcript both go through one `RequestLogger`) must NOT
        # sit at the root, or this shape hands it to MAIN and to GATHER alike. That one lives
        # under `<run>/observe/` for exactly this reason — see `_run_paths.OBSERVE_DIR`, and
        # `tests/test_wire_log_read_gate.py`, which pins both agents denied.
        under(run, SEG),
        under(run, rf"gather_summaries/{SEG}"),
    ]
    if raw:
        shapes.append(under(run, r"gather_raw/l-\d+/\d+\.json"))
    shapes.append(under(dfn, rf"(?:{corpus})(?:/{SEG})*/{SEG}\.md"))
    return PathShapes(shapes)


def reader_grants(run_dir: Path, defender_dir: Path, *, raw: bool) -> tuple[Grant, ...]:
    scope = read_shapes(run_dir, defender_dir, raw=raw)
    return (
        Grant(program="cat", pattern=program_shape("cat"), scope=scope),
        *(Grant(program=v, pattern=program_shape(v)) for v in STDIN_VIEWERS),
        *(
            Grant(program=s, pattern=program_shape(s))
            for s in sorted(set(NON_ADAPTER_SHIMS) | set(_INERT))
        ),
    )


__all__ = ["read_shapes", "reader_grants"]
