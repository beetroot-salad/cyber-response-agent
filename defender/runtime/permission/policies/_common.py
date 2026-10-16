
from __future__ import annotations

from pathlib import Path

from defender.run_repository import (
    GATHER_RAW_SHAPE,
    alert_input_shape,
    gather_summaries_shape,
)
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
    run_dir: Path, defender_dir: Path, *, raw: bool, tenant_agent: Path | None = None
) -> PathShapes:
    run, dfn = run_dir.resolve(), defender_dir.resolve()
    corpus = "|".join(_CORPUS_SUBDIRS)
    shapes = [
        # One segment: every file at the run root, nothing below. So a stream that replays
        # another agent's context (the wire log) must not sit at the root, or MAIN and GATHER
        # can both read it; it lives under `<run>/wire_logs/`.
        under(run, SEG),
        under(run, gather_summaries_shape(SEG)),
        # The alert and its record: the one directory down the input directory holds (#1222).
        # A shape of its own, so `wire_logs/` stays out of reach.
        under(run, alert_input_shape()),
    ]
    if raw:
        # The shared shape, not a local spelling: it must match the lead-id validators, or
        # gather is denied its own payload.

        shapes.append(under(run, GATHER_RAW_SHAPE))
    bases = (dfn,) if tenant_agent is None else (dfn, tenant_agent.resolve())
    shapes.extend(under(base, rf"(?:{corpus})(?:/{SEG})*/{SEG}\.md") for base in bases)
    return PathShapes(shapes)


def reader_grants(run_dir: Path, defender_dir: Path, *, raw: bool, tenant_agent: Path | None = None) -> tuple[Grant, ...]:
    scope = read_shapes(run_dir, defender_dir, raw=raw, tenant_agent=tenant_agent)
    return (
        Grant(program="cat", pattern=program_shape("cat"), scope=scope),
        *(Grant(program=v, pattern=program_shape(v)) for v in STDIN_VIEWERS),
        *(
            Grant(program=s, pattern=program_shape(s))
            for s in sorted(set(NON_ADAPTER_SHIMS) | set(_INERT))
        ),
    )


__all__ = ["read_shapes", "reader_grants"]
