#!/usr/bin/env python3
"""The CLI plumbing every spec-graph checker shares — argv parsing, stdio encoding, and
graph loading — so the family's exit-code contract (0 clean, 1 findings, 2 could-not-look)
rests on one implementation instead of a copy per script."""
from __future__ import annotations

import sys
from collections.abc import Iterable
from pathlib import Path

import yaml


def utf8_stdio() -> None:
    """Emit findings (and WARN lines) as utf-8 regardless of the ambient locale. The
    finding text carries non-ASCII (em-dashes), so a non-utf-8 stdout/stderr — a C-locale
    runner, a Windows console — would raise UnicodeEncodeError on the very `print` that
    reports a finding. A gate that cannot emit its finding reads as clean to a caller that
    checks exit code but loses the traceback (the #588/#589 class, output side).
    reconfigure exists on the standard TextIOWrapper streams; guard for a replaced one."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8")


def parse_argv(
    argv: list[str],
    *,
    valued: Iterable[str] = frozenset(),
    multi: Iterable[str] = frozenset(),
    flags: Iterable[str] = frozenset(),
) -> tuple[dict, list[str]]:
    """(options, positionals) over the family's flat argv shape. A valued option consumes
    the next token (missing value → None); a multi option appends each non-None value; a
    flag sets True; everything else is positional. Keys in the returned dict drop the
    leading dashes (`--config` → `"config"`); defaults are None / [] / False."""
    valued, multi, flags = set(valued), set(multi), set(flags)
    opts: dict = {o.lstrip("-"): None for o in valued}
    opts.update({o.lstrip("-"): [] for o in multi})
    opts.update({o.lstrip("-"): False for o in flags})
    positionals: list[str] = []
    it = iter(argv)
    for a in it:
        if a in valued:
            opts[a.lstrip("-")] = next(it, None)
        elif a in multi:
            v = next(it, None)
            if v is not None:
                opts[a.lstrip("-")].append(v)
        elif a in flags:
            opts[a.lstrip("-")] = True
        else:
            positionals.append(a)
    return opts, positionals


def load_graph(path: Path) -> dict:
    """A spec graph off disk, empty-tolerant, shape-guarded."""
    graph = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(graph, dict):
        # Valid YAML, wrong shape. Without this the first `.get` raised AttributeError,
        # which a main catching only YAML/OS errors turns into exit 1 ("found findings")
        # behind a traceback instead of 2 ("could not read").
        raise TypeError(f"top level is a {type(graph).__name__}, not a mapping")
    return graph
