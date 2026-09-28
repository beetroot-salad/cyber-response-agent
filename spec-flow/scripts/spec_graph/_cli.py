#!/usr/bin/env python3
"""CLI plumbing shared by the spec-graph checkers: argv parsing, stdio encoding, and graph
loading. Exit-code contract: 0 clean, 1 findings, 2 could not look."""
from __future__ import annotations

import sys
from collections.abc import Iterable
from pathlib import Path

import yaml


def utf8_stdio() -> None:
    """Emit output as utf-8 regardless of locale: findings contain non-ASCII, and a C-locale
    stdout would raise on the very `print` reporting a finding. Replaced streams may lack
    `reconfigure`."""
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
    """(options, positionals). A valued option consumes the next token (missing → None); a
    multi option appends each value; a flag sets True; everything else is positional. Keys
    drop leading dashes; defaults are None / [] / False."""
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


#: The libyaml C loader when available (same safe subset, ~8x faster; every checker parses the
#: whole multi-MB graph corpus), else the pure-Python one.
_LOADER = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


def load_graph(path: Path) -> dict:
    """A spec graph off disk, empty-tolerant, shape-guarded."""
    graph = yaml.load(path.read_text(encoding="utf-8"), Loader=_LOADER) or {}
    if not isinstance(graph, dict):
        # Valid YAML, wrong shape: raise a type mains catch as "could not read" (exit 2).
        raise TypeError(f"top level is a {type(graph).__name__}, not a mapping")
    return graph
