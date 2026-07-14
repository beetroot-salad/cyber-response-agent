"""One cell, one line: the flatten every TSV emitter shares (#596/#614).

Several tools print ``<field>\\t<field>`` rows consumed via ``splitlines()`` +
``split("\\t")`` (trace_lesson, lessons_fm, lessons_env_retrieve,
lessons_actor_index). Any value landing in a cell — LLM-authored descriptions
and criteria, hook-written timestamps, even filenames — can carry a character
that forges a row or a column there, and the historical ``\\t``/``\\n``-only
replace idiom is provably insufficient: ``str.splitlines`` also breaks on
``\\r``, ``\\x0b``, ``\\x0c``, ``\\x1c``-``\\x1e``, ``\\x85``, U+2028 and U+2029.
One breaker set, one flatten, so the emitters can't drift apart again.
"""
from __future__ import annotations

# Every char ``str.splitlines`` treats as a line boundary, plus tab.
_BREAKERS = dict.fromkeys(map(ord, "\t\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"), " ")


def flatten_cell(value: str) -> str:
    """One cell, one line: every line/column breaker becomes a single space."""
    return value.translate(_BREAKERS)
