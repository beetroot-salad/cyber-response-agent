from __future__ import annotations

_BREAKERS = dict.fromkeys(map(ord, "\t\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"), " ")


def flatten_cell(value: str) -> str:
    return value.translate(_BREAKERS)
