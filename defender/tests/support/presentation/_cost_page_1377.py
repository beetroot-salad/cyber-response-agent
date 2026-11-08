"""The run page's cost, as a reader sees it (#1377 r7): the headline and the cost bar's segments. NO test functions."""
from __future__ import annotations

import re


def headline(html: str) -> str:
    """The text of the page's headline cost (`$1.2345`, `at least $1.2345` or `unknown`)."""
    found = re.search(r'ts-cost">(.*?)</', html, flags=re.S)
    assert found is not None, "no headline cost"
    return found.group(1).strip()


def dollars(text: str) -> float:
    found = re.fullmatch(r"(?:at least )?\$([0-9.]+)", text)
    assert found is not None, f"the headline reads {text!r}, not a dollar figure"
    return float(found.group(1))


def at_least(text: str) -> bool:
    return text.startswith("at least ")


def segments(html: str) -> dict[str, float]:
    """Every cost-bar segment (a `cb-seg` titled "<name> · $v · p%") by lower-cased name."""
    return {name.lower(): float(v)
            for name, v in re.findall(r'class="cb-seg"[^>]*title="([^"]*?) · \$([0-9.]+) · ', html)}


def segment_titles(html: str) -> list[str]:
    """The dollar text of each cost-bar segment's title, as written (`$0.1234`)."""
    return re.findall(r'class="cb-seg"[^>]*title="[^"]*? · (\$[0-9.]+) · ', html)
