
from __future__ import annotations

CAT_BOOL = "AbeEnstTuv"

WC_BOOL = "clLmw"

GREP_BOOL = "nicovwxHhsEFabz"
GREP_LIST = "lL"

TAIL_HEAD_BOOL = "cnqvz"
DIGITS = "0123456789"


def bundle(letters: str, *, drop: str = "") -> str:
    kept = "".join(c for c in letters if c not in drop)
    return rf"-[{kept}]+"
