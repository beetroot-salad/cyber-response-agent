#!/usr/bin/env python3
from __future__ import annotations




def parse_verdict(text: str, *, error_prefix: str) -> str:
    for line in reversed(text.strip().splitlines()):
        s = line.strip().strip("*`# ").strip()
        if s.upper().startswith("VERDICT:"):
            v = s.split(":", 1)[1].strip().strip("*`. ").upper()
            if v in ("GOOD", "BAD"):
                return v
            raise SystemExit(f"{error_prefix}: unrecognized verdict {v!r}")
    raise SystemExit(
        f"{error_prefix}: no VERDICT line found in verifier output:\n" + text[-1000:]
    )

