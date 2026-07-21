from __future__ import annotations

from pathlib import Path


def extract_case_entities(investigation_path: Path) -> str:
    if not investigation_path.is_file():
        return ""
    seen: list[str] = []
    in_block = False
    for line in investigation_path.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s.startswith(":V prologue.vertices"):
            in_block = True
            continue
        if in_block:
            if not s or s.startswith(":") or s.startswith("```"):
                break
            cols = s.split("|")
            if len(cols) >= 3 and cols[0].strip().startswith("v-"):
                tok = cols[2].strip()
                if tok and tok not in seen:
                    seen.append(tok)
    return ",".join(seen)
