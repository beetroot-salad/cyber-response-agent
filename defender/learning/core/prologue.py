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
                typ, cls = cols[1].strip(), cols[2].strip()
                # The `class` cell carries the slash-tuple ONLY (skills/invlang/SKILL.md);
                # every consumer parses these tokens as `type:class`, so qualify here.
                #
                # A cell holding a `,` is dropped with the half-filled rows: `,` is the
                # DELIMITER of the string this builds, so an unresolved class carrying an
                # enumerated candidate set (`class={a/b/c, d/e/f}`) would split across it,
                # truncating the real entity and fabricating a second from the tail. An
                # unresolved slot cannot satisfy a selector anyway.
                if not typ or not cls or "," in typ or "," in cls:
                    continue
                tok = f"{typ}:{cls}"
                if tok not in seen:
                    seen.append(tok)
    return ",".join(seen)
