"""Build DP / DB / DH dense variants from V1.6 baseline.

Splices V1.6 lines 1..152 (preamble through §Story authoring) with a variant-
specific §Output format section, then V1.6 lines 301..end (§Disciplines tail).

Run after editing `_dense_outputs.py`. No CLI args.
"""

from __future__ import annotations

from pathlib import Path

from _dense_outputs import COMMON_PREFACE, OUTPUT_FORMAT_DB, OUTPUT_FORMAT_DH, OUTPUT_FORMAT_DP

VARIANTS_DIR = Path(__file__).parent / "variants"
BASELINE = VARIANTS_DIR / "V1.6.md"

# 1-indexed inclusive line ranges, derived from the V1.6 layout.
PREAMBLE_END = 152   # last line of "## Story authoring"
TAIL_START = 301     # first line of "## Disciplines (reference tail)"


def build(name: str, output_format: str) -> None:
    src = BASELINE.read_text().splitlines(keepends=True)
    preamble = "".join(src[:PREAMBLE_END])
    tail = "".join(src[TAIL_START - 1 :])
    composed = preamble + COMMON_PREFACE + output_format + "\n" + tail
    out = VARIANTS_DIR / f"{name}.md"
    out.write_text(composed)
    print(f"wrote {out} ({len(composed)} bytes)")


if __name__ == "__main__":
    build("DP", OUTPUT_FORMAT_DP)
    build("DB", OUTPUT_FORMAT_DB)
    build("DH", OUTPUT_FORMAT_DH)
