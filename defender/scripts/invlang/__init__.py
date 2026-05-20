"""Defender-side invlang loader + query helpers.

Standalone — does not import from soc-agent. Tolerates the surface drift
in defender-emitted investigation.md (unescaped `|` in attrs, extra empty
hypothesis cells, missing `⟂` in resolutions).
"""
