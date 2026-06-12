"""PydanticAI runtime driver for the defender investigation loop.

Phase A of the `claude -p` → PydanticAI migration: functionality parity,
implementation simplification. See defender/docs/runtime-pydanticai-migration.md
and the slice plan. The agent gets generic tools (bash/read_file/write_file/
edit_file) gated by a single in-process permission decision (`permission.py`)
that reuses the existing `hooks/_cmd_segments.py` taxonomy + the invlang
validator — same gates as the `claude -p` runtime, run in-process instead of as
subprocess hooks.
"""
