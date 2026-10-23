"""#1108 P4: the agent knowledge this repo shipped in its product tree before P4 moved it to
each tenant (O1, O-U5) — the exact bytes of base `0f62791e`'s `defender/lessons/`,
`defender/skills/gather/queries/` and `defender/skills/tacit-knowledge/`, laid out as an agent
half (`lessons/`, `skills/...`) under `tests/fixtures/pre-p4-shipped/agent/`.

Tests whose subject is an engine (frontier recall and scoring, the scaffold rule, the tacit
registry's gate) exercised over that real content read it here; no run, tenant or drain reads
it. A committed copy, not `git show 0f62791e:...`: CI checkouts are shallow."""
from __future__ import annotations

from pathlib import Path

SHIPPED_AGENT = Path(__file__).resolve().parents[2] / "fixtures" / "pre-p4-shipped" / "agent"
LESSONS = SHIPPED_AGENT / "lessons"
CATALOG = SHIPPED_AGENT / "skills" / "gather" / "queries"
TACIT_REGISTRY = SHIPPED_AGENT / "skills" / "tacit-knowledge" / "registry.yaml"
