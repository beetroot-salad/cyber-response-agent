# Runtime changes

- `../SKILL.md` defines runtime-agent behavior; inspect the affected code and the current approved design before changing it.
- The driver is in `driver/`; permission checks are in `permission/`; role definitions and grants originate in `../agents.py`.
- The close-time review gate (`close_tool.py`, `challenge_gate.py`, `review/`) is a write-time gate, not a driver phase. Preserve its fail-closed behavior.
- Artifact invariants must hold for host writers and publication paths as well as model tool writes. Use the existing schema and guarded I/O seams; do not infer an artifact is valid merely because one write path validates it.
- Read `../docs/runtime-development.md` when changing artifacts, observability, logging, or their readers. Use `../learning/lead_repository.py` for lead/query joins rather than reparsing artifacts.
- For permission changes read `../docs/runtime-gates.md`; for loop or lesson-retrieval changes read the relevant parts of `../docs/learning-loop.md`.
