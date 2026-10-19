# Learning changes

- Read `../docs/learning-loop.md` before changing loop shape, questioner/judge/curator prompts, or the lesson mechanism. `../docs/learning-development.md` describes queues, branch replay, and retrieval.
- Branch orchestration lives in `branch/`; questioner prompts in `branch/questioner/`; grading in `judge/`; curators in `author/`; catalog curation in `leads/`.
- Keep findings about defender conduct separate from findings about world construction; they feed different queues and lesson corpora.
- Use `lead_repository.py` for lead/query reads and joins, and the existing shared stage-assembly helpers for model stages.
- The drain orchestrator owns git operations; spawned product agents do not commit. Preserve the worktree and batch boundaries.
- Changes to shared artifacts must account for runtime writers/readers and integration scenarios, not only the learning consumer.
