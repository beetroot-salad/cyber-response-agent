# Handoff — implement the curator GLM port from its spec

You are picking up a **write-tests spec** and turning it into shipped, CI-green code via
`/write-code-from-spec`. The spec (tests + spec_graph) is committed and reviewed; the
implementation does not exist yet. Everything you need is in this repo.

## Resume in 60 seconds
```bash
# from /workspace (main checkout)
git checkout spec/authors-glm-tests            # or: git worktree add <path> spec/authors-glm-tests
git log --oneline -3                            # 09db395 = the spec (tests + spec_graph)
```
- **Design/spec of record:** `defender/tests/spec_graph_curator-glm-port.yaml` — READ IT FIRST. It is
  the resolved demand list + structure + the gate outcomes. The four `defender/tests/test_curator_glm_*.py`
  files are its executable form.
- **Base:** `origin/main @ 0184af4` (#546 `bind`/`compile_policy` landed — assume that machinery exists).
- **Run the spec suite** (note the worktree PYTHONPATH gotcha — the shared `.venv` editable-install
  pins to the *main* checkout, so prepend the tree you're testing):
  ```bash
  PYTHONPATH=$(pwd) /workspace/defender/.venv/bin/python -m pytest \
    defender/tests/test_curator_glm_engine.py \
    defender/tests/test_curator_glm_policy.py \
    defender/tests/test_curator_glm_dispatch_dlq.py \
    defender/tests/test_curator_glm_survival.py -q
  ```
  Today: engine+policy ERROR at collection (missing `curator_engine`); dispatch fails with `KeyError`;
  survival's characterization tests pass. **Done = all four files green** (plus the existing
  `test_author_*` / `test_orchestrate_thresholds` / `test_loop` suites stay green).

## What you're building (and why)
Port the four learning-loop lesson curators off `claude -p` (claude-sonnet-4-6) to **in-process
PydanticAI GLM-5.2@low**, mirroring the lead-author port (#543, `leads/lead_author_engine.py` — your
template). The four curators, each `run_batch(*, hold_committed, paths) -> int`:

| Curator | Entry | Corpus | Invoke seam |
|---|---|---|---|
| A findings | `author/lessons/run.py` | `defender/lessons/` | inline `invoke_agent` (run.py:228) |
| B actor | `author/malicious_actor/run.py` | `defender/lessons-actor/` | `curator.py:invoke_curator_agent` |
| C env-benign | `author/benign_actor/run.py` | `defender/lessons-environment/` | `curator.py:invoke_curator_agent` |
| D env-adversarial | `author/benign_actor/env.py` | `defender/lessons-environment/` (SHARED with C) | `curator.py:invoke_curator_agent` |

## Two decisions already made (do NOT re-litigate — they shaped the tests)
1. **Corpus navigation = flat per-curator bash allowlist.** In-process there is NO Glob/Grep tool.
   `decide_bash` keys ONLY on `AgentPolicy.bash_allow` (BashGrammar.viewers + `_common._CORPUS_SUBDIRS`
   are irrelevant when you hand-build the policy, exactly like the actor/judge/lead-author). So each
   curator's `bash_allow` is a flat anchored tuple: `ls`/`grep`/`cat` on ITS OWN corpus + its
   forward-check `python3 <verifier>` + a scoped single-draft `rm`. **Do NOT touch `_CORPUS_SUBDIRS`**
   (it feeds the live MAIN/GATHER runtime reader — widening it is capability creep). The bash lane does
   no `resolve()`, so patterns must reject `..` textually (copy the lead author's
   `_rm_skills_pattern` anti-`..` seg), and a hand-built viewer pattern gets NO auto secret-denylist —
   its corpus-anchored operand is the sole containment.
2. **Failure contract = batch-granular DLQ.** rc mapping is forced to `RunUnprocessable → AuthorError
   → rc 2` (invoke_agent returns a dict, so there is no rc-124 lane like the lead author's). On top of
   that, add a dead-letter queue so a poison batch quarantines after N attempts instead of retrying
   every tick forever. Systemic faults (`FatalConfigError`/`StageAbort`) still exit 2, never dead-lettered.

## Implementation checklist (each item is pinned by ≥1 test; names must match the spec_graph)
- [ ] **New `defender/learning/author/curator_engine.py`** (mirror `leads/lead_author_engine.py`):
  - `AgentRole.CORPUS_AUTHOR` (add to `runtime/agent_role.py`); `CORPUS_AUTHOR_DEF = AgentDefinition(
    role=CORPUS_AUTHOR, model, effort, tools=ToolSet(read=True, bash=BashGrammar(), write=True))`
    registered in `runtime/agents.AGENTS`.
  - `CuratorDeps(AgentDeps)` with `role = AgentRole.CORPUS_AUTHOR` and classmethod
    `for_run(run_dir, repo_root, corpus_dir, verifier_scripts)` (positional, required — worktree
    `defender_dir = repo_root/"defender"`, per-spawn policy).
  - `_corpus_author_policy(corpus_dir, verifier_scripts) -> AgentPolicy`: `write_allow=(build_write_allow(
    corpus_dir, suffix=".md"),)`; `bash_allow` = flat anchored (corpus-anchored `ls`/`grep`/`cat`,
    per-curator `python3 <verifier>` like the actor's `_script_pattern`, single-draft `rm`). Reads via
    `decide_read` defaults. Every other capability bit off. Build it directly — NOT `compile_policy`/`bind`.
  - `run_curator_stage(*, system_prompt_file, batch_id, user_prompt, corpus_dir, verifier_scripts,
    repo_root, learning_run_dir, model, effort, request_limit, timeout, log,
    source_key=config.source_first_party_key, run_author=_run_curator_pydantic) -> dict`:
    source key FIRST (FatalConfigError propagates), `run_stage(require_output=True)`, parse
    `AUTHOR_RESULT:` from the returned TEXT via `runner.extract_marked_result` + `json.loads`
    (missing/bad → AuthorError), map `RunUnprocessable`/parse-error → `AuthorError`, let
    `FatalConfigError`/`StageAbort` propagate; return the parsed dict. Keep `_run_curator_pydantic`
    (the `run_author` default; takes `make_model` + `prompt_path`, mirror `_run_author_pydantic`).
- [ ] **Rewrite the invoke seams** to call `run_curator_stage` and still return the AUTHOR_RESULT dict:
  `author/lessons/run.py:invoke_agent` (A) and `author/curator.py:invoke_curator_agent` (B/C/D). KEEP
  the `invoke_agent` cfg-field seam and the entire transaction envelope
  (`run_batch`/`_author_to_author`/`verify_agent_state`/`commit_corpus`/`rotate_queue`) unchanged.
- [ ] **Config (`core/config.py`):** `AUTHOR_MODEL`/`AUTHOR_ACTOR_MODEL`/`AUTHOR_ENV_MODEL` default
  `"glm-5.2"`; `AUTHOR_EFFORT`/`AUTHOR_ACTOR_EFFORT`/`AUTHOR_ENV_EFFORT` `"low"`; NEW
  `AUTHOR_REQUEST_LIMIT`/`AUTHOR_ACTOR_REQUEST_LIMIT`/`AUTHOR_ENV_REQUEST_LIMIT` (default **250** —
  subprocess had NO cap; a small cap kills a multi-file curator); NEW `LEARNING_AUTHOR_MAX_ATTEMPTS`
  (default **3**, mirror `LEAD_AUTHOR_MAX_RETRIES`).
- [ ] **Dispatch fix (`core/orchestrate.py`):** `_CURATOR_MODULES["author_actor_env"] =
  "defender.learning.author.benign_actor.env"`.
- [ ] **DLQ:** NEW `attempts` int field on the curator queue rows + a `deadletter.jsonl` sidecar per
  queue (under `_pending`). The envelope bumps `attempts` on a per-run authoring fault and, at
  `LEARNING_AUTHOR_MAX_ATTEMPTS`, moves the batch's rows to `deadletter.jsonl` and out of the active
  queue (the move-aside shape of `_quarantine_marker`, at row level). Batch-granular. Do NOT bump on
  systemic / lock-contention / dirty-corpus.
- [ ] **State-root:** pin `DEFENDER_LEARNING_STATE_DIR` into the in-process agent's bash-tool env (the
  in-process twin of `curator_agent_env`) so the forward-check subprocess resolves the real source
  bundle, not the worktree's empty `runs/` (the #425 mode). `run_common.run_env` does not carry it today.
- [ ] **Trace:** per-spawn distinct trace path `{batch_id}.{pid}.trace.jsonl` in persistent shared
  state (a pending/state dir), NOT the throwaway worktree (RequestLogger opens truncate → collisions).
- [ ] **Prompts:** rewrite the four `author/*/prompt.md` to enumerate via bash `ls`/`grep` instead of
  the absent `Glob`/`Grep` tools (else the whole-corpus fold pass silently dies green → duplicate lessons).
- [ ] **Teardown:** after the port `runner.invoke_claude_print`/`curator_allowed_tools`/
  `curator_agent_env` have no prod callers (remove/retire the `claude -p` transport); KEEP
  `resolve_verifier_python` (the four curators still build `python3 <verifier>` grants).

## Seam names the tests assume (match exactly or the tests won't bind)
`curator_engine.run_curator_stage` (signature above), `curator_engine._run_curator_pydantic`,
`AgentRole.CORPUS_AUTHOR`, `CORPUS_AUTHOR_DEF` in `AGENTS`, `CuratorDeps.for_run(run_dir, repo_root,
corpus_dir, verifier_scripts)`, `_corpus_author_policy(corpus_dir, verifier_scripts)`,
`config.AUTHOR_REQUEST_LIMIT`/`AUTHOR_ACTOR_REQUEST_LIMIT`/`AUTHOR_ENV_REQUEST_LIMIT`,
`config.LEARNING_AUTHOR_MAX_ATTEMPTS`, queue-row field `attempts`, a `*deadletter*.jsonl` sidecar under
`_pending`, env key `DEFENDER_LEARNING_STATE_DIR`. Bash operands are repo-relative
(`defender/<corpus>/…`); verifier scripts are passed as worktree-absolute `Path`s.

## Gotchas / CI gates
- **Worktree PYTHONPATH** (above) — or you test the main checkout, not your changes.
- **`lint_unsafe_jsonl_io`**: the dispatch+DLQ and engine tests read jsonl via raw `json.loads`. Under
  `defender/` this gate fails on hand-rolled json readers — use `read_jsonl_rows`/`append_jsonl` in the
  IMPL (the DLQ sidecar read/write especially), and in the tests either switch to the helper or add
  `# lint-jsonl-io: ok` on the offending line spans.
- **`lint_monkeypatch`**: use DI seams (cfg fields, `source_key`/`run_author`/`make_model` kwargs),
  never `monkeypatch.setattr` (the spec tests already follow this — keep the impl's own tests, if any, to it).
- **`lint_unanchored_default`**: anchor new knob defaults at the boundary, not with in-body
  `x = x if x is not None else DEFAULT`.
- **`/verify`** before shipping: drive a real curator drain end-to-end (a real GLM smoke via
  `FIREWORKS_API_KEY`), not just the suite — the port's runtime surface is the in-process spawn.

## Deferred (NOT part of this PR, but flag it in the PR body)
The sonnet→glm@low A/B on lesson-authoring QUALITY is the port's real risk (this drops the loop's
highest-judgment WRITER to glm/low). The eval harness is `defender/evals/harness.py` + `scenarios/`.
Not a code change here — a measurement to run before trusting the port in production.

---
Spec authored via `/write-tests` (grounding → 4 adversarial lenses + frontier strong author → address
diff → gate R0–R5 → 2 human forks). Full trail in the commit `09db395` and the spec_graph's `handoff:`
section. Memory: `curator-glm-port-spec`.
