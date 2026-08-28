# defender/

**Status: experimental. PoC stage, learning-loop first.**

`defender/` is the alert-triage agent: a runtime loop that investigates one alert end-to-end (`run.py`, driven by the in-process PydanticAI driver — not a Claude Code plugin), plus an offline **learning loop** under `defender/learning/` where most iteration happens. It runs against the `playground-v2/` environment; per-system knowledge lives under `defender/skills/`. Investigations record reasoning in the invlang on-disk format (`++/+/-/--` vocabulary; `skills/invlang/`).

**`defender/SKILL.md` is the runtime spec.** Design rationale lives in `defender/docs/` — start with `learning-loop.md` before changing the loop shape, the actor/judge/oracle prompts, or the lessons mechanism. When a doc and the code disagree, **the code wins**.

## Vocabulary — what the shorthand refers to

| Term | Meaning / home |
|---|---|
| **the runtime** / **the driver** / **the main loop** | `runtime/driver.py` — the main-agent loop (ORIENT → PLAN → GATHER → ANALYZE → REPORT), tools in `runtime/tools.py` |
| **the gate** / **permissions** | `runtime/permission/` — the single in-process deny-by-default gate (bash + file reads/writes). Design notes: `docs/runtime-gates.md`. Audit CLI: `scripts/policy_cli.py` (`defender-policy show\|explain`, operator-only) |
| **the review gate** / **the reviewer** | `runtime/challenge_gate.py` (harness + routing) + `runtime/review/` (projections, role prompts, reply contract), dispatched from `runtime/close_tool.py`. **Not a loop phase** — a write-time gate every *confident* close passes before it commits; `inconclusive` bypasses it. Two blind lenses (`support`, `ablation`) + a `composer`, roster in `REVIEW_ROLES`. Fails closed |
| **gather** | the per-lead data-access subagent — `skills/gather/` (prompt + query templates), dispatched from `runtime/tools.py`, calls the typed `query` tool (`runtime/query_tool.py`) |
| **the actor** (malicious / benign) | `learning/pipeline/malicious_actor/`, `learning/pipeline/benign_actor/` — adversarial / FP-hunting story writers |
| **the oracle** | `learning/pipeline/oracle/` — synthesizes the telemetry the actor's story would have produced |
| **the judge** | `learning/pipeline/judge/` — classifies outcome (`caught\|survived\|undecidable\|incoherent\|skip-passthrough`), emits findings; prompts `malicious.md`/`benign.md` |
| **the curators** / **authors** | `learning/author/` — fold queued findings into lessons (`author/lessons/`, `author/malicious_actor/`, `author/benign_actor/`), each gated by the **forward-check** (`author/verify_forward/`) |
| **the lead-author** | `learning/leads/` — offline curation of the gather query catalog + system skills |
| **lessons** | `defender/lessons/` (+ `lessons-actor/`, `lessons-environment/`) — authored by the loop, retrieved by two pushes — the PLAN-time `defender-lessons` shim keyed on the alert signature, and the `append_block`/`fix_row` block keyed on the invlang frontier (`scripts/lessons/lessons_frontier.py`, #919). Grep, no index |
| **the agents / registry** | `defender/agents.py` — role → `AgentDefinition` (each brings its own grants + deps); `runtime/agent_definition.py` is the seam |
| **the frontend** / **the visualizations** | rendered HTML, not a web app: `scripts/visualize/` emits `transcript.html` (judge view) + `runtime.html` (run inspection) per run; `learning/frontend/build.py` emits the standalone `lessons.html` posture view |
| **evals** | `defender/evals/` — measurement layer (scores, not CI): `held_out.py` is the north-star metric (the frozen-actor replay and the judge A/B are retired); see `evals/README.md` |

## Layout (one line each)

```
defender/
  SKILL.md          # runtime agent spec (the loop's system prompt)
  run.py            # entrypoint: investigate one alert; post-steps render HTML + enqueue learning
  agents.py         # agent registry
  run_common.py     # shared run-dir + post-step helpers
  runtime/          # in-process PydanticAI engine: driver, tools, permission/, providers/, bash_exec, observe, orient, compaction
                    #   branch.py — the turn-N resume (#920): which message may be branched from, and where the fork lands
                    #   close_tool.py + challenge_gate.py + review/ — the write-time review gate on every confident close
  hooks/            # gate LOGIC imported as libraries (lead claim, descriptors, budget, lesson-load) — no longer Claude Code hooks
  skills/           # invlang, gather, handbook, advisory + per-system references (elastic/ identity/ cmdb/ ticket/ change-mgmt/ threat-intel/ host-state/)
  scripts/          # adapters/, gather_tools/, visualize/, lessons/, case_history/, policy_cli.py, pricing.py, workspace_map.py
  learning/         # offline loop: loop.py (orchestrator CLI), lead_repository.py (THE read/join surface),
                    #   _prompt.py + _pydantic_stage.py (the shared stage-assembly pair, used by every engine),
                    #   pipeline/, author/, core/, leads/, branch/, tickets/, ops/, frontend/
                    #   branch/ is the turn-N branch (#920): ledger.py records every response the estate served
                    #   with the decision behind it; estate/ is what a sibling world queries through
  evals/            # metrics + harness-on-the-harness (scenarios/)
  lessons/          # checked-in lesson corpus
  fixtures/         # alert.json (+ optional gather_raw payloads) used as runtime inputs
  run-transcripts/  # curated transcripts of past real-alert runs
  tests/            # THE test tree — every collected suite lives here, none in the source dirs (#720).
                    #   *.py       learning-loop invariants
                    #   e2e/       hermetic replay (test_replay_*, run with -m e2e)
                    #   learning/  the loop orchestrator (test_loop.py)
                    #   evals/     the measurement tooling's unit tests
  docs/             # design docs (learning-loop.md, runtime-gates.md, system-skill-shape.md, ...)
```

The runtime agent has no unit tests — it's evaluated by running real alerts through `run.py` and reviewing the run dir, plus the e2e replay suite.

## Running it

```bash
cd defender && uv venv .venv && uv pip install --python .venv/bin/python -e '.[dev]'   # bootstrap (entrypoints re-exec into .venv themselves)
python3 defender/run.py <alert.json>                 # one investigation → run dir under /tmp/defender-runs/; --no-learn skips enqueue
python3 defender/learning/loop.py <run_dir>          # LEARN one run; --learn-drain / --author-drain / --lead-author-drain are the workers
```

**Running the suite as root fails four tests that are not broken.** The
accounting-failure tests in `tests/test_budget_enforcement_631.py`
(`test_one_failed_accounting_write_costs_one_call_of_overshoot` and its three
siblings) simulate a failing write by chmod'ing the run dir to `r-x`, and root
ignores permission bits — so the write lands and the test asserts "the failed
write landed anyway". CI runs non-root and they pass there. Confirm against CI
before chasing them; don't "fix" the tests.

## Run dir + the two tables

Each run writes to `$DEFENDER_RUNS_BASE/{run_id}/` (default `/tmp/defender-runs/`): `alert.json` (read-only input), `provenance.json` (the commit the run was made against and whether that tree was dirty — the only file here that is a fact ABOUT the run rather than content it produced, stamped by the host at run-dir creation before any agent exists; see `_provenance.py` for what a sha does and does not pin, and note it is deliberately absent from the model-facing workspace map), `investigation.md` (invlang work log), `report.md` (YAML frontmatter — `disposition: benign|false-positive|inconclusive|malicious` — is the headline the learning loop parses; the same frontmatter also carries the review gate's `outcome`/`cause`/`failure_kind`, which today only the visualizer reads), `review_record.{turn}.json` + `review_{role}_trace.jsonl` (the review gate, one record per close *attempt*), `wire_logs/llm_requests.jsonl` + `tool_trace.jsonl` (observability — `wire_logs/llm_requests.jsonl` is the run's ONE wire log: the main agent, every gather subagent as `gather:{lead_id}`, and every review stage as `review:{lens}` write through the same `RequestLogger`, which is what makes all three priceable; it sits under `wire_logs/` rather than at the run root because MAIN's and GATHER's run-dir read shape `under(run, SEG)` is ONE segment, so the subdirectory is what keeps a log holding gather's raw payloads and MAIN's transcript unreadable by both of them — `_run_paths.WIRE_LOG_DIR`, which also records why that argument covers those two roles and no others), `transcript.html` + `runtime.html`, and the **two append-only tables**, written live during the run:

| Table | Where | Key |
|---|---|---|
| **leads** | `gather_raw/{lead_id}.lead.json` (written via `claim_lead` — id reuse raises) | `lead_id` (the `:L` invlang row id) |
| **queries** | `executed_queries.jsonl` (captured in-process by the `query` tool); raw payloads by-ref at `gather_raw/{lead_id}/{seq}.json` | `(lead_id, seq)`, FK `lead_id` |

The single read/join surface is `learning/lead_repository.py` (`joined` / `actor_view`) — consumers never re-parse the artifacts. `query_id` is `{system}.{kebab-name}`, matching a template under `skills/gather/queries/` when one fit (`ad-hoc` = one-off probe); `params` are bound values. A `∅.`-prefixed `query_id` is a **sentinel**: a writer-only record of something that never reached a system (a refused repeat, a failed reducer shim), which `joined` splits onto `JoinedLead.sentinels` so that `JoinedLead.queries` means only what the defender ran — `.rows` is the remerge, for the readers that mean the table (#841). Schema may still break during the PoC phase.

## Learning loop (the headlining experiment)

Off-process: `run.py` enqueues a marker; workers drain independently, each committing from its own git worktree off `origin/main` with one PR per batch — the loop is the sole committer, spawned agents run no git. Per case: disposition selects direction (`benign` → hunt the FN, `malicious` → hunt the FP, `inconclusive` → both, `false-positive` → neither: it is a verdict about the rule, not the entity, so it trains nothing — `directions.UNTRAINED_DISPOSITIONS`) → **actor** writes a candidate story (may SKIP) → **oracle** synthesizes its telemetry → **judge** classifies + emits findings → queued findings accumulate until the **curators** fold them into lessons, each edit gated by the same-case **forward-check** regression (BAD = the lesson would flip a correctly-resolved case → revert). Lessons feed back into the runtime twice: at PLAN time via `defender-lessons`, and on every write that moves the investigation's open set via `scripts/lessons/lessons_frontier.py`.

## Where to make changes

| To change... | Edit... |
|---|---|
| Runtime loop shape, phase discipline, gather dispatch ergonomics | `defender/SKILL.md` |
| Per-system reference (what data a system holds, sample queries) | `defender/skills/{system}/SKILL.md` |
| Gather subagent behavior, query templates, raw payload contract | `defender/skills/gather/` |
| How the two tables are read/joined | `defender/learning/lead_repository.py` |
| Actor / oracle / judge prompts + drivers | `defender/learning/pipeline/<stage>/` (each holds `prompt.md` + `run.py`) |
| Curator / forward-check prompts + drivers | `defender/learning/author/<curator>/` |
| Lessons corpus | `defender/lessons/*.md` (hand-edits fine if they match the schema) |
| Eval metrics / scenarios | `defender/evals/` |
| Permission gate / grants | `runtime/permission/` + each agent's `bash_shapes` in `defender/agents.py`; secrets denylist in `runtime/bash_policy.json` |

## Conventions

- Runs live outside the repo (`/tmp/defender-runs/`) so transcripts stay out of git.
- **In the devcontainer, set `DEFENDER_RUNS_BASE=/workspace/.defender-runs`** (gitignored) — the default `/tmp/defender-runs` is not a path this container shares with the docker daemon, so the box cannot resolve its bind source and `start_box` fails with a C46/DooD `BoxFault`.

## Lint gates

Every gate below lives at `scripts/lint/lint_*.py` (repo root) and **blocks CI**. Almost all scope to `defender/` alone — the text-I/O gate also covers `spec-flow/scripts/`, and the stale-reference scan works off the PR's whole diff. Run one directly: `defender/.venv/bin/python scripts/lint/<lint>.py`.

They are **ratcheted**, not absolute: each carries a checked-in `<lint>_baseline.json` (`scripts/lint/_baseline.py`) recording today's findings, so a gate fails only on a fingerprint that is not already in its baseline. That makes the baselines part of the contract, and there are two different reasons to touch one — keep them apart:

- A **pre-existing** finding moved or got refingerprinted by an unrelated refactor → regenerate with the lint's `--update-baseline` and say so in the PR.
- A **new** finding your change introduced → fix it, or suppress the one line with the gate's own comment and a reason. Baselining it is how a gate stops meaning anything; don't.

Most gates take a line suppression of the form `# lint-<tag>: ok — <reason>`. The reason is not decoration — for several of these the reason is the only thing a later reader has to judge whether the exemption still holds.

### One seam already exists — hand-rolling it is the failure

| The gate wants | Instead of hand-rolling | Suppress with |
|---|---|---|
| Any `git` argv through the `defender._git` facade | your own `subprocess` + rc check + porcelain parsing | `# lint-git: ok` |
| Per-line JSONL through `_io.read_jsonl_rows` / `_io.append_jsonl` | your own append-mode handle or line loop (a torn last line crashes the drain) | `# lint-jsonl-io: ok` |
| Markdown frontmatter through `_frontmatter.split_frontmatter` / `parse_frontmatter` / `parse_frontmatter_or_none` | your own fence arithmetic | `# lint-frontmatter: ok` |
| Writes into a box-writable tree (a run dir, the drain worktree) through the alias-refusing `_io.write_guarded` / `guarded_mkdir` / `open_guarded` | a plain write — the model may have planted a symlink there | `# lint-unguarded-tree-write: ok` |
| Reads out of that same tree through `_run_paths.artifact_file` / `artifact_dir`, which `lstat` | a plain stat/read/copy, which follows the link the write side refuses | `# lint-tree-read-follows-link: ok` |
| Prompt sections already `defender._untrusted.wrap`-ed when they reach `stage_user_message` | interpolating a section into the prompt yourself | `# lint-stage-frame: ok` |
| `encoding="utf-8"` pinned on every text read and write | bare `read_text()` / `open(p)` / `write_text(s)`, which use the ambient locale | `# lint-text-io: ok` |
| An optional input resolved once at the boundary (see below) | re-coalescing the default in the body | `# lint-default: ok` |

### Test discipline

| The gate wants | Why | Suppress with |
|---|---|---|
| Collaborators injected through the config/deps seams, not `monkeypatch.setattr` | attribute-patching couples the test to import scope; the seams exist for this | `# lint-monkeypatch: ok` |
| A test's expected value computed some way *other* than the git query the code under test runs | an oracle that re-runs production's own command cannot disagree with it — every input the primitive is wrong on is invisible by construction | `# lint-oracle: ok` |

### Shape gates — each is a bug class that already shipped once

| The gate wants | Suppress with |
|---|---|
| Membership in someone else's closed vocabulary answered by *that module's* normalizer, not re-derived locally (#785: one parser, six interpreters, three of which disagreed) | `# lint-vocabulary: ok` |
| No branching on ONE literal key of someone else's keyed gate table — the table's other keys then have no reader at that boundary (#879) | `# lint-half-table: ok` |
| A function that DECLARES a shape not returning raw `json.loads` / `safe_load` output — `Any` satisfies every annotation, so mypy stays green over the lie | `# lint-parse: ok` |
| In the invlang tokenizer and projector, no row leaving a loop without either a `ParseWarning` or a landing (#876) | `# lint-row-drop: ok` |
| `registry.verbs(system)[verb]` inside the fault seam — the production registry lazily imports the adapter there, so a broken adapter unwinds the stage with no row (#672/#678) | `# lint-verb-dispatch: ok` |
| `dataclasses.fields()`, never `__dataclass_fields__` — the raw mapping also holds `ClassVar`/`InitVar` pseudo-fields, so splatting it raises (#965) | `# lint-dataclass-fields: ok` |
| One home for a helper, not the same `def` in two or more modules (jscpd's token-clone gate is structurally blind to 1–5 line copies) | `# lint-dup: ok` |
| A render list and a key set spelled as two values (see below) | `# lint-keyset: ok` |
| A mixed collection classified exhaustively, with the residue reported (see below) | `# lint-selection: ok` |
| Every writer of `investigation.md` / `report.md` to meet their schema (see below) | `# lint-artifact-gate: ok` |

### Hygiene

| The gate wants | Suppress with |
|---|---|
| No vendor- or environment-specific tokens outside the carved-out systems-skill dirs — `defender/` ships vendor-neutral | `# lint-shippable: ok` |
| No hardcoded `/workspace` or `/tmp/defender` paths in shipping code; no bare `python3 x.py` in a hook `command:` (it gets system python); a hook matcher naming *both* `Task` and `Agent`, since production dispatches as both | `# lint-hygiene: ok` |
| No reference left behind to a symbol or file the PR's own diff removed — the missed-callsite-after-rename class. Diffs against `$STALE_REF_BASE` (default `origin/main`) | `# lint-stale-ref: ok` |
| No newly-introduced dead code (wraps vulture) | baseline only |
| Committed spec graphs passing the spec-flow checkers (`lint`/`gate`/`binds`/`claims`) — they used to run only at authoring time, so graphs merged carrying their findings | baseline only |

CI also runs a jscpd Python-duplication gate at a `--threshold 3` ratchet over today's ~1.4%, which blocks a PR that meaningfully grows copy-pasted Python.

### Four that get a paragraph, because the fix is not obvious from the failure

- **Anchor a default in one place.** Resolve an optional input once at the boundary, thread it inward non-`Optional`; don't re-coalesce in the body (`x = x if x is not None else DEFAULT`). Prefer `is not None` over `or`.
- **A render list is not a key set.** A sequence that records *what happened in what order* and a key set that names *the distinct things* are different values — spelling them with one name hides the confusion at every call site. Where both are wanted, derive them separately at the one place the list is built (`dict.fromkeys(...)` keeps the order) and give the deduped one its own name. Walking the raw list to patch a table already keyed by it patches one bucket per appearance (#956).
- **Read invlang fences through one helper.** `skills/invlang/parser.scan_fences` is the only thing that decides which bytes of an `investigation.md` are invlang content; it hands back what the fences ORPHAN (`orphaned_headers`) alongside what they hold, so a reader cannot take the content and drop the complement without saying so. Three readers used to derive that split independently and all three dropped it in silence — content outside a fence never reaches the tokenizer, so it cannot even raise a `ParseWarning`, and a run's whole PLAN section parsed to an empty companion that every hypothesis-side rule then passed vacuously (#932). The same rule applies one level down: selecting from a mixed cell with `[t for t in xs if SOME_ID_RE.fullmatch(t)]` drops whatever matches neither namespace, which is how a qualified `h-001.ac1` in a `:L findings` `tests` cell reached no rule at all — classify exhaustively and report the residue. The suppression must state where the complement goes.
- **Every writer of the two model-authored artifacts meets their schema.** `_artifact_schema.py` owns what a well-formed `investigation.md` / `report.md` IS, and `permission.decide_write` applies it to every write a MODEL makes — which is what made "a committed investigation parses" true, and true only of the verbs the agent writes through. Three writers sat outside that set: the harness seeding lead-0's declaring row before MAIN's first turn (#964), the turn-N branch seeding a sibling's whole document from a fence-boundary prefix (a valid source does not guarantee a valid prefix — the reference rules are order-independent), and `close_investigation`, the one verb that PUBLISHES, which validated the report it wrote and never the companion it published (#961). The general shape is worth recognising on sight: **an invariant enforced at a gate, and then believed of the artifact** — a gate can only promise something about the paths that run through it. The gate asks co-occurrence, not dataflow: it cannot tell whether the validated text is the written text, cannot see a write split across two functions, and cannot see the consumer half of #961 at all — those are `tests/test_ungated_artifact_write_961_964.py`'s. Suppress by naming which gate covers that write instead.

## Out of scope here

The environment itself — the `playground-v2/` stack, its detection rules, and host baselines. Defender consumes it through `defender/skills/`; it does not provision it.
