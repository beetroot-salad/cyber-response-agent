# Development lint reference

Read the relevant entry when changing a shared seam or resolving a lint finding. This is not an additional always-loaded instruction file.

This reference describes lint expectations and existing seams. `.github/workflows/ci.yml` determines which checks currently block CI; each checker module defines its exact scope and suppression syntax. The checkers live at `tooling/lint/lint_*.py` (repo root). Almost all scope to `defender/` alone — the stale-reference scan works off the PR's whole diff. Run one directly: `defender/.venv/bin/python tooling/lint/<lint>.py`.

They are **ratcheted**, not absolute: each carries a checked-in `<lint>_baseline.json` (`tooling/lint/_baseline.py`) recording today's findings, so a gate fails only on a fingerprint that is not already in its baseline. That makes the baselines part of the contract, and there are two different reasons to touch one — keep them apart:

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
| Reads out of that same tree through `run_repository._layout.artifact_file` / `artifact_dir`, which `lstat` | a plain stat/read/copy, which follows the link the write side refuses | `# lint-tree-read-follows-link: ok` |
| Prompt sections already `defender._untrusted.wrap`-ed when they reach `stage_user_message` | interpolating a section into the prompt yourself | `# lint-stage-frame: ok` |
| `encoding="utf-8"` pinned on every text read and write | bare `read_text()` / `open(p)` / `write_text(s)`, which use the ambient locale | `# lint-text-io: ok` |
| Whole-file reads through `defender._io`: `read_text_utf8` for `read_text(encoding="utf-8")`, `read_bytes_capped` for `read_bytes()` (same semantics), capped at `READ_LIMIT`, which a caller can only lower | a bare `read_text()` / `read_bytes()` (or a reference to one), which sizes its buffer from the file | `# lint-whole-read: ok` |
| Lesson text through `_corpus.Lesson.line` / `.lines` / `.match_text`, and inside a `_untrusted` frame when it reaches a model (#1206). The gate matches names (`.fm`, a `lesson…`'s `.raw` / `.body`, a `hit…`'s `.frontmatter`), so a lesson file parsed directly is not seen | reading the raw text and printing it — a line break or terminal control in a value forges rows | `# lint-lesson-text: ok` |
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
| A value's SOLE PRODUCER declared as `@owns <field>` in its docstring, and only one function claiming it — the two-derivations-of-one-quantity class jscpd cannot see (#923) | `# lint-owns: ok` |
| An AST check over shipped source resolving a name through `tooling/lint/_astlib.py`, not by matching the spelling — an alias, the attribute form or a local shadow each read right and mean something else | `# lint-ast-resolve: ok` |
| A mixed collection classified exhaustively, with the residue reported (see below) | `# lint-selection: ok` |
| Every writer of `investigation.md` / `report.md` to meet their schema (see below) | `# lint-artifact-gate: ok` |

### Hygiene

| The gate wants | Suppress with |
|---|---|
| No vendor- or environment-specific tokens outside the carved-out systems-skill dirs — `defender/` ships vendor-neutral | `# lint-shippable: ok` |
| No hardcoded `/workspace` or `/tmp/defender` paths in shipping code; no bare `python3 x.py` in a hook `command:` (it gets system python); a hook matcher naming *both* `Task` and `Agent`, since production dispatches as both | `# lint-hygiene: ok` |
| No reference left behind to a symbol or file the PR's own diff removed — the missed-callsite-after-rename class. Diffs against `$STALE_REF_BASE` (default `origin/main`) | `# lint-stale-ref: ok` |
| Every program (`__main__` block) calls `_log.configure_from_env()` first — without it INFO lines vanish and nothing is JSON | `# lint-log-setup: ok` |
| Tenant delivery stays fenced (#1108 P3): no `git-credentials` spelling in production source; the box's check-file name is spelled once (in the box spec) and in no agent-facing text | none (no baseline) |
| Every production pydantic_ai `Agent(...)` passes `retries=` (#631): the framework default gives a denied tool call no second try | none (no baseline) |
| Scrub order (#540): in the entrypoint the box lifecycle runs before any reader of the run folder; no handler swallows the run-tainted signal; the bash tool never calls the in-process executor | none (no baseline) |
| Isolated modules (#1092, #983, #631): the box image scripts import only the standard library with no package-relative import; the tacit-knowledge registry adapter makes no filesystem write; the budget enforcer reads no environment, file or JSON; the ticket writer and lead-zero modules are handed their environment (no `run_env`, `os.environ`, `os.getenv`; the writer also no `process_defender_dir` or `cwd`) | none (no baseline) |
| Venv guard (#1080): `execution/_venv.py` imports only the standard library; every script that re-executes into the venv calls the guard at module scope before any other `defender.*` import | none (no baseline) |
| Close single read (#991): the close makes one read and one parse of the investigation companion, the challenge gate makes none, and the parse sits in the guard that turns a fault into a refusal | none (no baseline) |
| Paths resolve (#1080): every path in a lint's scope list, every path in a lint-baseline key, and every `defender/cli`/`defender/box` command in `ci.yml` exists (commands: with a `__main__` block) | none (no baseline) |
| Episode trees are reached only through the Episode handle and the runs repository's walk: no episode I/O in the migrated modules but the declared residue, no path-taking parameter or path maker outside the allowlists, no production code opens or re-binds an episode by path | none (the script's tables are the allowlists) |
| Episode ids carry no composed meaning (no `{episode_id}-…` build, banned id derivers, labelled `RunId.mint`); the walk owner makes no folder by its path; the arm roster's file name is spelled only in the episode layout | none (no baseline) |
| No newly-introduced dead code (wraps vulture) | baseline only |

CI also runs the jscpd Python-duplication gate; read the workflow for its current threshold.

### Four that get a paragraph, because the fix is not obvious from the failure

- **Anchor a default in one place.** Resolve an optional input once at the boundary, thread it inward non-`Optional`; don't re-coalesce in the body (`x = x if x is not None else DEFAULT`). Prefer `is not None` over `or`.
- **A render list is not a key set.** A sequence that records *what happened in what order* and a key set that names *the distinct things* are different values — spelling them with one name hides the confusion at every call site. Where both are wanted, derive them separately at the one place the list is built (`dict.fromkeys(...)` keeps the order) and give the deduped one its own name. Walking the raw list to patch a table already keyed by it patches one bucket per appearance (#956).
- **Read invlang fences through one helper.** `skills/invlang/parser.scan_fences` is the only thing that decides which bytes of an `investigation.md` are invlang content; it hands back what the fences ORPHAN (`orphaned_headers`) alongside what they hold, so a reader cannot take the content and drop the complement without saying so. Three readers used to derive that split independently and all three dropped it in silence — content outside a fence never reaches the tokenizer, so it cannot even raise a `ParseWarning`, and a run's whole PLAN section parsed to an empty companion that every hypothesis-side rule then passed vacuously (#932). The same rule applies one level down: selecting from a mixed cell with `[t for t in xs if SOME_ID_RE.fullmatch(t)]` drops whatever matches neither namespace, which is how a qualified `h-001.ac1` in a `:L findings` `tests` cell reached no rule at all — classify exhaustively and report the residue. The suppression must state where the complement goes.
- **Every writer of the two model-authored artifacts meets their schema.** `records/_artifact_schema.py` owns what a well-formed `investigation.md` / `report.md` IS, and `permission.decide_write` applies it to every write a MODEL makes — which is what made "a committed investigation parses" true, and true only of the verbs the agent writes through. Three writers sat outside that set: the harness seeding lead-0's declaring row before MAIN's first turn (#964), the turn-N branch seeding a sibling's whole document from a fence-boundary prefix (a valid source does not guarantee a valid prefix — the reference rules are order-independent), and `close_investigation`, the one verb that PUBLISHES, which validated the report it wrote and never the companion it published (#961). The general shape is worth recognising on sight: **an invariant enforced at a gate, and then believed of the artifact** — a gate can only promise something about the paths that run through it. The gate asks co-occurrence, not dataflow: it cannot tell whether the validated text is the written text, cannot see a write split across two functions, and cannot see the consumer half of #961 at all — those are `tests/runtime/permissions/test_ungated_artifact_write_961_964.py`'s. Suppress by naming which gate covers that write instead.
