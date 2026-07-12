# #575 — RESOLVED demand list (the spec). Post-step-7.

Base `09e0a93c`. Design = issue #575 body + its "Resolved forks" addendum. Grounding = `.spec/brief.md` (read it).

Every demand below is `form: test` unless marked `clause`/`waiver`. All tests RED at HEAD (the target doesn't exist yet) — that is the expected state.

## Entry points under test
- `permission.decide_bash(cmd, *, policy, run_dir, defender_dir) -> BashDecision`
- `permission.decide_read(path, *, run_dir, defender_dir, policy) -> Decision`
- `agent_definition.compile_policy_for(defn, run_dir, *, scope, defender_dir) -> AgentPolicy`
- `permission.is_untrusted_read(path) -> bool`
- the `defender-policy` CLI (`show` / `explain`)

## Test-construction idiom (mirror `tests/test_read_confine_bash.py`)
```python
main   = compile_policy_for(MAIN_DEF,   run_dir=run, defender_dir=dfn)
gather = compile_policy_for(GATHER_DEF, run_dir=run, defender_dir=dfn)
d = permission.decide_bash(cmd, policy=pol, run_dir=run, defender_dir=dfn)
```
Judge/actor/lead-author via `bind(<DEF>, run, scope=RunScope(...))`. NO monkeypatch (CI ratchets it).

---

## §A — The containment model

- **a1** behavior — a command is ALLOWED only if it matches a grant's `pattern` AND every operand `PROGRAMS[argv[0]]` extracts resolves into that grant's `scope`.
- **a2** negative — **no UNMARKED grant's `pattern` embeds a path.** Introspect every compiled `Grant` for all 8 defs; a grant whose `pattern.pattern` contains a literal/escaped `run_dir`/`defender_dir`/script/ticket-CLI path MUST carry `pins_path=True`.
  *positive control*: the three `pins_path=True` grants DO embed a path (so the audit can see the difference); and `scope` patterns DO carry the anchored roots.
- **a3** behavior — `under(root, tail)` fullmatches the **RESOLVED** path.
- **a4** negative — no path shape uses `[^\x00]*`; the machine-generated shapes are tight (`gather_raw/l-\d+/\d+\.json`).
- **a5** negative — **symlink**: `{run}/evil.json` → `/etc/passwd`, `cat {run}/evil.json` → **DENY** for gather (resolve() collapses it out of scope).
  *positive control*: a real `{run}/gather_raw/l-001/0.json` under the same grant → ALLOW for gather.
- **a6** behavior — a symlink `{run}/x.json` → another **in-root** file → **ALLOW** (a5 denies for ESCAPE, not because symlinks are banned).
- **a7** behavior — **symlink loop** → `resolve()` raises `RuntimeError` → DENY (fail closed, no exception escapes).
- **a8** behavior — a **broken** symlink and a **missing** path both `resolve()` WITHOUT raising (`strict=False`) → verdict by SHAPE, never by existence. A not-yet-written `{run}/gather_raw/l-001/0.json` still ALLOWs for gather.
- **a9** behavior — an embedded-NUL operand → `ValueError` ∈ `_RESOLVE_ERRORS` → DENY (no raise out of the tool).
- **a10** behavior — **scope anchors on the RESOLVED root**: a `run_dir` reached through a symlink (symlinked `$DEFENDER_RUNS_BASE`) still ALLOWs `cat {run}/investigation.md`. (Compile scope from the unresolved root and EVERY in-root read denies — the inverse of `_common.py:250-259`.)
- **a11** behavior — a **relative** operand (`cat defender/lessons/x.md`) is rebased on `defender_dir.parent` (the executor's cwd, `tools.py:305`) before resolve → ALLOW. Drop the rebase and gate and executor name different files.
- **a12** behavior — **every pipe stage** is gated: `cat {run}/x.md | cat /etc/passwd` → DENY (the second stage's operand is checked too).

## §B — PROGRAMS, and the OPENS_NOTHING obligation

- **b1** behavior — `PROGRAMS["cat"] is _cat_input_files`; every other granted program is `OPENS_NOTHING`.
- **b2** behavior — **`compile_policy` RAISES** when a grant names a program absent from `PROGRAMS`. Fail LOUD at compile, not fail-open at first decide. (Replaces today's `_OPERAND_GATED_PROGRAMS.get(...) is None → True` pass-through, `bash.py:282-284`.)
- **b3** behavior — **every `AgentPolicy` in the registry passes the program-table validation, INCLUDING CORPUS_AUTHOR's**, which is built directly by `_corpus_author_policy` and never calls `compile_policy` today. (It is the one denylist-free lane.)
- **b4** domain-outcome — `_cat_input_files` returns `None` → DENY for EVERY unrecognized `-`-prefixed token. Parametrize.
  *positive control*: known boolean bundles (`-n`, `-A`, `-vET`) extract the file operands correctly.
- **b5** domain-outcome — `cat -- /etc/passwd` → **DENY**. Post-`--` tokens ARE appended as file operands (`bash.py:243-245`), so they get scope-checked. (An enumerator read this backwards and produced a fail-open — pin it.)
- **b6** domain-outcome — `cat -` (bare dash = stdin) extracts NO operand → the stdin-pipe shape still ALLOWs.
- **b7** ⚠️ **THE PRIME FAIL-OPEN** negative, parametrized — **every `OPENS_NOTHING` program's SHAPE regex must admit no file-opening / arg-consuming flag**, because the gate skips the scope check for them entirely. ALL of these → DENY, for main AND gather:
  ```
  wc --files0-from=/etc/passwd          grep --file=/etc/passwd x
  grep -f /etc/passwd x                 grep --exclude-from=/etc/passwd x
  grep -e x /etc/passwd                 grep -r x        grep -R x
  jq --rawfile v /etc/passwd .          jq --slurpfile v /etc/passwd .
  jq -f /etc/passwd                     jq -L /etc .
  tail -f /etc/passwd                   head -c 100 /etc/passwd
  ```
  *positive control*: the stdin forms ALLOW — `cat {run}/x.md | grep -n s`, `| wc -l`, `| head -5`, `| tail -3`, `| jq -r '.'`.
- **b8** negative, structural — over EVERY `OPENS_NOTHING` grant: its pattern admits **no `--` long option** and **no `-`-prefixed positional**. Today these are *conventions* (`gnu_flags.bundle` emits single-dash only; the `(?!-)` free-text close, #579) — this test makes them **enforced properties** a future grammar author cannot silently drop.

## §C — The lane after the change (the behavior-change ledger — pin BOTH sides)

- **c1** domain-outcome — file-operand viewers: `grep -n secret {run}/x.md` → **DENY** (ALLOW at HEAD); `cat {run}/x.md | grep -n secret` → **ALLOW**. Same for `head`/`tail`/`wc`.
- **c2** negative — `ls` (any form) and `cd` (any form) → DENY for main and gather.
  *positive control*: the surviving programs still ALLOW.
- **c3** negative — **`main` has no recursive-descent primitive**: `ls -R {run}`, `grep -r x {run}` → DENY. (The property `_common.py:117-122` says made the now-deleted textual raw clamp complete rather than lucky.)
- **c4** survival — the shipped query template's LITERAL command still ALLOWs for gather:
  `cat ${payload} | jq -r --arg uid "1000" '.entries[] | select(split(":")[2] == $uid)'`
  (`skills/gather/queries/host-state/container-identity-and-uid.md:28` — a shipped template the gate denies is a documented dead command.)
- **c5** ⚠️ **behavior change #3** — the `RAW_MARKER in cmd` substring scan is GONE: `cat {run}/report.md | grep gather_raw` → **ALLOW** for main (it opens `report.md`, which is in scope; nothing touches gather_raw). **At HEAD this DENIES** (verified). Pin the new verdict.
- **c6** survival — **curator behavior change #4**: `grep -l 'source_signature:.*x' defender/lessons/a.md` → **DENY**; `cat defender/lessons/a.md | grep -l 'source_signature:.*x'` → **ALLOW** on the curator lane. And `ls defender/lessons/` → DENY (the corpus manifest from #574 replaces it).

## §D — gather_raw, positive enumeration, and the read surface

- **d1** domain-outcome — `cat {run}/gather_raw/l-001/0.json`: **ALLOW for gather, DENY for main**, on the bash lane.
- **d2** ⚠️ **behavior** — `decide_read(main, {run}/gather_raw/l-001/0.json)` → **DENY**, with a reason naming gather_raw. `raw_reads` is deleted, so `files.py:173`'s clamp is gone — the DENY must now come from the **read-side positive enumeration**, and the **e2e deny-tail substring ("must not read gather_raw") must still match** (`tests/e2e/test_replay_skeleton.py:152-179`). Do NOT relax that assertion.
- **d3** ⚠️ **negative** — `is_untrusted_read({run}/gather_raw/l-001/0.json)` is **True** → the payload read is still **salt-tag wrapped**. Deleting `RAW_MARKER` untags the primary attacker-influenced channel and **fails the prompt-injection defense open**.
  *positive control*: `is_untrusted_read({run}/investigation.md)` is False, and a gather payload read IS wrapped in the salt tags end-to-end.
- **d4** parity — **read↔bash scopes are the SAME OBJECTS.** For MAIN and GATHER, the shape tuple `decide_read` enforces IS (identity, not equality-by-luck) the tuple the `cat` grant's `scope` carries. Falsify: construct a policy whose read scope and cat-grant scope differ and assert the parity harness FAILS.
- **d5** parity, parametrized — the **allow-matrix**: for each `(agent, path)`, `decide_read(path).allow == decide_bash(f"cat {path}").allow`. Corpus MUST include:
  `{run}/investigation.md`, `{run}/report.md`, `{run}/alert.json`, `{run}/executed_queries.jsonl`,
  `{run}/gather_summaries/l-001.md`, `{run}/gather_raw/l-001/0.json`, `{run}/gather_raw/l-001.lead.json`,
  `{dfn}/lessons/x.md`, `{dfn}/docs/x.md`, `{dfn}/fixtures/held-out/m01/ground_truth.yaml`, `/etc/passwd`
- **d6** behavior — the **denylist still applies inside scope**: `{dfn}/lessons/.env.md` matches the corpus `.md` shape but `_denylisted` DENIES it. And `{run}/x/.ssh/id_rsa` denies.

## §E — The exempt (`pins_path`) grants

- **e1** ⚠️ **negative — THE JUDGE'S SECURITY PROPERTY.** `<py> <ticket-cli> get-ticket case-1` (no `--require-closed`) → **DENY**. A boolean-flag allowlist makes every flag OPTIONAL; the mandatory-flag lookahead must survive the migration.
  *positive control*: `<py> <ticket-cli> list-tickets --require-closed` → ALLOW.
- **e2** behavior — the adversarial judge (`RunScope(ticket_cli=None)`) has NO ticket grant: even `… list-tickets --require-closed` → DENY.
- **e3** behavior — `--require-closed` cannot be smuggled inside a quoted operand: `<py> <cli> get-ticket "x --require-closed"` → DENY (the `_TOKEN_SPACE` NUL sentinel keeps every space in the joined argv a true token boundary).
- **e4** behavior — the actor's `python3 <pinned-script>` and the lead author's `rm {skills}/<name>.md` still ALLOW; `python3 /etc/evil.py` and `rm {skills}/../../etc/passwd` DENY.

## §F — Routing, Decision, and layering

- **f1** behavior (**demand #0**) — `BashDecision` still carries `pipelines` (for `bash_exec.run_parsed`, the #456 single-parse), `adapter_argv` (`list[str]`), and `sql_pipe` (`(adapter_argv, sql_argv)`) — all three consumed by `tools.py:280-296` → `_derive_system` → the circuit breaker. `Grant.route` tags reader-lane grants only.
- **f2** behavior — **adapter classification stays structural**: `_decide_adapter` runs AFTER the reader lane returns `None` (`bash.py:404-411`). Pin the ORDER (`test_permission.py:652` pins "bash_allow claims BEFORE adapter classification"), not just the verdict.
- **f3** behavior, parametrized — the two SPECIFIC adapter deny reasons survive (the e2e deny-tail asserts them as substrings):
  `defender-elastic query foo` (main) → reason contains "data-source CLIs directly";
  `curl http://example.invalid/x` (main) → reason contains "only the defender-* shims".
- **f4** behavior — the sanctioned pipe: `defender-elastic query X | defender-sql 'SELECT 1'` → ALLOW for gather with a correct 2-stage split; `defender-elastic query X | head` → DENY.
- **f5** negative — **AST walk over `defender/runtime/**`: no import of a `defender.learning.*` name starting with `_`** (today `_bash_allow` lazily imports `_judge_policy`/`_actor_policy`/`_rm_skills_pattern` at `:275,:278,:285`). Function-body/lazy imports COUNT. And nothing under `runtime/` enumerates agents.
  *positive control*: the relocated `defender/agents.py` DOES import the 6 `*_DEF`s — proof the scan sees such an import when present.

## §G — Prompt surface (a dead program named in a prompt teaches a dead command)

- **g1** negative — **no deny_reason and no `_overflow_filter_hint` output names a program the agent cannot run.** For every def: tokenize `deny_reason` + `_overflow_filter_hint(policy)` for program-looking words and assert each is admitted by that agent's OWN lane. Catches `policies/main.py:18` and `policies/gather.py:22` naming the DELETED `ls`, and `bash.py:70` telling gather to "filter the persisted payload **file** with jq/grep" after both lose their file slot.
  (Do NOT implement as a grep for a hardcoded dead-name list — it drifts on the next deletion.)
- **g2** behavior — `_overflow_filter_hint` still reaches the `jq` branch for main/gather (`cat <path> | jq '<filter>'`), `defender-sql` for the judge, and the read-tool fold for the rest. **`tools._lane_admits` (`tools.py:58-62`) does `p.fullmatch(probe)` over `policy.bash_allow` — an `AttributeError` in production once that tuple holds `Grant`s.** It must go through the real decide seam.

## §H — Lifecycle

- **h1** behavior — `compile_policy_for` twice for the same `(def, roots)` yields an equal policy (idempotent).
- **h2** behavior — **no cross-run bleed**: two runs with DIFFERENT `run_dir`s in ONE process produce policies whose scopes anchor on their OWN run_dir. (`reader_patterns_for` is `@lru_cache(maxsize=1)`; `resolve_roots` is deliberately UNCACHED — the #497/#534 hazard. `tools_gather.py:325` binds GATHER_DEF per DISPATCH, many per run.)
- **h3** behavior — `test_empty_denylist_does_not_brick_reader_lane` survives: an empty denylist axis contributes no lookahead and does not brick the lane.

## §I — The audit CLI

- **i1** behavior — `defender-policy show <agent> --run-dir X` prints each agent's read/write/bash grants with scopes; an exempt (`pins_path`) grant reports its PATTERN as the containment, never a misleading `scope: []`.
- **i2** behavior — **differential**: for a corpus of (agent, command), `defender-policy explain` reports the SAME verdict and the SAME matched-grant/deny-reason as `decide_bash`. The CLI is a second CONSUMER of the gate, never a second implementation.
- **i3** negative — `defender-policy` is NOT in `NON_ADAPTER_SHIMS`: `defender-policy show main …` → DENY on every agent lane (adding it to `_cmd_segments.py:56` would hand every agent policy introspection for free via `_shim_names`).

## Waivers (`form: waiver` — examined no's)

- **w1** "Net LOC does not increase" — a review property, not observable behavior. Checked at review, not by a test.
- **w2** The `-f`/`tail -f` wedge (a stage that never returns) is bounded by `_BASH_TIMEOUT_S=120`, not by the gate. b7 pins the DENY; the timeout is out of scope.
