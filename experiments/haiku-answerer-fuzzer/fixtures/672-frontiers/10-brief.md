---
phase: A
status: complete
inputs: [{path: intent-design-672.md, inventory_echo: {claims: 16}}]
inventory: {claims: 20, flagged_facts: 9, shared_roots: 2}
---

## Digest

Grounding brief for #672 (typed closed-ticket tool for the benign judge). All 16 inherited
claims re-verified against this tree: 16 hold (c2/c3/c4/c5 re-executed, censuses c6/c11/c15
re-run, referential claims re-read); no design-refuted. Two doc-census drifts, both safe:
defender/CLAUDE.md's "three exemptions" prose is GONE (#673 slimmed it — one M6 deletion site
fewer), and grant.py's comment moved to 196-206 without the literal "Three grants" phrase.
Three new load-bearing facts: (1) the judge's ENTIRE bash lane is dead-at-executor today —
bind() gets no box, the inert BoxExecutor refuses on first use (only run.py:166 starts a box)
— so cat/defender-sql refuse too, not just the ticket read; gate ALLOW decisions still pass.
(2) M3's carrier seam exists (replace at _pydantic_stage.py:66; registration follows
defn.tools at driver.py:218) but run_stage/build_stage_agent carry NO tools param today —
the per-leg override needs a new threading. (3) Registration order is fixed and asserted
(test_agent_definition.py:307-319 pins _function_toolset.tools exactly). Shared roots: the
ticket store (writers run.py:148/208 + ticket_enrichment; readers = adapter verbs, gather's
unpinned get-ticket via registry, 2 CLI subprocess callers) and gather_raw (N7). Resource
declared under specGraph.resources (ticket_store); drivers + resource censuses tool-derived.

## Red flags

- **Doc census stale (safe direction), M6 prose list**: `defender/CLAUDE.md` no longer
  contains the "three exemptions" / ticket-grant prose — #673 (acb3f750) slimmed CLAUDE.md
  after the doc's sweep. That M6 deletion site no longer exists. `permission/grant.py`'s
  pins_path comment now sits at 196-206 and does not literally say "Three grants"; it names
  "the judge's ticket CLI" in its example list (still a real M6 edit site).
  `permission/bash.py` mentions are at ~181 (`--require-closed` lookahead in the
  `_TOKEN_SPACE` comment) and 331. Nothing new appeared; the census only shrank.
- **F1 (below) widens the doc's "bash-side ticket lane is already dead" story**: today the
  benign judge's *whole* bash lane — cat and defender-sql included — refuses at the executor
  (inert box), not only the ticket commands. Consistent with the doc's sequencing-free
  premise (restoration, not preservation), but the teaching surfaces (benign.md:37,
  `_cited_policy_read_section`) currently teach commands that cannot execute at all.
- **M3 is underspecified against current code, not false**: the `replace` seam rebinds only
  `model`/`effort`; no parameter today carries a per-leg `tools=` from `JudgeWiring` through
  `run_stage`/`build_stage_agent` (see F2). The doc's own c12 records this ("model/effort are
  today's only per-leg overrides"); the enumerators should treat the threading as new
  surface, not existing.

## Neighborhood — structure the change attaches to

### Actors (provenance: code)

- `learning_loop` (`defender/learning/loop.py`) — the live judge driver: imports
  `invoke_judge` (loop.py:72). Per-direction legs run **concurrently** on an inconclusive
  case (judge/run.py:110-114 docstring).
- `run_investigation` (`defender/run.py`) — does NOT drive the judge; it IS the box starter
  (run.py:166) and the ticket-store writer (open/close case tickets, run.py:148/208).
- `evals/run_judge_ab.py`, `evals/judge_equivalence.py` — eval drivers reaching
  `judge/run.py` (and run_judge_ab reaches `engine_pydantic.py`) in-process.
- `gather` (runtime, via `query` tool) — reaches the SAME ticket verb bodies through
  `ModuleVerbRegistry` (by-path module load, verbs.py:294) with `require_closed` a
  model-chosen param defaulting False; persists payloads to `gather_raw/{lead}/{seq}.json`
  (query_tool.py:471-475). The N7 cached surface's producer.
- Subprocess CLI callers (host, loop-side, not model-facing): `ticket_seeds._list_closed`
  (ticket_seeds.py:65-90; argv `list-tickets --status closed --label X`, NO
  `--require-closed`, 15s subprocess timeout, non-fatal empty-pool on any failure) and
  `verify_forward/forward.py:119-120` (argv `get-ticket <id> --require-closed`).
- `policy_cli.py` (`defender-policy show|explain`, operator-only) — compiles the judge's
  MAXIMAL policy with a demo ticket scope.

### Shared root 1 — the ticket store (HTTP service behind docker-exec; provenance: code)

Access is never a file: every route forks `docker --context soc-playground exec <bastion>
curl …` from the HOST (`_stub_transport.docker_exec_curl`, :163-220). Census by
`spec-graph trace resource ticket_store` (entry added to `specGraph.resources` in
`.claude/spec-flow.json`, both main checkout and worktree copy — g10):

- **Writers** (all outside this change's surface; N5): `run.py:148 open_case_ticket` /
  `run.py:208 close_case_ticket` (POST `/tickets`, POST `/tickets/{key}/transitions`);
  `learning/tickets/ticket_enrichment.py` → `annotate_case_ticket` / `enrich_case_resolution`
  (imported at :29-31, passed as fn values :88-89 — a floor line I classified by read; POST
  `/tickets/{key}/comments`, `/tickets/{key}/transitions`). Axes: ticket `key` = the run-dir
  basename (case id).
- **Readers**: the three verb bodies `list_tickets`/`get_ticket`/`health_check`
  (`ticket_adapter.py:64-108`) — consumed by (a) the gather `query` tool (dynamic registry
  edge — floor, classified live), (b) the two subprocess CLI callers above (string-composed
  path `_TICKET_CLI` = ticket_seeds.py:30 — floor, classified live), (c) the benign judge's
  bash grant text (dead at executor today, F1); plus `ticket_writer._fetch_enrich_ticket`
  (GET `/tickets/{key}`, loop-side).
- Floor lines classified by hand: `playground/ticket-server/app.py` = the store's own server;
  `health_check` hits in the six sibling adapters = same-name different symbols (each
  adapter's own); `test_620_consumers.py` = a fake registry (test double);
  `case_ticket.py:193` = comment only.

### Shared root 2 — `gather_raw/` (fs; the N7 carve-out; provenance: code)

Writer: the `query` tool's capture (`_persist_payload`, query_tool.py:471-475), one
`gather_raw/{lead_id}/{seq}.json` per query — including unpinned `ticket.get-ticket`
payloads fetched at investigation time. Readers: the judge, by design, via its read roots
(`RunScope.add_dirs` = gather_raw + comparison dirs → policy `read_roots`;
engine_pydantic.py:204-207) through `read_file` and (when a live box exists) `cat |
defender-sql`. Identical before and after this change — the doc's N7 carve-out is real and
pre-existing (probe: g17).

### Sibling surfaces reaching the store, with constraints (`constraints_by_via`)

| via | who | trust | constraints today |
|---|---|---|---|
| typed `query` tool | gather model | attacker-influenced (params derive from alert content) | verb-name allowlist; `require_closed` optional, default False; NO closed pin; salt-wrapped untrusted returns; capture row + circuit breaker |
| bash grant (argv) | benign judge model | attacker-influenced | pattern-pinned `<py> <cli> {list-tickets\|get-ticket}` + mandatory `--require-closed` lookahead (`_ticket_grant`, engine_pydantic.py:116-142); DEAD at executor today (F1) |
| subprocess CLI | loop code (ticket_seeds, verify_forward) | operator | pinned exit codes 0/1/2/64; ticket_seeds trusts server-side `--status closed` filter (no `--require-closed`); own subprocess timeouts (15s / see forward.py) |
| direct writer module | run.py + enrichment | operator | write path; separate concern (N5) |

### The mechanism seams M1-M6 attach to (all verified by read)

- Registration: `ToolSet` bits (agent_definition.py:67-100; existing bits: read, bash,
  write, forward_check, lesson_read, template_search, query — **no `closed_tickets` name
  collision anywhere**, probe g13) → `register_tools`/`_register_deferred_tools`
  (tools.py:511-609; deferred idiom = import-at-registration from the owning package, e.g.
  `register_forward_check_tool`, verify_forward/tool.py:277-290) ← `build_agent_core`
  (driver.py:218 `register_tools(agent, defn.tools, verbs)`).
- Per-leg rebind: `_pydantic_stage.build_stage_agent`:66 `defn = replace(AGENTS[role],
  model=lambda: model, effort=effort)`; `AGENTS` = `build_registry(... JUDGE_DEF ...)`
  (agents.py:25,34). `JUDGE_DEF.tools = ToolSet(read=True, bash=True)`
  (engine_pydantic.py:157).
- Wiring: `JudgeWiring.closed_ticket_read` (config.py:389-408, default False) set True only
  on the benign Direction (directions.py:41); flows today into
  `build_judge_invocation(closed_ticket_read=)` → `JudgeInvocation.ticket_cli` →
  `_ToolScope.ticket_cli` → `RunScope.ticket_cli` → `ResolvedRoots.ticket_cli` →
  `_judge_bash_shapes`' grant branch (engine_pydantic.py:111-113). `compile_policy` never
  touches registration (c7/c9 re-verified: agent_definition.py:287-306).
- Error seam + envelope idiom (M4): query_tool.py:314-334 (control-flow re-raise :319-322,
  `AdapterFault → (exit_code, detail)` :323-324, `BaseException` catch-all :325-326);
  view/fault both `_format_bash_result(…, _wrap(…, "untrusted", deps.salt), …)`
  (:388-409). Helpers: `_format_bash_result` tools.py:128; `untrusted.wrap` untrusted.py:20;
  `_bash_env` tools.py:269 → `run_common.run_env`. `VerbContext(defender_dir, run_dir, env)`
  off deps + `asyncio.to_thread(fn, vctx, **params)` (:436-446). Stage binds mint a fresh
  uuid4 salt (bind docstring, agent_definition.py:387-389).
- External tool semantics (probed, not priors): fault taxonomy `UpstreamFault`=1,
  `TransportFault`=2, `ConfigFault`=2, `USAGE_EXIT_CODE`=64; `AdapterFault` is the base
  (probe g5-g8, executed). CLI usage error exits 64; missing config exits 2 with stderr
  detail (executed, g8).

### Config knobs

- `defender/knowledge/environment/systems/ticket/config.env`: `TICKET_URL_BASE`
  (`http://ticket-server:8080`), `TICKET_BASTION_HOST` (`web-1`), `TICKET_TIMEOUT_SEC`
  (`10`); per-key run-env override beats the file (`load_config`,
  _stub_transport.py:124-160); missing file/key → `ConfigFault` (exit-2 class).
  Subprocess timeout = `TIMEOUT_SEC + 10`, mandatory on every fork (:210-213).
- `SOC_PLAYGROUND_DOCKER_CONTEXT` (default `soc-playground`) — retargets the whole family.
- `DEFENDER_BOX_RUNTIME` ∈ {runsc, runc} — box tier only; `--network=none` in both
  (box.py:457; c10 re-verified).
- `JUDGE_MODEL`/`JUDGE_EFFORT`/`BENIGN_JUDGE_EFFORT` env knobs; `JUDGE_REQUEST_LIMIT = 45`
  (engine_pydantic.py:55).

### Consumers of what M6 removes (probe g19: grep + per-file read; pyrefly on
`_ticket_grant` resolved {engine_pydantic.py:112,116; test_judge_pydantic_engine.py:224},
attribute-level `ticket_cli` refs under-resolve — honest tool floor, census is grep+read)

- Mechanism: engine_pydantic.py:111-113 (grant branch), 116-142 (`_ticket_grant`);
  judge/run.py:39+52 (`_ToolScope`/`JudgeInvocation.ticket_cli`), 55-57
  (`_ticket_cli_path`), 60-94 (`_cited_policy_read_section`; taught argv at 78-79), 129,
  159-164, 186; agent_definition.py:184 (`RunScope.ticket_cli`), 206, 246
  (`ResolvedRoots` threading); policy_cli.py:50-52 (demo scope — points at
  `case_history/case_ticket.py`, NOT the real CLI: the latent wrong-script bug, F7).
- Teaching/prompt: benign.md:37 (item 7); `_JUDGE_DENY_REASON` engine_pydantic.py:60-68
  ("benign only — the pinned closed-ticket read"); suite net =
  test_grant_gate_575.py:904-916 (`test_g1_no_deny_reason_or_hint_names_a_program_...`).
- Tests (9 files): test_judge_pydantic_engine.py:215-310 (grant shape + spoof defenses),
  test_grant_gate_575.py:134-143 fixtures + 717-748 (e1-e3; NOTE the fixture's ticket CLI
  path is also `case_history/case_ticket.py`, mirroring the policy_cli demo path),
  test_bind_sole_seam_551.py:238-263, learning/test_loop.py:1837-1857 (asserts
  `captured["ticket_cli"] is not None` on the benign leg), test_benign_direction.py:569-623
  (wiring flags + invocation pins; adversarial-leg negatives at :609-623),
  test_judge_sql_idioms_corpus.py:323, test_permission.py:688-751, test_ticket_adapter.py
  (verb-level; SURVIVES — it tests the verbs M2 reuses), e2e/test_query_tool_611.py:1310-1318
  (`test_ticket_cli_dual_surface_survives` — its "three consumers incl. the judge's grant"
  claim goes false with M6).
- Spec-graph nodes (c15 re-verified exact): spec_graph_575-grant-gate.yaml:300-319,
  573-580, 729, 894, 966, 1021; spec_graph_551.yaml:44-45, 261; spec_graph_538.yaml:366;
  spec_graph_611-query-tool.yaml:233, 362-367, 500, 540.
- Prose comments: _stub_transport.py:78 ("three subprocess callers"), grant.py:196-206,
  bash.py:~181+331, policy_cli.py:44-49+77-86, engine_pydantic.py:6+102,
  test_circuit_breaker.py:26-29 ("three subprocess consumers"), ticket_adapter.py:7-16
  docstring census ("three NON-gather consumers"). CLAUDE.md site: gone (Red flags).

### Execution-context census (probe g9: check_actors engine anchored on the touched
modules — spec-time variant of `spec-graph trace drivers`; no diff exists yet)

- `engine_pydantic.py` ← learning/loop.py, evals/run_judge_ab.py [import closure].
- `judge/run.py` ← loop.py, run_judge_ab.py, judge_equivalence.py [import closure].
  (Its "is itself an entrypoint" and the replay_actor subproc hit are stem-match artifacts:
  replay_actor.py:104 re-execs `pipeline/malicious_actor/run.py`, classified by read.)
- `_pydantic_stage.py`, `agent_definition.py`, `tools.py`, `ticket_seeds.py` ← 11-13
  entrypoints each (all learning/author/eval drivers + run.py — the shared-infra blast
  radius; full lists reproducible via the probe script).
- Floor: `ticket_adapter.py` and `policy_cli.py` sit OUTSIDE `specGraph.codeRoots`
  (defender/scripts/) — no static driver census exists for them; their drivers are the
  registry by-path load (verbs.py:294), the two subprocess callers, and the operator CLI.
  Dynamic-dispatch floor: `ModuleVerbRegistry` spec_from_file_location.

## Flagged facts (consequence-bearing; disposition each)

- **F1** The judge is bound with NO box (engine_pydantic.py:205-208 passes no `box=`;
  only run.py:166 calls `start_box`), and an unattached `BoxExecutor` refuses on first use
  as a tool error (tools.py:301-318, box.py:302-309, AgentDeps default tools.py:173). The
  benign judge's whole bash lane — cat, defender-sql, AND the taught ticket commands —
  currently fails at execution while `decide_bash` still ALLOWs. → feeds O1
  ("restoration, not preservation") and the sequencing premise; also means grant-pattern
  tests pass on a lane that cannot run.
- **F2** `run_stage`/`build_stage_agent` have no `tools` parameter; the only per-leg
  overrides threaded today are model/effort (_pydantic_stage.py:41-74, 88-157). → feeds M3:
  the `tools=` override requires new threading from `JudgeWiring.closed_ticket_read` through
  the shared transport (or a judge-side equivalent); the seam (replace + defn.tools) exists.
- **F3** Registration order is fixed and suite-asserted: `_function_toolset.tools` exact
  list + order pinned (test_agent_definition.py:307-319; tools.py:516-518 names the fixed
  order ending "…template_search, query"). → feeds M1: two new tools enter an asserted
  order; the ordering tests are in the change's blast radius.
- **F4** The query tool's error seam is entangled with CAPTURE (queries row `_record` +
  `circuit_breaker.record_outcome`, query_tool.py:330-334, 385); M4 mirrors the seam only —
  the judge's tool writes no queries row and trips no breaker; `ModelRetry` reserved for
  malformed calls; `RunAborted`/control-flow re-raised. → feeds O4 (fault → failed tool
  result, no retry loop, no unwind) and bounds O5 (breaker keying stays CLI-side).
- **F5** The "host-side HTTP read" forks `docker exec curl` subprocesses on the host with a
  MANDATORY inner timeout (`TIMEOUT_SEC + 10`); `asyncio.wait_for` cannot kill the thread —
  the transport's inner timeout is the only real kill (query_tool.py:440-446,
  _stub_transport.py:210-213). → feeds O1/N1 (host-side execution is the intent) and the
  doc's accepted timeout tradeoff.
- **F6** Gather's `ticket.get-ticket` has no closed pin on the query-tool surface (verb
  param default False; model-chosen) and its payloads persist under `gather_raw/` which the
  judge reads by design. → feeds N7 (pre-existing carve-out, confirmed identical
  before/after) — NOT an O2 surface.
- **F7** policy_cli.py:52's demo ticket scope AND test_grant_gate_575's fixture
  (`_ticket_cli`, :142-143) both point at `case_history/case_ticket.py`, not the real
  adapter CLI. → feeds M6 (the latent wrong-script demo is removed; the same wrong path
  appears in a test fixture slated for retirement — e2 even asserts on
  `endswith("case_ticket.py")`).
- **F8** `_JUDGE_DENY_REASON` staleness is mechanically test-visible:
  test_grant_gate_575.py g1 scans deny_reason + overflow hint for programs the agent cannot
  run. → feeds M6's teaching-surface obligation (the rewrite is forced, not optional).
- **F9** `defender/CLAUDE.md` census entry in M6 no longer exists (#673). → feeds M6:
  drop that edit site; `no-consequence` beyond the doc correction (nothing replaced it that
  teaches the ticket lane).

## Claims ledger (censuses + probes; g* extend/re-verify the doc's inherited c*/r1)

```yaml
claims:
  - {id: g1, kind: census, re_verifies: c11, claim: "ticket_cli file census: 15 files — 4 mechanism (engine_pydantic, judge/run, agent_definition, policy_cli) + 2 comment-only (permission/bash, _stub_transport) + 9 test (8 under defender/tests/ + learning/test_loop.py)", probe: "grep -rln ticket_cli --include='*.py' defender/ (2026-07-20, this tree) + per-file read", observed: "exactly the 15; split as listed", verdict: holds}
  - {id: g2, kind: census, re_verifies: c6, claim: "non-test argv consumers of the ticket CLI: judge grant/prompt text (judge/run.py:78-79 via :129), ticket_seeds.py:68-71, verify_forward/forward.py:119-120; rest are docstrings/comments", probe: "grep -rn 'ticket_adapter|_TICKET_CLI' --include='*.py' defender/ minus tests", observed: "those three + prose mentions (ticket_writer.py:10, ticket_seeds.py:12, adapter usage lines)", verdict: holds}
  - {id: g3, kind: census, re_verifies: c15, claim: "spec-graph nodes bound to the bash ticket surface are exactly the anchors listed in the doc", probe: "grep -n 'require-closed|require_closed|ticket_grant|ticket_cli' defender/tests/spec_graph_*.yaml", observed: "575:300-319,573-580,729,894,966,1021; 551:44-45,261; 538:366; 611:233,362-367,500,540", verdict: holds}
  - {id: g4, kind: census, corrects: "M6 prose list", claim: "the defender/CLAUDE.md exemption prose is gone (#673); grant.py comment at 196-206 without the 'Three grants' literal; bash.py at ~181,331", probe: "grep -rn 'exemption|ticket' defender/CLAUDE.md defender/runtime/permission/*.py", observed: "CLAUDE.md: no hits; grant.py:198; bash.py:181,331", verdict: doc-census-stale-safe}
  - {id: g5, kind: behavior, re_executes: c2, claim: "get_ticket(require_closed=True) on an open ticket raises UpstreamFault exit 1, no payload", probe: "in-process, stubbed http_get returning status=open (scratchpad probe_verbs.py)", observed: "UpstreamFault exit_code=1 detail=\"SOC-1 is status='open', not 'closed' (--require-closed)\"", verdict: holds}
  - {id: g6, kind: behavior, re_executes: c3, claim: "list_tickets(require_closed=True) pins outgoing status=closed over a stray status arg", probe: "in-process, captured outgoing params", observed: "http_get('/tickets', {'status': 'closed'})", verdict: holds}
  - {id: g7, kind: referential, re_executes: c5, claim: "VERBS importable/callable in-process: {get-ticket, health-check, list-tickets}", probe: "import + callable() sweep", observed: "all three callable", verdict: holds}
  - {id: g8, kind: behavior, re_executes: c4-class, claim: "infra faults are the exit-2 class with stderr detail; usage errors exit 64", probe: "ran the CLI with DEFENDER_DIR pointing at a missing tree (ConfigFault) and with --bogus-flag", observed: "exit=2 'config file not found: …'; exit=64 argparse usage", verdict: holds}
  - {id: g9, kind: census, claim: "execution contexts reaching the touched modules, as tabulated in the census section; scripts/* modules outside codeRoots are floor", probe: "check_actors._Census engine anchored on the design's touched modules (scratchpad probe_drivers.py — spec-time trace drivers)", observed: "as tabulated; replay_actor subproc hit classified as malicious_actor/run.py; dynamic floor verbs.py:294", verdict: holds}
  - {id: g10, kind: census, claim: "ticket-store writers/readers as tabulated under Shared root 1", probe: "spec-graph trace resource ticket_store (specGraph.resources entry added: writers ticket_writer.py::{open,close,annotate,enrich}_*, readers ticket_adapter.py::{list_tickets,get_ticket,health_check}, grep 'ticket_adapter.py') + hand classification of every floor line", observed: "resolved: run.py:148,208 + tests; floors classified: ticket_enrichment.py real writer (import :29-31), server-side app.py, same-name health_checks, test doubles, string-path CLI callers", verdict: holds}
  - {id: g11, kind: referential, claim: "only run.py:166 starts a live box; bind() without box= leaves the inert BoxExecutor which refuses on first use as a tool error; the judge's bind passes no box", probe: "grep start_box across defender/ + read tools.py:169-173,301-318, box.py:296-309, engine_pydantic.py:205-208", observed: "as stated — the judge's whole bash lane is dead-at-executor today (F1)", verdict: holds}
  - {id: g12, kind: referential, re_verifies: c12, claim: "the per-leg carrier seam exists (replace at _pydantic_stage.py:66; registration follows defn.tools at driver.py:218) but no tools parameter threads through run_stage/build_stage_agent today", probe: "read _pydantic_stage.py:41-157, driver.py:175-219", observed: "signatures carry model/effort/make_model only", verdict: holds}
  - {id: g13, kind: referential, re_verifies: c7, claim: "typed tools are authorized by registration alone (ToolSet bit → register_tools); no grant path for non-bash tools; no 'closed_tickets' name exists; deferred-tool idiom is import-at-registration in the owning package", probe: "read tools.py:511-609, agent_definition.py:67-100; grep closed_tickets defender/", observed: "as stated; grep empty", verdict: holds}
  - {id: g14, kind: referential, re_verifies: [c8, c13], claim: "the query tool's error seam + salt-wrap envelope exist as the doc cites, and are entangled with capture (rows + breaker) which M4 does not mirror", probe: "read query_tool.py:49-60,314-334,388-446,471-475; tools.py:128,269; untrusted.py:20", observed: "as stated (F4)", verdict: holds}
  - {id: g15, kind: referential, re_verifies: [c9, c14], claim: "benign-only wiring + teaching surfaces + deny-reason suite net as cited; adversarial leg carries ticket_cli=None end-to-end", probe: "read directions.py:41, config.py:389-408, judge/run.py:60-94,159-186, benign.md:37, engine_pydantic.py:57-68, test_grant_gate_575.py:904-916, test_benign_direction.py:569-623", observed: "as stated", verdict: holds}
  - {id: g16, kind: referential, claim: "ticket config knob: TICKET_{URL_BASE,BASTION_HOST,TIMEOUT_SEC} with defaults as listed, per-key env override, ConfigFault on missing; transport forks docker-exec-curl host-side with mandatory inner timeout TIMEOUT_SEC+10", probe: "read knowledge/environment/systems/ticket/config.env, _stub_transport.py:124-160,163-220", observed: "as stated", verdict: holds}
  - {id: g17, kind: census, claim: "gather's route to the same verb bodies: query tool → ModuleVerbRegistry by-path load; require_closed model-chosen default False; payloads persist to gather_raw/{lead}/{seq}.json which the judge reads via its read roots", probe: "read verbs.py:294-330, query_tool.py:423-446,471-475, test_query_tool_611.py:1310-1318; grep gather_raw writers", observed: "as stated (F6/N7)", verdict: holds}
  - {id: g18, kind: referential, claim: "JudgeDeps: run_dir = learning run dir; read roots = gather_raw + comparison dirs; stage binds mint a fresh uuid4 salt; JUDGE_DEF tools = read+bash; request cap 45", probe: "read engine_pydantic.py:71-82,153-161,181-215; agent_definition.py:377-423", observed: "as stated", verdict: holds}
  - {id: g19, kind: census, claim: "the full consumer set of the M6-removed plumbing is the 'Consumers of what M6 removes' section; pyrefly resolves _ticket_grant refs to engine_pydantic.py:112,116 + test_judge_pydantic_engine.py:224; attribute-level ticket_cli refs under-resolve in pyrefly (guard tripped) so that census is grep+read, not resolver-backed", probe: "pyrefly-refs engine_pydantic.py:116 _ticket_grant; pyrefly-refs agent_definition.py:184 ticket_cli (guard tripped); grep + per-file read of all 15 files", observed: "as listed; honest tool floor recorded", verdict: holds}
  - {id: r1-extended, kind: reachability, claim: "post-M6 the benign judge's model-reachable live-store routes are the two new typed tools and nothing else: bash shrinks to cat+defender-sql (file-opening only; the store is HTTP, no file exists), read_file opens files, no query bit on JUDGE_DEF, gather_raw is the N7 cache not a store path", probe: "surface sweep over JUDGE_DEF ToolSet + _judge_bash_shapes minus the ticket branch; phase F must re-probe against the BUILT policy and registered toolset", observed: "no other live-store surface found in this tree", verdict: unrefuted}
```

## Probe artifacts

- `probe_verbs.py`, `probe_drivers.py` in the session scratchpad
  (`/tmp/claude-0/-workspace/d4d3d45b-c0bd-4434-b4a8-c7a4fb58a295/scratchpad/`) — re-runnable.
- `specGraph.resources.ticket_store` added to `.claude/spec-flow.json` (worktree AND main
  checkout `/workspace/.claude/spec-flow.json`) — the durable census entry;
  `spec-graph trace resource ticket_store` reproduces g10.
