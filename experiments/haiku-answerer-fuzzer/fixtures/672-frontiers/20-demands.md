---
phase: A-extract
status: complete
inputs: [{path: intent-design-672.md, inventory_echo: {claims: 16}}]
inventory: {demands: 22, claims: 24, background: 9, forks: 2}
---

## Digest
Extraction over intent-design-672 (16 inherited claims echoed): 22 demands (20 test, 2 clause), 8 new claims raised — all probed, all hold — 9 background entries, 2 forks. No design-refuted finding.
Demand #0 (tool_result_envelope) pinned PROVISIONAL: plain-string `_format_bash_result`-shaped result, success view and fault detail salt-wrapped untrusted, never an unwind — fork f1: the doc is silent on whether the tool records its reads (queries-table row / truncated-view note, as the query tool does) or is record-free with the view inline; pinned reading = record-free.
Fork f2: tool/bit names are the doc's own proposal (`closed_tickets`; list/get closed ticket) — confirm or rename at §7.
Obligation spine: O1→d1,d13; O2→d3,d4,d5,d18 (surface census; N7 carve-out noted); O3→d2,d12; O4→d5–d10,d16; O5→d14; O6→d12,d17; O7→d0,d11; M6→d15,d20,d21; N2 minted as d19 (no query tool on judge legs).
Key probes: judge bash executes through the box today — `deps.box.run_parsed` (runtime/tools.py:310) + `--network=none` (box.py:457) + docker-exec-curl transport — so the "lane already dead, restoration not preservation" sequencing claim holds (x1); JUDGE_DEF `tools=ToolSet(read=True, bash=True)`, all ToolSet bits default False, so M3's default-off premise holds (x6); verb signatures ground d3's exact param sets {label,q}/{key} (x8); the "does not survive on that basis" instruction lives BOTH at judge/run.py:80-84 (inside the section M6 rewrites) and benign.md:148 — d16 guards its survival (x2).
Red-flagged anchor drift only: JudgeWiring is at learning/core/config.py:389 (doc cites judge/run.py:159-164 — those are its use site); policy_cli is defender/scripts/policy_cli.py, and its :51 demo scope pointing at case_history/case_ticket.py (the latent wrong-script bug M6 removes) is confirmed live.

## Red flags
- Demand #0 is `provisional: true` (fork f1, recording/observability of tool reads unspecified) — must route to §7; phase C must not treat the record-free reading as settled.
- Doc anchor drift (content verified, location wrong): `JudgeWiring` is defined at `defender/learning/core/config.py:389`, not judge/run.py:159-164 (that is `invoke_judge`'s consumption of it); `policy_cli.py` is `defender/scripts/policy_cli.py`. Neither refutes any claim — c9/c11/c12's mechanisms all verified at their real locations.
- `policy_cli.py:51` latent bug confirmed live: the judge demo `RunScope(ticket_cli=...)` points at `scripts/case_history/case_ticket.py`, not the real CLI `scripts/adapters/ticket_adapter.py` — M6's deletion removes it, as the doc says.
- The teaching-surface instruction O4/d16 depends on exists in TWO places (judge/run.py:80-84, inside `_cited_policy_read_section` which M6 rewrites; benign.md:148, outside item 7): the rewrite must not orphan either.

## Demands

Addresses follow references/schema.md forms. Ids are code names where code exists; `closed_tickets`, `get_closed_ticket`, `list_closed_tickets` are the doc's proposed names (fork f2). `discharged_by` names the stub each `form: test` demand points at; its outcome sentence is in "Docstring seeds" below (authored once, destined for the test docstring — no `outcome` on test demands).

```yaml
- id: d0_tool_result_envelope
  kind: behavior
  form: test
  provisional: true   # fork f1 — recording unspecified; pinned reading: record-free, view inline
  binds: ["interacts(benign_judge->get_closed_ticket).response", "interacts(benign_judge->list_closed_tickets).response"]
  discharged_by: test_tool_result_envelope
- id: d1_benign_registration
  kind: seam
  form: test
  binds: ["closed_tickets", "interacts(benign_judge->get_closed_ticket)", "interacts(benign_judge->list_closed_tickets)", "JudgeWiring.closed_ticket_read"]
  discharged_by: test_benign_leg_registers_closed_ticket_tools
- id: d2_adversarial_absent
  kind: negative      # positive control: d1 (same stage-build seam, wiring bit on)
  form: test
  binds: ["interacts(adversarial_judge->get_closed_ticket)", "interacts(adversarial_judge->list_closed_tickets)", "closed_tickets.domain.distinguished[false]"]
  discharged_by: test_adversarial_leg_has_no_ticket_tools
- id: d3_schema_closed_by_construction
  kind: shape         # exactness subsumes the negative (no require_closed, no status)
  form: test
  binds: ["interacts(benign_judge->get_closed_ticket).payload", "interacts(benign_judge->list_closed_tickets).payload"]
  discharged_by: test_tool_schemas_have_no_status_or_require_closed
- id: d4_body_pins_closed
  kind: behavior
  form: test
  binds: ["interacts(get_closed_ticket->ticket_store)", "interacts(list_closed_tickets->ticket_store)"]
  discharged_by: test_bodies_hardcode_require_closed
- id: d5_nonclosed_refused_as_fault
  kind: domain-outcome
  form: test
  binds: ["ticket_store.domain.distinguished[open]", "interacts(benign_judge->get_closed_ticket).response"]
  discharged_by: test_open_ticket_refused_as_failed_result
- id: d6_unreachable_store_fault
  kind: behavior
  form: test
  binds: ["interacts(get_closed_ticket->ticket_store)", "interacts(benign_judge->get_closed_ticket).response"]
  discharged_by: test_unreachable_store_is_failed_result
- id: d7_unmapped_fault_enveloped
  kind: behavior
  form: test
  binds: ["interacts(benign_judge->get_closed_ticket).response"]
  discharged_by: test_unmapped_fault_returns_envelope
- id: d8_single_attempt_no_retry
  kind: negative      # positive control: the attempt observed in d5/d6; minted from O4's "never a retry loop"
  form: test
  binds: ["interacts(get_closed_ticket->ticket_store)"]
  discharged_by: test_store_fault_single_attempt
- id: d9_control_flow_reraise
  kind: behavior
  form: test
  binds: ["get_closed_ticket", "list_closed_tickets"]
  discharged_by: test_control_flow_exceptions_propagate
- id: d10_model_retry_malformed
  kind: behavior
  form: test
  binds: ["interacts(benign_judge->get_closed_ticket).payload"]
  discharged_by: test_malformed_key_model_retry
- id: d11_untrusted_wrap
  kind: shape
  form: test
  binds: ["interacts(benign_judge->get_closed_ticket).response", "interacts(benign_judge->list_closed_tickets).response"]
  discharged_by: test_returns_salt_wrapped_untrusted
- id: d12_bash_grants_exact
  kind: behavior      # exactness = positive (cat+defender-sql present) and negative (no ticket shape) at once
  form: test
  binds: ["judge_bash_grants"]
  discharged_by: test_judge_bash_grants_exactly_cat_sql
- id: d13_in_process_host_side
  kind: seam
  form: test          # discharged largely by construction: every drive goes through the deps seam
  binds: ["get_closed_ticket", "list_closed_tickets", "ticket_adapter_verbs"]
  discharged_by: test_tools_drive_verbs_in_process_via_deps
- id: d14_cli_surface_survives
  kind: survival
  form: test
  binds: ["ticket_adapter_cli", "interacts(ticket_seeds->ticket_adapter_cli)", "interacts(verify_forward->ticket_adapter_cli)", "ticket_adapter_cli.domain.distinguished[64]"]
  discharged_by: test_cli_exit_codes_survive_for_subprocess_consumers
- id: d15_teaching_teaches_tool
  kind: behavior
  form: test
  binds: ["cited_policy_read_section", "benign_prompt"]
  discharged_by: test_teaching_surfaces_teach_tool_not_bash
- id: d16_cited_seed_instruction_survives
  kind: survival
  form: test
  binds: ["cited_policy_read_section"]
  discharged_by: test_cited_seed_instruction_survives
- id: d17_deny_reason_matches_grants
  kind: behavior
  form: test
  binds: ["judge_deny_reason", "judge_bash_grants"]
  discharged_by: test_deny_reason_matches_shrunk_grants
- id: d18_store_route_census
  kind: negative      # positive control: d1+d4 (the typed tools DO reach the store); re-probes claim r1 against the built policy
  form: test
  binds: ["ticket_store.access[typed-tool]", "ticket_store.access[bash]", "ticket_store.access[read-tool]"]
  discharged_by: test_benign_store_routes_census
- id: d19_no_query_tool_on_judge
  kind: negative      # minted from N2 (independently observable); positive control: d1
  form: test
  binds: ["interacts(benign_judge->query_tool)", "interacts(adversarial_judge->query_tool)"]
  discharged_by: test_no_query_tool_on_judge_legs
- id: d20_bash_plumbing_removed
  kind: negative
  form: clause        # recorded downgrade: field-level absences are implementation structure; their observable consequences are pinned by d12/d15/d17
  binds: ["RunScope.ticket_cli", "_ticket_grant", "_ticket_cli_path", "policy_cli_judge_demo"]
  outcome: {nl: "The bash-side plumbing is deleted: _ticket_grant and its wiring branch, the RunScope.ticket_cli / ResolvedRoots.ticket_cli threading, the judge-side carrier with its pinned command text and _ticket_cli_path, and policy_cli.py's judge demo scope — removing its latent wrong-script bug (it points at case_history/case_ticket.py, not the real CLI)."}
  rejected: [{nl: "No runtime direction check replaces the grant — the adversarial property is absence by registration (N3)."}]
- id: d21_stale_censuses_updated
  kind: negative
  form: clause        # recorded downgrade: suite/graph/prose maintenance, not e2e behavior; conservation rides censuses c11/c15
  binds: ["ticket_adapter_cli", "judge_bash_grants"]
  outcome: {nl: "Every surface still teaching or checking the deleted bash lane is retired or updated per censuses c11/c15: the grant-regex tests (test_judge_pydantic_engine.py:215-310, test_grant_gate_575.py:717-748 e1-e3, test_bind_sole_seam_551.py:238-262) and learning/test_loop.py:1837-1857's scope.ticket_cli assertion; the spec-graph nodes across spec_graph_575/551/538/611; and the comment/docstring censuses (adapter docstring three-to-two consumers, permission/bash.py:182,331, grant.py:196-205 three-exemptions-to-two, policy_cli.py:44-49,77-83, _stub_transport.py:78, engine_pydantic.py:5-6,102, defender/CLAUDE.md)."}
```

### Rejected-branch notes to transfer onto tests (phase E)

- d1: N6 — presence is a `ToolSet` bit on the built definition, never a conditional buried in a body; extending `defender-policy show` stays out of scope (it does not display the `query` bit today either).
- d2: N3 — no runtime direction check as the adversarial defense; the property is absence by registration.
- d3: N5 — no write verb is exposed; the adapter stays read-only (`ticket_writer.py` is a separate concern). Also: two tools, deliberately no operation discriminator (M1).
- d6: scale-dive tradeoff — no outer wall-clock budget; the transport's mandatory inner timeout (x4) is the only kill, the same tradeoff the query tool accepted.
- d13: N1 — no network egress through the box, which stays `--network=none`; N4 — the gather-side `VERBS` registry and six CLI-less adapters are untouched (a fourth consumer over the same two verb bodies, not a rework).
- d18: N7 — investigation-time ticket payloads cached under `gather_raw/` are a pre-existing surface, identical before and after; the judge reads them by design. O2 governs only the live-store read.

## Docstring seeds (phase E — authored once, one per test demand)

- test_tool_result_envelope: "Both closed-ticket tools return a plain string as a normal tool result — success is the verb payload's view inside the salted untrusted envelope, a fault is its exit-code class with the salt-wrapped detail — never a raised exception, never a structured object. [provisional per fork f1: record-free, view inline]"
- test_benign_leg_registers_closed_ticket_tools: "The benign judge leg's built agent registers exactly the two closed-ticket tools (list + get), carried by the closed_tickets ToolSet bit set per-leg from JudgeWiring.closed_ticket_read on the stage-build replace seam — JUDGE_DEF's static default keeps the bit off."
- test_adversarial_leg_has_no_ticket_tools: "The adversarial judge leg's built agent schema contains no closed-ticket tool — absence by registration; positive control: the benign leg registers them through the same seam with the wiring bit on."
- test_tool_schemas_have_no_status_or_require_closed: "The model-facing schemas expose exactly label/q on list-closed-tickets and exactly key on get-closed-ticket — no require_closed, no status parameter: closed-only is unreachable by construction, never model-chosen."
- test_bodies_hardcode_require_closed: "The tool bodies call the existing verb bodies in-process with require_closed=True hard-coded: the outgoing store query pins status=closed on list, and get refuses a non-closed ticket — observed through a stub transport injected on the deps seam."
- test_open_ticket_refused_as_failed_result: "Driving get-closed-ticket on the open in-flight ticket returns a failed tool result carrying the exit-1 class detail and none of the ticket's content — the answer key stays unreadable through the live-store read."
- test_unreachable_store_is_failed_result: "An unreachable ticket store surfaces as a failed tool result carrying the infra fault class (exit-2) detail — the judge run continues."
- test_unmapped_fault_returns_envelope: "A fault nobody mapped — a BaseException (e.g. SystemExit) out of the transport — comes back as the fault-class envelope in a normal tool result; nothing unwinds out of agent.iter()."
- test_store_fault_single_attempt: "On a store fault the tool makes exactly one transport attempt — never a retry loop."
- test_control_flow_exceptions_propagate: "Control-flow exceptions (the breaker's RunAborted, CancelledError, ModelRetry) re-raise out of the tool body instead of being swallowed into a fault envelope."
- test_malformed_key_model_retry: "A malformed call — missing or ill-formed key — raises ModelRetry (the validator-reject idiom) and makes no store attempt."
- test_returns_salt_wrapped_untrusted: "Every remote-sourced string the tools return — success views and fault detail alike — rides inside the salted untrusted envelope; no bare ticket-store free text reaches the judge."
- test_judge_bash_grants_exactly_cat_sql: "The benign judge's compiled bash grant set is exactly cat + defender-sql — no ticket shape remains on any bash lane, either leg."
- test_tools_drive_verbs_in_process_via_deps: "The tools execute the existing ticket_adapter verb bodies in-process on the host — a VerbContext built from ctx.deps, off the event loop — so a stub transport injected through the deps seam is what every drive observes: no subprocess, no box."
- test_cli_exit_codes_survive_for_subprocess_consumers: "The adapter CLI's argv grammar and pinned exit codes 0/1/2/64 survive unchanged: ticket_seeds._list_closed and verify_forward._fetch_closed_resolution still complete as subprocess consumers, and 64 stays the usage-error class the circuit breaker keys on."
- test_teaching_surfaces_teach_tool_not_bash: "The benign judge's teaching surfaces — the cited_policy_read section and benign.md item 7 — instruct the typed closed-ticket tools and carry no bash command text (no ticket_adapter.py invocation, no --require-closed argv), while keeping the in-flight-key warning and the candidate seed menu."
- test_cited_seed_instruction_survives: "The instruction that a cited seed the store can't confirm, or whose grounded conditions the actuals contradict, does not survive on that basis continues to govern after the rewrite — present in the rewritten section, with benign.md:148's fuller statement untouched."
- test_deny_reason_matches_shrunk_grants: "_JUDGE_DENY_REASON names only what the shrunk lane grants — the stale pinned-closed-ticket-read clause is gone — and the existing suite check of the reason against the live grant list holds."
- test_benign_store_routes_census: "Surface census over the built benign policy: the two typed tools are the only model-reachable route to the live ticket store — every bash grant (cat/defender-sql) and read_file opens mounted files only, and no other registered tool reaches HTTP."
- test_no_query_tool_on_judge_legs: "Neither judge leg registers the generic query tool — the closed-ticket capability arrives only as the dedicated closed-only tools, so require_closed can never become a model-chosen parameter with a default."

## Claims

Inherited from the doc's `claims:` block, echoed by id (16 — none re-derived; extensions and drift noted in the raised claims):

- inherited: c1 (dual-surface adapter — re-confirmed in passing while reading verbs)
- inherited: c2 (get refuses non-closed: UpstreamFault exit-1 — refusal site re-read at ticket_adapter.py:95-108)
- inherited: c3 (list pins status=closed)
- inherited: c4 (unreachable → exit 2)
- inherited: c5 (verbs importable/callable in-process)
- inherited: c6 (three non-test argv consumers)
- inherited: c7 (registration-only authorization for typed tools)
- inherited: c8 (query-tool in-process dispatch precedent)
- inherited: c9 (adversarial already grantless; wiring reaches grants only)
- inherited: c10 (box denies network — box.py:457 re-confirmed)
- inherited: c11 (M6 deletion-site census — spot-checked: engine_pydantic grants branch, judge/run.py carrier, test_loop.py:1837-1857 assertion, policy_cli demo all present as listed)
- inherited: c12 (per-leg replace seam + defn.tools registration — re-read at _pydantic_stage.py:66, driver.py:218)
- inherited: c13 (query-tool error seam + salt-wrap idiom — re-read at query_tool.py:316-333,403-409)
- inherited: c14 (two teaching surfaces + deny reason, suite-visible)
- inherited: c15 (spec-graph node census)
- inherited: r1 (unrefuted reachability census — d18 is its mandated re-probe against the built policy)

Raised by this pass (behavior/referential facts the doc asserts outside its ledger — each probed):

```yaml
- {id: x1, kind: behavior, claim: "the judge's bash lane executes through the network-denied box today, so the bash-side ticket read is dead in-box and sequencing is restoration, not preservation", probe: "read runtime/tools.py:310 (deps.box.run_parsed on the shared bash tool path), box.py:457 ('--network','none'; the :95-105 knob downgrades runsc->runc only, never opens the boundary), _stub_transport.py:188-218 (transport is docker-exec curl with mandatory timeout)", probe_kind: read, observed: "bash tool -> deps.box.run_parsed -> boxed exec; no network, no docker socket in-box", verdict: holds}
- {id: x2, kind: referential, claim: "the 'cited seed the store can't confirm does not survive on that basis' instruction O4 says continues to govern exists today, in two places", probe: "grep 'not survive|confirm' over judge package", probe_kind: search, observed: "judge/run.py:80-84 (inside _cited_policy_read_section, the section M6 rewrites) and benign.md:148 (outside item 7's command teaching)", verdict: holds}
- {id: x3, kind: referential, claim: "exit 64 is the documented usage-error class and the exit-code taxonomy is what the subprocess callers and the circuit breaker key on", probe: "read ticket_adapter.py:31 and main()'s AdapterFault handler comment ('the three subprocess callers (and the circuit breaker behind them) key on it')", probe_kind: read, observed: "as claimed", verdict: holds}
- {id: x4, kind: behavior, claim: "the transport's inner timeout is mandatory on every fork, and the CLI consumers hold their own subprocess timeouts today (the pair the scale-dive tradeoff swaps)", probe: "read _stub_transport.py:188,210-218 ('timeout is MANDATORY on every fork ... the only real kill left'); ticket_seeds.py _LIST_TIMEOUT_SEC=15 used at :75; forward.py _POLICY_FETCH_TIMEOUT at :125", probe_kind: read, observed: "as claimed", verdict: holds}
- {id: x5, kind: referential, claim: "the forward_check deferred-tool precedent M1 cites exists exactly as cited", probe: "read learning/author/verify_forward/tool.py:277-290 (register_forward_check_tool), runtime/tools.py:562-580 (_register_deferred_tools at :565, forward_check bit at :575)", probe_kind: read, observed: "as cited", verdict: holds}
- {id: x6, kind: referential, claim: "JUDGE_DEF's static tools are ToolSet(read=True, bash=True) and every ToolSet bit defaults False, so a new closed_tickets bit is off by default — M3's premise", probe: "read engine_pydantic.py:153-161, agent_definition.py:68-90", probe_kind: read, observed: "as claimed; judge built via build_stage_agent (engine_pydantic.py:23), i.e. through the replace seam", verdict: holds}
- {id: x7, kind: referential, claim: "two doc anchors drifted in location but not content: JudgeWiring is defined at learning/core/config.py:389 with the closed_ticket_read field (judge/run.py:159-164 is its use site), and policy_cli.py is defender/scripts/policy_cli.py whose :51 judge demo scope points at case_history/case_ticket.py — the latent wrong-script bug, live as the doc says", probe: "grep 'class JudgeWiring' defender/ ; find policy_cli.py; read scripts/policy_cli.py:43-58", probe_kind: search, observed: "as stated", verdict: holds}
- {id: x8, kind: behavior, claim: "the verb signatures ground d3's exact model-facing param sets: list_tickets takes status/label/q/require_closed (so the tool schema must expose only label/q), get_ticket takes key/require_closed (so only key)", probe: "read ticket_adapter.py:85-115 (signatures and param assembly; require_closed overrides any stray status into status=closed)", probe_kind: read, observed: "as claimed", verdict: holds}
```

## Forks

- f1 (feeds demand #0, `provisional: true`): the design pins the return envelope (plain string, salt-wrapped view/detail, `_format_bash_result`/`_model_view` idiom) but is silent on **observability of the reads**: the query tool it mirrors also records every call as a queries-table row, persists the payload to disk, and returns a truncated view plus payload-path note for large payloads (query_tool.py:316-333); the cited idiom span for the new tools (423-446) does none of that. Pinned provisional reading: **record-free — the view rides inline, no row, no truncation note**. Alternative: mirror the capture too. Decides what every success-path test asserts and whether an audit trail of judge ticket reads exists.
- f2 (naming, low impact but the doc marks it a proposal): ToolSet bit `closed_tickets` and the two tool names (here coined `list_closed_tickets` / `get_closed_ticket`). The graph joins to code by name (schema.md, "Coin ids"), so §7 should confirm before phase E freezes test names.

## Background

Explicitly classified — neither normative nor a fresh reality claim (already-laddered facts point at their claim):

- bg1: the adapter's deliberate dual-surface history (VERBS + one surviving CLI) — rides c1.
- bg2: #611 precedent — in-process verb calls, six CLIs killed — rides c8.
- bg3: #338 origin story — why closed-only is the grant's entire security property.
- bg4: the judge as one wiring-parametrized driver, two legs over one frozen AgentDefinition — rides c12/x6.
- bg5: the doc's §Review narrative (cold-review process, findings reconciled) — process record, no obligations.
- bg6: issue-body provenance (spun out of #665, decided at its seam; the "why" narrative) — its facts ride c9/c10/x1, its norms are O1-O7/N1.
- bg7: sequencing note ("lands before the #665 boxing spec reruns") — process ordering; grounded free by x1.
- bg8: security-dive asset naming (the store; the open in-flight ticket as answer key) — framing for O2/O3/O7, no separate obligation.
- bg9: scale-dive "does not fire" rationale — its factual half is x4; its tradeoff rides d6/d14's rejected notes.

## Sentence-sort conservation

Every doc section accounted; no sentence outside the sort:

| Doc section | Sorted to |
|---|---|
| Issue body — why / decision / constraints / open questions | bg6, bg7; facts→c9,c10,x1; norms restated by O1-O7,N1 (no independent demand minted from the body) |
| O1 | d1, d13 (+d0 return contract) |
| O2 | d3, d4, d5, d18 |
| O3 | d2, d12 |
| O4 | d5, d6, d7, d8 ("never a retry loop" minted), d9, d10 via M4; instruction clause→d16, fact→x2 |
| O5 | d14; facts→x3, x4 |
| O6 | d12, d17 |
| O7 | d0, d11 |
| N1-N7, scale dive | rejected notes on d1,d2,d3,d6,d13,d18; N2 minted as d19; scale-dive fact→x4, bg9 |
| M1 | d1, d13; facts→x5, c7, c8 |
| M2 | d3, d4; facts→c2, c3, x8 |
| M3 | d1, d2; facts→c12, x6, x7 |
| M4 | d0, d6, d7, d9, d10, d11; facts→c13 |
| M5 | d14, docstring census→d21 |
| M6 | d12, d15, d16, d17, d20, d21; facts→c11, c14, c15, x2, x7 |
| Background paragraph | bg1-bg4 |
| Security dive | d18 (O2 census), d2+d12 (O3 census), d11 (O7); framing→bg8 |
| Claims block | 16 inherited, echoed above |
| Review section | bg5 |
