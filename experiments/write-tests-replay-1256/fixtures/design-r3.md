# #1256 — Decide a system's usability at run start, not by failing calls

Design revision r3 — decided. r1 independently reviewed, findings reconciled here; D2 and D3 decided by the human (2026-10-15). r3 (2026-10-15): D4 decided by the human during write-tests; text corrections from the contract review. Direction (startup check) chosen by the human. Grounding base: `d7b1886d`.

## Problem and intended change

A system whose settings are missing or unusable fails every call with exit 2, the same code as an outage. The circuit breaker sees only the code, so today:

- an unconfigured system costs two failed calls before it is marked down;
- every such failure counts toward the run-wide abort (5), so three unconfigured systems (2+2+1) abort a run whose configured systems answered fine, with a message blaming an unreachable environment.

Yet whether a system is configured is fixed before the agent's first call: the run reads every system's `config.env` once into its tenant record and no adapter re-reads settings (O1/O2, #1107). The run discovers a fact it already holds, one failed call at a time.

**Change.** At run start, each granted system is judged usable or not by its own adapter's settings check, run over the frozen record. A system that fails the check is *down for this run* from the start, with its reason: the agent is told so before it plans, every dispatch or call to it is refused without running the adapter, and the breaker never sees it. The breaker then counts only failures that can change during a run.

Before: three unconfigured systems → agent dispatches to each, 5 failed calls, run aborted "environment appears unreachable or unconfigured".
After: the run starts with those three listed as "not configured: <reason>"; the agent never calls them; the configured systems carry the run; no abort.

## Principles

Inherits `docs/principles.md`. Applied here:

- **P2 fail closed, loud, fast — at the first point the condition is visible.** Settings are visible at run start, so that is where an unusable system is judged.
- **P3 no apologetic programming.** No second call-time lane for adapters that "didn't declare" a check: every adapter declares its settings check, and a call-time config fault ceases to exist as a runtime outcome.

Design properties (adopted with this design):

- **DP1 — A fact fixed at run start is decided at run start.** Anything about a system that cannot change during the run (its settings, its access method) is judged once, before the agent starts, and is never inferred from call outcomes.
- **DP2 — The breaker counts only what can change during the run.** Its causes are outages, errors, timeouts; "not configured" leaves its vocabulary.
- **DP3 — One check, one owner; one meaning for `ConfigFault`.** The adapter owns which settings it needs (system rules live with the adapter, #1215) and declares one settings check that covers every config fault any of its verbs can raise. `ConfigFault` means "this system is not configured for this run" wherever it is raised: if one ever escapes the startup check at call time, the system goes Down(NotConfigured) on the spot, uncharged, and the escape is logged as an adapter defect. This is not a second lane — it is the same status and the same accounting, reached late — and it makes an incomplete check harmless instead of reviving #1256.
- **DP4 — One notion of "down".** A system is down for a run with a cause — *not configured (reason)* set at start, or *tripped (n failures)* set by the breaker. Every gate that refuses a down system asks one question and the message names the actual cause.

## Intent

Obligations:

- **O-1** A granted system whose adapter's settings check fails at run start is down for the whole run, with the check's reason. No call to it runs the adapter.
- **O-2** No failure of a not-configured system is charged to the breaker, per-system or run-wide. A run's abort can only follow failures of systems that passed the startup check.
- **O-3** The agent learns at the start which granted systems are not configured and why — MAIN in its workspace view, gather in its system index and in `list_verbs` — and is told not to dispatch them and to name the visibility gap.
- **O-4** A dispatch or call to a not-configured system is refused with a message that names "not configured: <reason>", never "tripped by N infra failures".
- **O-5** Every adapter declares a settings check (a system needing none declares that). For each adapter, every `ConfigFault` any verb can raise is also raised by its check (observable per adapter: settings that make a verb raise make the check raise).
- **O-5a** A granted adapter that fails to import, declares no check, or whose check raises anything but `ConfigFault` is Down(AdapterBroken(reason)) from the start, logged loudly; no call to it runs and none is charged. (Detection is by importing at start, which already happens; so this is entailed by the startup check, not added scope.)
- **O-5b** A `ConfigFault` raised at call time marks its system Down(NotConfigured) immediately, uncharged, and logs an adapter defect.
- **O-6** The correlation lead (lead zero) on a system down at start ends before it claims its lead or spends a gather count (as the withheld ending does), with its own ending naming the cause, distinct from "tripped breaker" and "every call failed". It never becomes a run refusal: the correlation grant check at start does not consult usability.
- **O-8** A run where no granted system is usable at start (every one down) is refused at start, naming each system and its reason — the existing "gather can query nothing" refusal, applied to the systems granted and up. Amends #1107's O5 for this case only (decided D3). A run-start refusal only: `tenant.py setup` does not refuse it (decided D4). An adapter whose source does not parse stays what it is today, a grant refusal at roster read (C11), not Down(AdapterBroken).
- **O-9** A branch sibling runs the same startup check over its own resolved settings; a system down there is down in that sibling even if the source run's capture holds answers for it (decided D2).
- **O-7** The operator sees, at run start, each granted system that is down and why (a start log line per system).

Non-obligations:

- No change to what a configured system's outages cost: limits, harness-lead `counts_toward_run`, messages for tripped systems.
- No verb-level granularity. Census found no verb whose settings differ from its system's (elastic's Kibana container is only read by `health_check`, which checks it first). A future verb-level need would extend the check's result, not this design.
- Rows: a refused call to a down system writes no query row today (breaker refusal); not-configured refusals follow that. Making refusals visible to offline readers is a separate gap.
- The run is not refused because some systems are unconfigured (O5 of #1107 stands), except when none is usable (O-8).
- Pre-flight replay (branch CLI) calls adapters directly with no run state or gates; it keeps seeing call-time faults. The case-history ticket writer keeps its own lane. Neither is in scope.
- Resumed runs: MAIN's resume prompt is not rebuilt; the rebuilt gather index, `list_verbs`, and dispatch refusals carry the down status. No resume-prompt change.
- Elastic's requirement of `KIBANA_URL` while the Kibana container is optional is an elastic config inconsistency; follow-up, not here.

## Design

### Model

Per run, a **system status** per granted system, held on the run's state:

```
SystemStatus = Up | Down(cause)
cause        = NotConfigured(reason: str)      # set at start (or on an escaped ConfigFault)
             | AdapterBroken(reason: str)      # set at start: import failed, no declared check,
                                               #   or the check raised something other than ConfigFault
             | Tripped(failures: int)          # set by the breaker during the run
```

`NotConfigured` is stored, derived once from the frozen record; `Tripped` is the breaker's existing count. A system cannot move from Down back to Up within a run (unchanged). A not-configured system is never charged, so it can never also be Tripped.

### Adapter declaration

Each adapter module declares a settings check: a pure function of the run's tenant record that raises `ConfigFault` naming what is wrong, covering every config-fault site its verbs can reach. Today those sites are spread out: for the five `_stub_transport` adapters, `load_config` + `access_context`; host-state, `access_context`; elastic, `load_config` + its ES container key (`_es_container`, read on every request path but not checked by `load_config` — the review's demonstrated defect in r1). tacit-knowledge declares that it needs none. How the check is factored against the existing loaders (one function or a wrapper, `VerbContext` vs tenant record) is the implementer's, bounded by O-5; callers that keep the loader signature include `ticket_writer`, the connect example adapter, and pre-flight.

### Flow at run start

1. Tenant resolved (`RunTenant.systems` frozen) — unchanged.
2. Roster read; adapters imported for granted systems. This import already happens today at startup (`descriptor_catalog` for gather's system index).
3. **New:** for each granted system, run its declared check over the record → status Up or Down(NotConfigured(reason)). Log one line per down system (O-7).
4. Statuses feed MAIN's workspace view, gather's system index, `list_verbs`, and the lead-zero dispatch decision.

### Flow at call / dispatch time

Every existing gate that asks "is this system tripped?" (gather dispatch, in-call check, lead zero) asks "is this system down?" and renders the down message from the cause. No adapter runs; no breaker charge; no query row (as for breaker refusals).

### Why not "effective grant = granted ∩ configured"

Treating an unconfigured system like an ungranted one would reuse the registry and need no status. It loses the visibility gap: an ungranted system reads as nonexistent by design (`list_verbs`: "your grant reaches no verb"), whereas a down system tells the agent to name the missing evidence in its ceiling-test row and escalate if it blocks disposition. A granted-but-unconfigured system is an expected source of evidence that is missing, so it must stay known and down. It would also route an unconfigured correlation system into the grant-agreement check, turning it into a run refusal.

### Siblings (branch worlds)

A sibling resolves its own tenant at its own start and runs the same startup check. A system unconfigured at sibling start is down in that sibling even if the source run's capture holds answers for it. Rationale: the sibling runs as the tenant does now; serving captured answers for a system the tenant cannot reach would make the world disagree with its own settings. (Arises only if settings changed between source run and branch.)

### What changes for existing contracts

- `test_1107_adapters::test_s7_mf8_config_fault_breaker_accounting_unchanged` pins "no config-fault exemption" — superseded by #1256.
- `test_1222_correlation_endings::test_p006…unconfigured` pins tripped/every-call-failed endings for an unconfigured correlation system — replaced by O-6.
- `e2e/test_query_tool_611::test_missing_config_is_infra_not_agent_fixable` — it drives a configured tenant with a verb that raises `ConfigFault`, so it becomes an O-5b case: the system goes down uncharged and the retry is refused. (r2 said "becomes a refusal"; corrected in r3.)
- `test_1222_correlation_dispatch::test_p134_tenants_siem_config_faulted_at_run_start` pins "nothing at run start names a faulted SIEM config" — superseded by O-3.
- `#1120`'s "setup refuses what run start refuses" parity now covers structure and grants, not system usability (D4).
- `INFRA_CAUSES` drops "not configured"; #1254's wording in `down_message`/`RunAborted` narrows back to reachability; `_tenants.py` doc line ("per-call ConfigFault, exit 2, trips the breaker") is rewritten.

## Decisions

- **D1 (resolved by review → O-5a).** Import failure is detected by the same startup import, so it is entailed.
- **D2 Siblings follow their own startup check — DECIDED yes (human).** → O-9. Settings drift between a branch's arm launches could make arms disagree on which systems are up; arises only from edits between launches.
- **D3 Every granted system down at start — DECIDED: refuse (human).** → O-8. Refuse the run at start, as the existing "gather can query nothing" grant check (`require_gather_query`) does, run over the systems that are granted and up. This amends #1107's O5 ("settings content never refuses a run") for this one case. Rejected alternative: keep O5; the run proceeds blind and ends inconclusive after spending budget.

- **D4 Setup and an all-down tenant — DECIDED: setup does not refuse (human, during write-tests).** Setup judges a tenant's structure (folder rules, grants, lead-zero config); its settings content may still be incomplete when it is adopted, and is filled in afterwards. O-8 is judged when a run starts, never by tenant-management commands. This scopes #1120 V14 ("any run-start refusal is setup's refusal") to structural refusals. Rejected alternative: O-8 in the shared readiness function, so setup refuses too.

## Review disposition

r1 reviewed by one independent reader at `d7b1886d`. Demonstrated defect (elastic ES container not covered by `load_config`) → DP3/O-5/O-5b. Unresolved choices closed: non-ConfigFault from a check (O-5a), escaped call-time ConfigFault (O-5b), lead-zero timing (O-6), resume and pre-flight (non-obligations), O-5 enforcement (O-5a, by import), D3 restated as an O5 amendment. r2 changes not re-reviewed: they close named findings without new interactions.

## Supporting grounding

```yaml
claims:
  - id: C1
    kind: behavior
    claim: "Today a ConfigFault counts toward per-system and run-wide breaker exactly like a TransportFault; N config-down systems abort at RUN_FAIL_KILL_LIMIT."
    probe: "cd defender && flock /tmp/defender-pytest.lock .venv/bin/python -m pytest -p no:xdist tests/tenant_1107_settings/test_1107_adapters.py::test_s7_mf8_config_fault_breaker_accounting_unchanged ::test_o5_missing_system_config_run_completes @ d7b1886d"
    probe_kind: executed
    observed: "2 passed"
    verdict: holds
  - id: C2
    kind: referential
    claim: "Settings are read once into RunTenant.systems at run start; no adapter re-reads config.env or the environment."
    probe: "run_tenant.py:62-68; _stub_transport.py:75 (all adapters read ctx.tenant.systems); grep for config.env / os.environ in adapters"
    probe_kind: search
    observed: "no re-read found"
    verdict: holds
  - id: C3
    kind: census
    claim: "Every ConfigFault raised by an adapter depends only on the frozen tenant record (no call params, network, docker or call-time files)."
    probe: "grep -rn 'ConfigFault(' defender --include=*.py | grep -v tests, each site read @ d7b1886d"
    probe_kind: search
    observed: "_stub_transport system_entry/access_context/load_config; tenant_settings read_env_file/read_systems; elastic load_config/_container — all over tenant record"
    verdict: holds
  - id: C4
    kind: census
    claim: "No verb-level config fault exists: every config fault a verb can raise is system-wide; elastic's Kibana container is read only by health_check, which checks it first."
    probe: "elastic_adapter.py:24-29,94-112,130-140,286,355,368-371,472; stub adapters' verb bodies"
    probe_kind: search
    observed: "system-wide holds. r1's sub-claim that load_config covers every fault is REFUTED: _http_json (every elastic request) calls _es_container, which raises ConfigFault for an unset ELASTIC_ES_CONTAINER that load_config never checks."
    verdict: holds
  - id: C11
    kind: referential
    claim: "A grant naming a system or verb with no adapter is refused at run start; case-history is never granted."
    probe: "systems/verbs.py ModuleVerbRegistry.__init__ (GrantError); reviewer read"
    probe_kind: read
    observed: "as claimed"
    verdict: holds
  - id: C12
    kind: referential
    claim: "require_gather_query refuses a run whose grants give gather no query verb."
    probe: "systems/verb_dispositions.py:152-163"
    probe_kind: read
    observed: "as claimed"
    verdict: holds
  - id: C5
    kind: referential
    claim: "Granted adapters are already imported at run start (descriptor_catalog → registry.verbs), silently dropping ones that fail to import."
    probe: "driver/__init__.py:383-395,565; hooks/inject_system_skill_description.py:40-60"
    probe_kind: read
    observed: "as claimed"
    verdict: holds
  - id: C6
    kind: referential
    claim: "No surface the agent sees (workspace map, gather system index, list_verbs) consults RunTenant.systems; unconfigured systems are shown like any other."
    probe: "driver:655-657 → workspace_map.py:93-95; tools_gather.py:220-232; query_tool.py:869-905"
    probe_kind: read
    observed: "as claimed"
    verdict: holds
  - id: C7
    kind: census
    claim: "Gates refusing a down system: tools_gather._tripped_message (in-call), tools_gather dispatch (~507), lead_zero (~220). Breaker refusals write no query row."
    probe: "grep -rn 'is_tripped' defender --include=*.py | grep -v tests"
    probe_kind: search
    observed: "3 sites"
    verdict: holds
  - id: C8
    kind: referential
    claim: "8 adapters: change_mgmt, cmdb, elastic, host_state, identity, tacit_knowledge, threat_intel, ticket. Five use _stub_transport.load_config; elastic has its own; host_state uses access_context only; tacit_knowledge has no config."
    probe: "ls defender/scripts/adapters; reads"
    probe_kind: search
    observed: "as claimed"
    verdict: holds
  - id: C9
    kind: referential
    claim: "Branch siblings run real adapters behind WorldRegistry, serving recorded answers first and calling the adapter live otherwise; a sibling re-resolves its tenant at its own start."
    probe: "learning/branch/estate/registry.py:264,391-438; run.py:679; branch/cli.py:384"
    probe_kind: read
    observed: "as claimed"
    verdict: holds
  - id: C10
    kind: referential
    claim: "ticket_writer's ConfigFault is the host-side case-ticket lane; it never reaches the breaker."
    probe: "scripts/case_history/ticket_writer.py:68-99"
    probe_kind: read
    observed: "catches AdapterFault, logs/receipts"
    verdict: holds
```


