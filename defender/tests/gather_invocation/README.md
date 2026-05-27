# Gather invocation tests

What we're testing: **when does gather fire §3.5's `data_source_debug.py`
wrapper?** Not the quality of gather's summary — only the trigger.

Each test = one fixture directory + one `claude -p` invocation of gather
against that fixture, run on Haiku (matching production). The harness
materializes a sandbox under `/tmp/gather-invocation-{fixture}-tN-...`, stubs
the system CLIs, runs claude, and reads back a trace file that records
whether the wrapper was invoked.

## Layout

```
fixtures/{name}/
  alert.json            # what gather Reads in §1
  elastic_payload.json  # what stub elastic_cli returns
  system_skill.md       # the system SKILL.md gather Reads in §1 (controls cache)
  dispatch.json         # dispatch parameters (system, goal, what_to_summarize)
  expected.json         # { wrapper_invoked: bool, rationale: str }
  dsd_verdict.txt       # optional override for stub data_source_debug output
stubs/
  elastic_cli.py
  data_source_debug.py
harness.py              # sandbox setup + claude -p invocation
test_invocation.py      # pytest wrapper, parametrized over fixtures
```

## Running

```bash
# Pytest
pytest defender/tests/gather_invocation/ -m llm

# Ad-hoc one fixture
python3 defender/tests/gather_invocation/harness.py F1_sentinel_no_cache --trials 3

# Keep sandbox after run (for postmortem)
python3 defender/tests/gather_invocation/harness.py F1_sentinel_no_cache --keep-sandbox
```

## Cost

~$0.02 per trial on Haiku. Full matrix (10 fixtures × 1 trial) ≈ $0.20.

## Calibration baseline

F1 (`F1_sentinel_no_cache`) is the load-bearing positive case — two
sentinel-valued declared fields, empty cache. Calibrated against the
gather SKILL as of `defender-v2-env` HEAD:

- Pre-rewrite (per commit 01207b1): 0/3 fire in three consecutive
  live runs — the failure that motivated the §3.5 design.
- Post-prompt-hygiene cleanup: 2/3 fire, all partial (1 call instead
  of 2) — model rationalized one sentinel inline.
- Post per-field rewrite: **3/3 fire, 2 calls each.** Per-field rule
  produces complete coverage.

## Why a real LLM and not a unit test

The trigger is a prompt-driven decision: Haiku reads the payload, the SKILL,
and decides whether to invoke the wrapper. There is no Python branch to
unit-test. Mock everything below the LLM (stub CLIs, fixture payloads), then
observe the model's behavior.

## Planned (not yet authored — would test mechanisms that don't exist in
the SKILL today; author the fixture *with* the mechanism, not before)

- **V3 sparse out-of-band** — auth events well below a template's
  declared `expected_volume` band. Expected: gather flags
  `payload_status: suspect_volume` and escalates. Requires a
  template-band mechanism in `gather/queries/SCHEMA.md` first.
- **A1 stale data** — populated rows but `max(@timestamp)` is far
  before the alert timestamp, indicating ingest lag. Expected:
  gather flags `payload_status: suspect_empty` with a lag reason.
  Requires a freshness check in the SKILL.

## Adding a fixture

1. Create `fixtures/{name}/` with the five files above.
2. Pick payload from a real run when possible — see
   `/tmp/defender-runs-v2/` for live artifacts. Synthetic payloads risk
   testing the harness, not the model.
3. If the fixture should xfail (gap in SKILL), add it to `_XFAIL_FIXTURES`
   in `test_invocation.py`.
