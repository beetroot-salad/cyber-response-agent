# Can the gather model use defender-sql's times? — #1125 / #1126 / PR #1129

## Question

**Engineering**: under which `defender-sql` time contract does `glm-5.3-flash` (the gather model)
state correct times, orders and window verdicts on the SQL moves it actually makes? And does any
contract change matter enough to ship, beyond not crashing?

### What gather does today (surveyed before planning)

From the wire logs of `gather-flash-port` + `glm53-container-attribution` (224 gather dispatches):

- 22 dispatches (~10%) used `defender-sql`, 113 calls in all; 49 of those calls touch a time.
- The moves: project `@timestamp`/`falco.time` to report them; `ORDER BY ts`;
  `MIN(first_seen)`/`MAX(last_seen)` across groups, including `MIN(v[2]->>'$')` on ES|QL rows;
  filter "events after 09:54:52". **It never casts a time.** No `now()`, `date_trunc` or durations.

From the 1,631 real payloads those runs fetched:

- Within one field, times are spelled uniformly: 4 of 1,819 payload fields mixed spellings.
- Between fields they differ. ES `@timestamp` has 3 fraction digits and `Z` (29k values).
  `falco.time` has 9 digits and `Z` (423). Change tickets' `window_start`/`window_end`/`created`
  carry `+00:00` offsets (~1.4k).

So the risk to test is not mainly the lexical-MIN trap. It is **two time fields in one result in
different forms** (main converts ms-`Z` and offset fields, leaves nanosecond fields as text), plus
the rarer mixed-spelling and all-timestamp ES|QL rows.

## Step zero: grade what already happened (before any harness)

The 22 real dispatches that used `defender-sql` ran under `current`, with the real model in the
real loop. Their summaries are in `gather_summaries/` and their payloads in `gather_raw/`. For each
time claim a summary makes, check it against the payload: is it right, and if it's wrong, can the
error be traced to the tool's time handling (two forms in one result, a converted value, a crash)?

- **No time-handling errors in those 22:** the #1125 question is largely settled. The run shrinks to
  #1126's crash fix, and the harness below runs only if we still want the duck-json vs pr answer.
- **Errors found:** they become fixtures, replacing the synthetic perturbations (T3, T5) wherever a
  real case covers the same trap.

Cost: reading only, with no model calls. It needs one pass by me, or by a subagent blind to the arms.

## Variants

One variable: the `defender-sql` contract, meaning `sql.py` plus the `defender-sql.md` section that
teaches it. Everything else (gather prompt, model, effort, payloads, lead) is identical.

### current (regression validator): `main` @ a1c65801
DuckDB guesses types from the rows. A guessed timestamp is written `…000000Z`, the rest stays
source text, zoned results crash (no pytz). The doc has no time section. The shared venv now has
pytz (installed for the PR), so this arm's harness hides it (`sys.modules['pytz'] = None`, as the
PR's fetch-error test does), to match what `main` ships.

### pr: PR #1129 @ f423c37a
Loaded fields keep the source's text (date/timestamp guessing off; TIME/UUID still guessed).
Computed times are written `…000000Z` (UTC session). Durations are seconds. ES|QL row positions are
always JSON. The doc's "Times are text" section teaches `::TIMESTAMPTZ` and "never `::TIMESTAMP`".

### duck-json: prototype, not in the repo
- Load with no guessing: `read_json_objects` → `json_group_structure`, with ES|QL `values` declared
  `JSON[][]`.
- Output written by DuckDB (`to_json` per row), so no Python type bridge and no pytz. Computed times
  are spelled `2026-01-01 10:00:00+00`; durations are text (`1 month`).
- Doc: the pr doc's time section, reworded for these spellings.
- Lives in `variants/duck-json/sql.py`; the harness points at it. It needs its own quick test pass
  (the payload shapes in `tests/test_sql_idioms.py`) before validation.

The three `defender-sql.md` texts are checked in under `variants/<arm>/defender-sql.md`, and the
diff between them is quoted in `variants/README.md`.

## Harness

The whole-run loop is the wrong instrument: the variable fires in ~10% of dispatches, amid live
playground drift. Instead, a **single gather dispatch** per trial, built with the runtime's own
`build_gather_agent` (`runtime/driver/_build.py`):

- Model: `glm-5.3-flash` at gather's shipped effort (the provider clamps it to `low`).
- Prompt and skill texts: whatever `build_gather_agent` assembles, with the arm's `defender-sql.md`
  in place of the shipped one.
- Payload: served as if the `query` tool had fetched it. If `build_gather_agent`'s deps take a
  query backend, the fixture is injected there. If not, the payload is pre-placed as the dispatch's
  `gather_raw/<lead>/0.json` and the lead says a query already ran. Validation settles which.
- Answer: the lead asks for a closing line of named fields, which the harness parses. A `submit`
  tool would change gather's tool set.
- Budget: gather's real `GATHER_REQUEST_LIMIT` (40).
- Not included: MAIN, and the live playground. This measures SQL-over-payload skill on a fixed
  payload, not whether gather chooses SQL at all.

Validation diffs the assembled prompt against a real dispatch's (from the survey runs) and lists
every difference, rather than claiming they are identical.

## Fixtures

All built from **real payloads** in the runs above (shape-current), copied into `fixtures/`, with
minimal perturbation where noted. Every task has a machine-checkable truth computed offline in
`fixtures/<id>/truth.json` as instants (UTC), counts or row orders.

| id | payload (source) | lead / task | why it's load-bearing |
|---|---|---|---|
| T1 | Falco alert hits: `@timestamp` (ms `Z`) + `falco.time` (ns `Z`) | "Give the time of the first `authorized_keys` write, and whether Falco's own time agrees with `@timestamp` within 1 s" | main: two forms in one result, one converted, one not |
| T2 | sshd ES|QL STATS BY src/host, `first_seen`/`last_seen` positions (mixed row) | "Earliest first_seen and latest last_seen across all sources" | the observed `MIN(v[2]->>'$')` move |
| T3 | T2 with count columns dropped, so every value is a timestamp (perturbed) | same as T2 | all-timestamp row: main reads `2026-… 10:00:00` via `->>'$'` |
| T4 | change-mgmt tickets (`window_start`/`window_end` with `+00:00`) + the alert time | "Was the alert inside any approved change window? Name the ticket" | offset vs `Z` comparison; main converts, pr keeps text |
| T5 | T4 with one ticket re-spelled in `+02:00` (same instant; perturbed) | same as T4 | where the text comparison actually lies |
| T6 | auth hits spanning 09:54 (real) | "How many events after 09:54:52, and the first one's time?" | the observed filter move |
| T7 | T6 | "Give `${start}`/`${end}` for a follow-up ES query covering first→last event ±5 min" | a computed time bound back into ES: must be a valid `strict_date_optional_time` |

`submit` takes the task's fields (times as strings, counts, ticket ids). Grading is automatic:

- time answers are parsed with a tolerant ISO parser and compared to the truth instant; a string
  that doesn't parse counts as wrong
- T7 bounds must also match ES's `strict_date_optional_time`
- counts and ids must match exactly

## Trials

- **Validation:** 1 per arm per fixture = 21 dispatches. Confirms that prompt assembly matches,
  effort reads `low` on the wire, every arm's `sql.py` runs every fixture, the truths are right (I
  answer each task by hand once), and `analyze.py` extracts every metric.
- **Scale-up:** N=10 per arm per fixture = 210 dispatches. At a few cents each on flash, well under
  $10. Run 3 arms concurrently, interleaved per trial index.
- **Mid-run analysis:** at trial index 3 (30%), run `analyze.py`. Abort an arm whose completion
  (a `submit` within budget) is under 80%. Stop the whole run early if all arms are ≥ 95% correct
  on every fixture: the answer is then already "no difference".
- **Analysis script:** `experiments/sql-time-contract/analyze.py`, written before scale-up.

Per dispatch, `analyze.py` records:

| metric | from |
|---|---|
| `correct` (all fields of the task right) | submit vs truth |
| `completed` | a submit within budget |
| `sql_calls`, `sql_errors` (exit ≠ 0), `tracebacks` | bash results |
| `casts` (any `::TIMESTAMP[TZ]`/`strptime` in its SQL), `plain_timestamp_cast` (`::TIMESTAMP`) | its SQL |
| `requests`, tokens | wire |

Report per arm × fixture: correct-rate with n, mean requests, cast rate. No count-weighting.

## Decision criteria

Correctness is the primary metric, per fixture and pooled over T1–T7.

- **current retained, #1125 closed won't-fix** if every fixture's correct-rate under current is
  within 5 points of the best arm. Ship only #1126's crash fix (fetch inside the error handling),
  and decide pytz vs `to_json` on cost alone.
- **pr wins** if its pooled correct-rate is ≥ 10 points over current and no fixture is > 5 points
  worse.
- **duck-json wins over pr** if its pooled correct-rate is within 5 points of pr's and its T7
  (bind-back) is not > 5 points worse. It is the smaller and simpler core, and it drops pytz.
  T7 only tells them apart if the model computes a time (casts, or takes MIN/MAX of a cast). If
  its cast rate is ~0, it copies source text under every arm, the spelling of computed times is
  moot, and duck-json wins on simplicity alone.
- **Guidance signal, whichever arm wins:** if the cast rate stays ~0 under pr/duck-json, the
  "cast with `::TIMESTAMPTZ`" teaching doesn't land. The contract then has to be right *uncast*,
  which argues for spelling uniformity over casting rules.

## Layout

```
experiments/sql-time-contract/
  plan.md
  variants/{current,pr,duck-json}/{sql.py,defender-sql.md} + README.md (quoted diffs)
  fixtures/T1..T7/{payload*.json,lead.md,truth.json}
  harness.py            # one dispatch: arm × fixture × trial → runs/<arm>-<T>-t<n>/
  runs/
  analyze.py            # written before scale-up
  results/
```
