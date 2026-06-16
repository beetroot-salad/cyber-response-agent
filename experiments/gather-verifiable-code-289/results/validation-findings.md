# Validation pass — findings (n=1 per cell, directional)

Validation set: 6 cells (current|proposed × large-sshd-dump | healthy-small |
same-second-session). Large-dump + buried-same-second at `--request-limit 40`;
healthy-small at 20 (didn't bind). Judge: Sonnet, hand-calibrated (see below).

| fixture | variant | complete | A2 ↓ | exact/dim | replay | reqs | wall_s | out_tok |
|---|---|---|---|---|---|---|---|---|
| large-sshd-dump | current | **0/1** | **1.00** | 0/11 | 0.00 | 10† | 36 | 1732 |
| large-sshd-dump | proposed | 1/1 | **0.00** | 11/11 | 1.00 | 26 | 68 | 4910 |
| healthy-small | current | 1/1 | 0.18 | 9/11 | 0.00 | 18 | 79 | 6132 |
| healthy-small | proposed | 1/1 | **0.00** | 11/11 | 1.00 | 18 | 40 | 3389 |
| same-second (buried) | current | 1/1 | 0.12 | 7/8 | 0.00 | 19 | 61 | 4105 |
| same-second (buried) | proposed | 1/1 | 0.12 | 7/8 | 0.88 | 26 | 82 | 6705 |

† crashed: `ModelHTTPError prompt too long: 214159 > 200000` — see Finding 1.

## Findings

**1. Decisive reliability win on the large dump — and a hard failure for prose.**
`proposed` scored every dimension exact (11/11), including the A2 trap
`distinct_invalid_usernames = 5` (`healthcheck, monitorprobe, nagios, sensu,
zabbix`) that sample-estimation under-reports. `current` **blew the 200K context
window** on the 4 MB dump (the `read_file` tool is uncapped; prose gather pulls
too much in) and returned nothing → A2 = 1.0. At the production limit of 20 both
variants instead hit the request ceiling. So on a large dump prose gather is not
merely less precise — it can fail outright, two different ways. Code-first keeps
every intermediate output tiny (64 KB capped passthrough + small jq results) and
never loads the payload whole.

**2. Small fidelity edge even on a clean small payload.** On `healthy-small`
`current` dropped the precise first/last timestamps (gave a `May 5–7` range);
`proposed` reported exact values (11/11). Minor, but real, and free.

**3. The buried-needle case is parity, not a discriminator.** Once gather filters
to `dev.dana` (current via 3 narrowing queries, proposed via jq), the 6-record
session is easy to summarize — both reconstructed it (7/8; both omit only the
explicit "same-second" *boolean* while correctly reporting the open/close
timestamps and 0.55 s duration). Implication: #289's value concentrates on
**aggregate fidelity over large dumps** (counts, cardinalities, ranges), not on
buried-needle reconstruction — that A2 sub-class is more a main-loop/#275 concern.

**4. Replayability holds.** Every computable dimension proposed reported is backed
by a recorded `analyses.jsonl` snippet+output (1.00 large / 1.00 small / 0.88
buried — the one gap is the derived "same-second" boolean, not a measured value).
`current` is 0 by construction. Even the *incomplete* large-dump proposed run (at
limit 20) had left all 11 values correctly recorded — partial work is durable.

**5. Cost is not the feared regression.** On the control `proposed` was *cheaper
and faster* (40 s / 3.4k tok vs 79 s / 6.1k tok) — prose over-queried. It is
pricier on the buried case (+34% wall, +63% out-tok) but within the 1.5× bound.
Large-dump cost is not comparable (current fails). Net: the ≤1.5× control
criterion is met.

## Issues surfaced (and dispositions)

- **Oracle bug (fixed):** `session_duration_sec` expected was `0` (second-res);
  both variants correctly reported `0.55 s` and were mis-scored `wrong`. Fixed
  expected → `0.55`; re-judged. Now 7/8 both.
- **Production gaps surfaced (report, don't fix here):** (a) `GATHER_REQUEST_LIMIT
  = 20` is too tight for a 4 MB / 6-dimension lead — both variants; (b) the
  `read_file` tool is uncapped, so prose gather can overflow context on a large
  payload. Both are arguably their own runtime-reliability issues.
- **Banned-interpretation leak (both variants):** summaries still append
  "consistent with an automated script". Orthogonal to #289; the proposed §4
  didn't make it worse. Worth a separate SKILL tightening.

## Calibration note (judge)

Spot-checked every per-dimension verdict in `results/extractions/`. The judge is
strict-but-fair: it correctly flagged prose's `May 5–7` range as a *dropped*
precise timestamp and the duration units as consistent (after the oracle fix).
One known strictness: it scores the "same-second" *boolean* as dropped when the
summary reports the two timestamps but not the explicit equality — defensible,
and it hits both variants equally.

## Recommendation

The directional signal is strong enough to scale **focused**, not uniform:
- **large-sshd-dump N=10/variant** — confirm the win + the prose failure mode are
  robust (is the context overflow consistent, or does prose sometimes squeak
  through and under-report?). This is the load-bearing cell.
- **healthy-small N=5/variant** — confirm the cost control (proposed ≤ current).
- **same-second buried N=3/variant** — cheap parity confirmation; not worth N=10.
