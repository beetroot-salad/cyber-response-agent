# Step zero: grading the time claims gather already made with `defender-sql`

**Question:** in the real runs, did the gather model report any time wrongly *because of* how
`defender-sql` handled times? The handling in question: DuckDB guesses which columns are
timestamps and re-spells them, leaves others as source text, fails `->>'$'` on all-text ES|QL
rows, and crashes on zoned results.

**Answer: no.** Of 21 wrong or suspect time claims found, none traces to the tool's time
handling. No call errored because of time handling, so no turns were wasted on it. The time
errors that did happen are the model's own misreadings: spans, "N s after", "only events after X",
"did not exist before". They occur just as often in claims built from `query` payloads as in claims
built from SQL output.

Sources: the wire logs, `gather_raw/`, `gather_summaries/` and `provenance.json` of
`gather-flash-port/runs/*` and `glm53-container-attribution/runs/*`. No model calls were made.
Helper: `../step0_extract.py`. It writes `step0_calls.json` and `step0_calls.txt`, one record per
`defender-sql` bash call with the tool result the model saw. "Call #N" below is the index into
`step0_calls.json`.

## 0. Scope and reconciliation with the survey

- **20 dispatches made 107 `defender-sql` bash calls.** Matching the string `defender-sql` in
  any gather tool call gives 21 dispatches and 114 calls. The 7 extra calls are `read_file` on
  `skills/gather/defender-sql.md`. One of them belongs to a dispatch that only read the doc and
  ran no SQL (`current-F2-t2 l-002`); the other six are in dispatches already counted. The plan's
  22/113 came from a slightly different match, which I could not reproduce exactly.
- **56 calls touch a time.** A call counts if its SQL names a time-ish field or function
  (`@timestamp|timestamp|falco.time|first_seen|last_seen|window_*|created|_at|date|now()|interval|::timestamp|min(v[|max(v[`),
  or if its stdout carries an ISO-like timestamp. The survey's 49 used a narrower rule. The OR
  on the output side adds calls like #95 (`SELECT v[1]..v[8]`), and the SQL side adds calls that
  errored or were blocked.
  - Of the 56, **32 returned rows**. One of those, #69, is really a `|| DESCRIBE data` fallback.
  - The rest were SQL errors (35 of all 107 calls), blocked by the bash surface (15), or were
    the dispatch's last call with no result (5).
- **Both run commits ship the same `sql.py`.** `9915d515` (all of gather-flash-port) and
  `68f0c7da` (glm53-flashgather-2) are byte-identical. Loading uses `read_json_auto` with type
  guessing on, and the output uses `json.dump(..., default=str)`. There is no pytz fallback, so a
  zoned value would have raised.
- **Reproduction.** I re-ran call #60 through that `sql.py` with pytz hidden. The output matched
  the recorded result byte for byte (`@timestamp` → `TIMESTAMP` →
  `"2026-08-30 09:54:51.724000"`; `falco.time` → `VARCHAR`). Every other call's recorded tool
  output is in the wire log, so I graded against what the model actually saw.
- **Models.**

  | model | dispatches | calls | wrong time claims |
  |---|---|---|---|
  | kimi-k2.6 | 4 | 37 | 0 |
  | deepseek-v4.1-flash | 10 | 51 | 18 |
  | glm-5.3-flash (the target) | 6 | 19 | 3 |

  Only 4 glm-flash dispatches have a summary with gradeable time claims, and only 3 of them
  (glm-flash-F1-t0 l-006, glm-flash-F1-t2 l-006, glm53-flashgather-2 l-00c) got a time-touching
  SQL call to succeed.

## 1. What the tool did with times in these calls (observed, not assumed)

| form the model saw | calls | source |
|---|---|---|
| **Converted:** `"2026-08-30 09:54:51.724000"` (space, 6 fraction digits, no zone) | #53, #60, #61, #74, #87, #106 | search-hits `h."@timestamp"`, and `kibana.alert.original_time` (#106) |
| **Source text, nanosecond `Z`:** `"2026-08-30T09:53:56.983976960Z"` | #53, #60 | `h.falco.time` |
| **Source text via `->>'$'`:** `"2026-08-30T09:54:51.727Z"` | #38–#40, #42–#44, #46–#48, #50, #58, #64, #93 | ES\|QL `values` rows |
| **JSON-quoted source text via bare `v[N]`:** `"\"2026-08-30T09:53:47.594Z\""` | #17, #71, #72, #77–#79, #81, #82, #95, #97, #98, #101 | ES\|QL `values` rows |

- **Two forms in one result** (converted `@timestamp` next to source-text `falco.time`): only
  **#53** (ds-flash-F1-t3 l-001) and **#60** (ds-flash-F1-t4 l-001). This is exactly the T1 trap
  in the plan.
- **ES|QL rows:** every one carried a numeric count column, so `values` loaded as `JSON[][]`
  (#69 prints the `DESCRIBE`). `->>'$'` always returned source text, and **no call hit
  "Malformed JSON"**.
- **Never produced:**
  - a `+00:00` offset field: no change-ticket payload was ever piped into SQL
  - a TIMESTAMPTZ or zoned value
  - any cast (`::TIMESTAMP`, `strptime`, `to_timestamp`, `now()`, `date_trunc`, `interval`,
    `epoch`): **0 of 107 calls**
  - a `Traceback`: **0 of 107 results**

  These are zero by observation: I grepped every command and every result.

## 2. Dispatch list

Columns:
- **time ok:** time-touching calls that returned rows
- **err:** SQL errors, counting those hidden behind `2>&1 | head` or `||`
- **blk:** refused by the bash surface
- **nores:** dispatch ended before the result came back
- **prec:** `->>` precedence errors (see §5)

| run | lead | model | commit | sql calls | time calls | time ok | err | blk | nores | prec | summary | time claims graded | wrong |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| current-F1-t0 | l-009 | kimi-k2.6 | 9915d515 | 16 | 0 | 0 | 2 | 12 | 1 | 0 | stub: "bash exceeded max retries" | 0 | 0 |
| current-F1-t2 | l-001 | kimi-k2.6 | 9915d515 | 2 | 2 | 1 | 1 | 0 | 0 | 0 | full | 10 | 0 |
| current-F1-t3 | l-006 | kimi-k2.6 | 9915d515 | 16 | 0 | 0 | 0 | 0 | 1 | 0 | stub: request limit | 0 | 0 |
| current-F2-t1 | l-006 | kimi-k2.6 | 9915d515 | 3 | 0 | 0 | 1 | 0 | 0 | 0 | full (CMDB; no times) | 0 | 0 |
| ds-flash-F1-t0 | l-007 | deepseek-v4.1-flash | 9915d515 | 8 | 7 | 6 | 2 | 0 | 0 | 1 | full | ~30 | 2 |
| ds-flash-F1-t2 | l-006 | deepseek-v4.1-flash | 9915d515 | 6 | 5 | 4 | 2 | 0 | 0 | 0 | full | ~50 | 0 |
| ds-flash-F1-t2 | l-008 | deepseek-v4.1-flash | 9915d515 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | full (spot-checked 13) | 13 | 1 |
| ds-flash-F1-t3 | l-001 | deepseek-v4.1-flash | 9915d515 | 2 | 2 | 1 | 1 | 0 | 0 | 0 | full | ~30 | 1 |
| ds-flash-F1-t3 | l-004 | deepseek-v4.1-flash | 9915d515 | 5 | 4 | 1 | 3 | 0 | 0 | 3 | full | ~18 | 2 |
| ds-flash-F1-t4 | l-001 | deepseek-v4.1-flash | 9915d515 | 3 | 3 | 2 | 1 | 0 | 0 | 0 | full | ~22 | 3 |
| ds-flash-F1-t4 | l-007 | deepseek-v4.1-flash | 9915d515 | 6 | 5 | 1 | 4 | 1 | 0 | 2 | full | ~25 | 3 |
| ds-flash-F2-t0 | l-005 | deepseek-v4.1-flash | 9915d515 | 15 | 15 | 9 | 6 | 0 | 0 | 1 | full | ~28 | 3 |
| ds-flash-F2-t2 | l-00c | deepseek-v4.1-flash | 9915d515 | 1 | 0 | 0 | 0 | 0 | 1 | 0 | stub: request limit 8 | 0 | 0 |
| ds-flash-F2-t2 | l-003 | deepseek-v4.1-flash | 9915d515 | 4 | 4 | 1 | 2 | 1 | 0 | 0 | full | ~15 | 3 |
| glm-flash-F1-t0 | l-006 | glm-5.3-flash | 9915d515 | 11 | 5 | 4 | 7 | 0 | 0 | 2 | full | ~16 | 3 |
| glm-flash-F1-t1 | l-004 | glm-5.3-flash | 9915d515 | 1 | 0 | 0 | 0 | 1 | 0 | 0 | full | 2 | 0 |
| glm-flash-F1-t2 | l-006 | glm-5.3-flash | 9915d515 | 2 | 1 | 1 | 1 | 0 | 0 | 0 | full | ~14 | 0 |
| glm-flash-F2-t0 | l-00c | glm-5.3-flash | 9915d515 | 1 | 0 | 0 | 0 | 0 | 1 | 0 | stub: request limit 8 | 0 | 0 |
| glm-flash-F2-t2 | l-00c | glm-5.3-flash | 9915d515 | 2 | 1 | 0 | 1 | 0 | 1 | 0 | stub: request limit 8 | 0 | 0 |
| glm53-flashgather-2 | l-00c | glm-5.3-flash | 68f0c7da | 2 | 2 | 1 | 1 | 0 | 0 | 0 | full | 8 | 0 |
| **total** | | | | **107** | **56** | **32** | **35** | **15** | **5** | **9** | | **~280** | **21** |

"Time claims graded" counts each time, span, ordering, window or first/last-seen statement once.
The "~" figures are approximate because a table row carrying a first and a last time counts as
two. Claims taken from `query` payloads were graded too, by grepping that dispatch's
`gather_raw/<lead>/*.json`.

## 3. Per-claim table

Evidence paths are relative to `gather-flash-port/runs/` unless they start with `glm53/`, which
means `glm53-container-attribution/runs/`. "Via" says where the model got the times: a
`defender-sql` call (#N) or a `query` payload.

### 3a. Every wrong or suspect time claim

| # | dispatch | claim (summary text) | truth (payload) | via | verdict | class |
|---|---|---|---|---|---|---|
| 1 | ds-flash-F1-t0 l-007 | "`Read ssh information` did **not** exist before … 08-07" | Present on every day from 07-30 (18 of the 19 days). The summary's own table shows ReadSsh=1 on 07-30…08-05 (`l-007/0.json`). | #38, `->>'$'` source text | wrong (novelty claim) | OTHER-TIME |
| 2 | ds-flash-F1-t0 l-007 | "burst timestamp 09:54:51Z is the 08-30 cluster's first drop-and-execute second (09:54:53.330Z)" | Drop-and-exec first_seen on 08-30 is 09:54:53.330Z, 2 s after 09:54:51 (`0.json`) | query | minor (not the same second) | OTHER-TIME |
| 3 | ds-flash-F1-t2 l-008 | "the alert's own second/third sudo events sit at 09:54:51Z, outside the reported `from`" | `threshold_result.from` = 09:54:51.724Z, and the events are at .724/.725, so at or after it (alert.json) | alert | minor | OTHER-TIME |
| 4 | ds-flash-F1-t3 l-001 | "nearest interactive login … is **~54 s** after the commands' own event times" | Login 09:54:41.339Z (`l-001/9.json`); event times 09:53:56.98–57.31Z (`6.json`); gap ≈ 44 s. The same summary says "~44 s" two paragraphs earlier. 54 s is the @timestamp→falco.time lag, so the two gaps look conflated. | #53 (two-form) + query | wrong | OTHER-TIME (see §4) |
| 5 | ds-flash-F1-t3 l-004 | "the burst (09:53:57Z) sits **~10 min** before 12:27:05Z" | 09:53:57 → 12:27:05 is 2 h 33 m. Also, the 1,555 sudo lines ending 12:27:05Z are on `db-1`, not soc-playground (`l-004/3.json`). | query | wrong | OTHER-TIME |
| 6 | ds-flash-F1-t3 l-004 | "daily 2026-07-31→2026-08-06 at exactly 483,840/day" | 08-06 = 177,008; the flat rate runs 07-31…08-05 (`12.json`) | query | minor (window off by a day) | OTHER-TIME |
| 7 | ds-flash-F1-t4 l-001 | auth events "a **~22s span** just before the burst" | Listed events run 09:53:47.594 → 09:54:41.383Z, which is 53.8 s. Relative to the burst's event time (09:53:57) they straddle it rather than precede it. | #61 (all `@timestamp` converted, one form) | wrong | OTHER-TIME |
| 8 | ds-flash-F1-t4 l-001 | "Syslog **and Falco** begin shipping at 09:53:47.59Z" | Syslog first 09:53:47.592Z ✓; earliest Falco first_seen is 09:53:56.879Z (`l-001/0.json`) | query | minor | OTHER-TIME |
| 9 | ds-flash-F1-t4 l-001 | ingest `@timestamp` vs `falco.time` "≈54.9s offset" | Actual offsets 54.74 / 54.54 / 54.41 s. The one arithmetic across a two-form result. | #60 (two-form) | imprecise by 0.2–0.5 s; immaterial | OTHER-TIME (see §4) |
| 10 | ds-flash-F1-t4 l-007 | "a `Write below etc` / `Read ssh information` pair from `elastic-agent` and `systemd-tmpfile` at 10:08:48" | Only Read ssh fired at 10:08:48.368Z. The latest `Write below etc` is 09:56:19.282Z (`l-007/3.json`). | #64 + query | wrong | OTHER-TIME |
| 11 | ds-flash-F1-t4 l-007 | "The only events after ~09:57 are kauditd…, OOM … at 09:55:08, podman/containerd mount teardowns through 10:13:19, and …10:08:48" | Omits curl/openssl drop-and-exec running to **10:12:55.396Z**, which the model had seen in #64. Lists a 09:55:08 event as "after 09:57". 10:13:19 is the `elastic_agent` dataset's last_seen (`1.json`), not mount teardowns. | #64 + query | wrong | OTHER-TIME |
| 12 | ds-flash-F1-t4 l-007 | "Every one of these [867 Falco events] … pre-dates or is concurrent with the ~09:53:47–09:56:36 … churn"; "10s to 3min after … the SSH session" | Drop-and-exec ×38 run to 10:12:55Z; Read ssh fires at 10:08:48Z (`3.json`, `11.json`) | #64 + query | wrong | OTHER-TIME |
| 13 | ds-flash-F2-t0 l-005 | "5 Falco fires … **−20h** → +6h around the alert" | First fire 07-27T16:35:02.631Z is −23.6 h from the 07-28T16:12:37 event, and +6 h is right (`l-005/2.json`) | #77 + query | minor | OTHER-TIME |
| 14 | ds-flash-F2-t0 l-005 | "**All seven** rule groups share the same two instants … 15:49:28.710 … 16:00:26.997 → 16:12:37" | The 2 metadata groups sit at 15:48:17–15:48:49Z; 5 of the 7 match (`4.json`) | query | minor | OTHER-TIME |
| 15 | ds-flash-F2-t0 l-005 | "Container-scoped Falco (143 events, 15:48:17.917 → 16:51:50.817Z)", followed by a per-rule table | 143 comes from the 15:30–17:00 query (`3.json`). The table rows come from the 15:45–16:20 query (`4.json`) and sum to 102. | query | minor (window conflation) | OTHER-TIME |
| 16 | ds-flash-F2-t2 l-003 | "Continuous daily Jul 1–13" | No fires on 07-05, 07-06 or 07-12 (`l-003/6.json`) | query | wrong | OTHER-TIME |
| 17 | ds-flash-F2-t2 l-003 | "resuming **Jul 27** (4 containers, 8 fires)" | 3 containers, 6 fires (`6.json`) | query | wrong (day-bucket count) | OTHER-TIME |
| 18 | ds-flash-F2-t2 l-003 | "widened to 15:50–16:30Z (the lead's anchor ±~13m)" | Anchor 16:12:37 gives −22.6 / +17.4 min | query | minor | OTHER-TIME |
| 19 | glm-flash-F1-t0 l-006 | Read ssh at 09:54:52.324Z "**~0.9s after** the root login" | Login 09:54:41.339Z (`l-006/3.json`), so it is 11.0 s after. Falco's own `evt.time` for it (1788083651996247837 ns = 09:54:11.996Z, `2.json`) is 29 s *before* the login. | query | wrong | OTHER-TIME |
| 20 | glm-flash-F1-t0 l-006 | Clear Log at 09:54:51.725Z "**at the same instant as the login**, not later" | 10.4 s after the login | query | wrong | OTHER-TIME |
| 21 | glm-flash-F1-t0 l-006 | "host-level Falco `connect` events are all boot-time (09:54:51–52)" | They span 09:54:51.728 → 09:55:09.343Z, and #98's own output showed 09:55:09.343 in source text | #98 (source text) | minor | OTHER-TIME |

Material wrong claims: 1, 4, 5, 7, 10, 11, 12, 16, 17, 19, 20 (11 claims). The other 10 are
minor or immaterial.

### 3b. Claims graded correct (grouped)

| dispatch | claims (all ✓ against the named payload) | via |
|---|---|---|
| current-F1-t2 l-001 | Burst 3× at 09:54:51.724–.725Z. Auth timeline 09:53:47.594, 09:54:41.339/.341/.363/.383, 09:55:01.743–.746. 30-day window, ~79K events (`l-001/1,2,8,12.json`). | query; #17 source-text |
| ds-flash-F1-t0 l-007 | 19 day rows 07-30…08-30 (dates right; see §5 for a non-time column swap on 08-22). LaunchSensitive first 08-06, ClearLog first 08-07, "≥7 prior days". Zero-days 08-14–16, 08-19–21, 08-23–29. curl/openssl 12,640 over 19 days, 07-30→08-30. Single-day procs 08-17/08-18. Alert 09:59:51Z. | #38–#44, `0.json`, `3.json` |
| ds-flash-F1-t2 l-006 | 17-row rule table: 34 first/last instants, all exact. Read ssh 09:54:52.324 / 10:08:48.368. Drop-exec 09:54:53.330→10:12:55.396. "Only events past ~09:56:34". e5b0 metadata 09:54:51.730–.756. Env-var, sensitive-file, setuid spans. | #46–#48, #50, `0.json`, `2.json` |
| ds-flash-F1-t2 l-008 | 12 of 13 spot-checked: psql 37× 08-17T09:52:22→08-30T12:27:05; createdb 08-18T08:05:47–09:45:56; e5b0 08-18T09:45:57→08-30T12:27:58; a3649 08-17T09:53:06; web pair 08-17T10:10:02–17:24:25; enroll rows 09:52:08–09:53:11 / 09:53:47–12:27:54; 08-17T17:56 stop. | query only |
| ds-flash-F1-t3 l-001 | **Two-form table** (#53): 3× `@timestamp` 09:54:51.724/.725/.725Z and 3× Falco time 09:53:56.983976960 / 57.182735705 / 57.310994840Z, all right. **"~55 s gap … ingestion lag, not two bursts"** is right (54.4–54.7 s). Postgres 09:53:54.319–.678 "~3 s before". Auth timeline. "~44 s after / ~10 s before ingest". Falco/Zeek/Postgres/syslog windows (09:53:53.192–10:05:58.785, 09:54:01.409–10:04:51.431, …). | #53 + query |
| ds-flash-F1-t3 l-004 | 147.235.199.7: 5 logins, 08-22 (08:53:21–16:09:13) and 08-30 (09:54:41–18:03:45). 79.177.137.245 08-01T17:05:03→08-18T11:25:04. "4-day handover". Auth index 07-31T00:00:03→08-30T18:05:01. 18 postgres days; daily volumes 28,620/26,956/100,340/60,544; db-1 span. | #58 (source text), `5,9,10,12,2,11.json` |
| ds-flash-F1-t4 l-001 | **Two-form table** (#60): ingest 09:54:51.724–.725Z and Falco 09:53:56.983/57.182/57.310Z, all right. "True event times … 09:53:56.98–09:53:57.31Z", "`@timestamp` is ingest time" ✓. Threshold from 09:54:51.724Z. Auth timeline 09:53:47.594…09:54:41.383 (from #61's converted values, re-emitted right). CRON 09:55:01–10:05:01. | #60, #61 + query |
| ds-flash-F1-t4 l-007 | Window. Login 09:54:41.339. Session 09:54:41.341/.363, 41.35–41.635. Server listening 09:54:40.675. Cron 09:55:01.7 / 10:05:01.7. Sudo 09:54:51.724–.725, "~10 s after login". containerd/dockerd 09:54:43–09:56:36. Metadata 09:54:51–09:55:39. runcmd 09:54:51.758. OOM 09:55:08.055. kernel 09:54:43–10:13. PackageKit 09:59:08.648. resolved 09:55:25. kauditd 10:00:06/10:10:07. `original_time` 09:54:51.725Z. setuid 09:54:51.746. curl 09:54:53.330. | #64 + query |
| ds-flash-F2-t0 l-005 | 5-row authorized_keys table: 8 instants all exact, with no leak from the 0-indexed #71/#72 (fixed in #77). 7-row container table spans. Syslog 15:48:08.137→15:48:13.250. Stale-sandbox 15:48. Host-wide 15:48:16.761→17:59:56.745. Alert-anchor "2nd of 2". | #77–#82 + query |
| ds-flash-F2-t2 l-003 | Writes 16:00:26.997 / 16:12:37.250Z (from #87's converted `ts`, re-emitted with Z). Alert 16:16:53Z. 4 container rule spans 15:55:22/15:59:10–16:28:40. 247 logins 15:50:00–16:27:11. 1df4 days Jul 1, 2, 3, 8, 9, 11, 28. | #87 + query |
| glm-flash-F1-t0 l-006 | Login 09:54:41.339. 6 follow-on 09:54:41.341–10:05:01.760. Drop-exec 17× each 09:54:53.330→10:10:55.382 ("~every-65s": actual 55/65 s alternating, OK). Read ssh times. Setuid 09:54:51.746. Sudo 09:54:51.724–.725. Postgres 09:54:01–10:10:51. Zeek 285 conns. | #93, #97, #98 + query |
| glm-flash-F1-t1 l-004 | `captured_at` 2026-09-11T08:07Z, "12 days after" 08-30. | query |
| glm-flash-F1-t2 l-006 | Login 09:54:41.339. Opens .341/.383. **Close 12:48:31 / 12:48:41, "~2h54m"**. Cron 09:55:01/10:05:01. authorized_keys read "pre-login (09:54:11)", correct because it used Falco's event time. common-password 09:54:41. Sudo 09:54:51.724–.725. Zeek 09:54:47–10:10:21, 09:55:06–09:55:39. | #101 + query |
| glm53-flashgather-2 l-00c | ±1h window 15:19:37–17:19:37Z. 7-day lookback from 2026-09-02T16:19:37.734Z. Neighbour alert `@timestamp` 16:19:37.805Z and "underlying events from 16:14:23.930Z" (= `threshold_result.from`). #106 returned both `alert_ts` and `orig_ts` converted to space form, and the summary re-spelled them right. | #106 + query |

## 4. The two places a tool-attributable error could have come from, examined

**The two-form results (#53, #60), which is the plan's T1 trap, seen in the wild.** Both
deepseek dispatches got `@timestamp` as `"2026-08-30 09:54:51.724000"` and `falco.time` as
`"2026-08-30T09:53:56.983976960Z"` in the same rows. Both summaries:
- reproduced every value of both fields correctly (6 of 6 each)
- named which one is ingest time and which is event time
- gave the gap as ~55 s / ≈54.9 s (truth 54.4–54.7 s)

Neither treated the two as disagreeing clocks or as two bursts. The only numeric slips near these
results are:
- #9, a 0.2–0.5 s imprecision on an "≈" figure, which cannot be reproduced from either spelling
- #4, "~54 s" where the truth is ~44 s

#4 compares the login time, taken from an ES|QL payload, with Falco event time. Neither
two-form field is misread there; the same summary gets the same gap right ("~44 s")
elsewhere. I classify both as OTHER-TIME. Reading #4 as a spelling problem would need the model
to have misread a value it quoted correctly in the same document.

**Converted values in general (#53, #60, #61, #74, #87, #106).** Every converted instant that
reached a summary was re-emitted as the right UTC instant. None came back with a wrong zone or a
±hours shift. Where a zone was written it was `Z`; some lists, such as ds-flash-F1-t4 l-001's
auth list, have no zone marker at all. No precision that mattered was dropped. There were
**0 T-CONVERT** cases.

The literal tool values behind the three classified items that sit on converted output:
- **#4 and #9:** #53/#60 returned
  `{"ts": "2026-08-30 09:54:51.724000", "falco_time": "2026-08-30T09:53:56.983976960Z"}`,
  `{… "2026-08-30 09:54:51.725000", … "2026-08-30T09:53:57.182735705Z"}` and
  `{… "2026-08-30 09:54:51.725000", … "2026-08-30T09:53:57.310994840Z"}`. The summaries' tables
  quote all six values correctly.
- **#7:** #61 returned `"ts": "2026-08-30 09:53:47.594000"` … `"ts": "2026-08-30 09:54:41.383000"`,
  all in one form. The summary lists the same endpoints correctly and then calls the span "~22s".

**MIN/MAX over text held up.** #43, #46 and #64 ran `MIN/MAX(v[N]->>'$')` over source text, and
every first/last value matched the payload. For example, #43's 08-17 Clear Log is
09:52:17.633–09:53:06.340Z, and #64's curl is 09:54:53.330Z→10:12:55.396Z. The plan's finding
that spelling is uniform within one field held in practice, so the lexical-MIN trap stayed
theoretical here.

**Near-miss, not an error: text comparison with a date-only bound.** #40 (ds-flash-F1-t0) ran
`WHERE v[4]->>'$' BETWEEN '2026-08-13' AND '2026-08-17'` over source text
`"2026-08-17T00:00:00.000Z"`. Lexically `'…-17T00…' > '2026-08-17'`, so the 08-17 row was silently
dropped and only 08-13 came back. The model re-queried with `< '2026-08-18T00'` (#41, which failed
on `->>` precedence) and then #42, which got 08-17. The summary's day table and zero-days list are
right, so no claim was affected. This is a T-LEXICAL trap that fired and was recovered from, at a
cost of one extra call. It happens because ES|QL `values` are JSON text, which is true on current
**and** under the PR, so no contract variant would change it.

## 5. Totals

| class | wrong/suspect claims | wasted turns (time-caused SQL errors retried) | notes |
|---|---|---|---|
| T-FORM | 0 | 0 | 2 two-form results (#53, #60), both read correctly |
| T-CONVERT | 0 | 0 | 6 calls returned converted space-form times; every instant re-emitted right |
| T-LEXICAL | 0 | 0 errors (+1 silent under-return, recovered next call) | #40 date-only `BETWEEN` upper bound |
| T-ESQL | 0 | 0 | 0 "Malformed JSON"; every ES\|QL row had a count column; `->>'$'` always gave source text |
| T-CRASH | 0 | 0 | 0 zoned values, 0 casts, 0 tracebacks in 107 results |
| OTHER-TIME | 21 (11 material, 10 minor) | n/a | 18 deepseek, 3 glm-flash, 0 kimi. 12 of 21 rest on `query` payloads only, with no SQL output involved. |

**Wasted SQL calls that are not time handling** (for scale):
- **9 `->>` precedence errors**: #41, #54, #55, #56, #65, #67, #80, #94, #96. DuckDB binds `->>`
  looser than `AND`/`OR`/`IN`/`LIKE`. `EXPLAIN` of `v[4]->>'$' > 'a' AND v[4]->>'$' < 'b'` shows
  `CAST(((v[4]->>'$') > 'a') AND CAST(v[4] AS BOOLEAN)) AS JSON) ->> '$' < 'b'`, so the tool
  answers `Failed to cast value to numerical: "<value>"`. In 4 of the 9 (#41, #55, #56, #80) the
  value quoted in the error is a timestamp, so the error *looks* time-related but isn't. #94/#96
  fail the same way on `"Read ssh information"`. This is the largest single source of wasted SQL
  calls in the corpus, and it is the same under every time contract.
- **12 bash-surface blocks** in current-F1-t0 (`\'` inside single quotes). That dispatch ended with
  "exceeded max retries".
- **16 identical `SELECT sha256`** calls in current-F1-t3 (a loop until the request limit).
- Shape/binder errors in glm-flash-F1-t0 (#88–#92).
- 0-indexed `v[0]` in ds-flash-F2-t0 (#71, #72; corrected in #77).
- Non-time claim errors seen while grading, not counted above:
  - ds-flash-F1-t0 08-22 row: ClearLog 112 / UDP "—", truth 1 / 112
  - ds-flash-F1-t2 l-006: "644 rule-fires", truth 859
  - ds-flash-F1-t4 l-007: "867 events", truth 859
  - ds-flash-F1-t3 l-004: 1,555 sudo lines put on soc-playground; they are on db-1

## 6. Bottom line

I found no time error in the real runs that traces to `defender-sql`'s time handling:
- **Traps that never fired:** no crash, no ES|QL `->>'$'` failure, no misread converted value,
  and no wrong comparison across the two forms.
- **Trap that fired but did no harm:** the one real instance of the plan's T1 trap
  (converted `@timestamp` next to source-text `falco.time`, #53 and #60) was read correctly in
  both dispatches that hit it. That includes a correct statement of the ingest-vs-event lag.

All 21 wrong or suspect time claims are the model's own:
- mis-subtracted spans ("~22 s", "~0.9 s", "~10 min")
- over-general "only/every event" statements
- "did not exist before" claims

Such errors appear as often on `query` payloads as on SQL output, and they would survive any
`sql.py` contract.

**Caveat:** the evidence for the target model is thin. Only 3 glm-5.3-flash dispatches got a
time-touching SQL call to succeed, and none of them hit a two-form result. Most of the
time-bearing SQL came from deepseek. Offset (`+00:00`) fields and zoned values never reached SQL
at all. So step zero settles #1125 as "no observed harm" rather than "proven harmless", and #1126
(the crash) went untriggered only because no one computed a time.
