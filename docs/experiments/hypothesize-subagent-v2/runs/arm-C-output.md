## HYPOTHESIZE (loop 1)

**Active hypotheses:**

- `?legitimate-automation` — attaches upstream of `v-src-ip-10.30.18.42` via `initiated` edge; proposed parent: `{type: process/service, classification: sanctioned-automation}`. Predicts: (1) srcip resolves to a known monitoring or scheduled-job host in `approved-monitoring-sources` or `scheduled-jobs` context records; (2) no additional 5710 attempts from this srcip against other hosts in the same window (single-target, single-attempt footprint). Refutation shape: srcip not in any sanctioned-automation range; or multiple targets hit in the window.

- `?authentication-mistake` — attaches upstream of `v-src-ip-10.30.18.42` via `initiated` edge; proposed parent: `{type: process/human-session, classification: human-authorized or misconfigured-client}`. Predicts: (1) srcuser `root` is a plausible typo or stale-credential artifact for a real account on app-web-07 (e.g., a depleted rotation that used to target root, or a client sending the wrong username field); (2) a successful 5501/5715 login from 10.30.18.42 to app-web-07 within ~60s of the alert (the operator corrects and succeeds). Refutation shape: no successful login within 60s; srcip has no history of successful logins to app-web-07.

- `?compromise-followup` — (adversarial — must survive until `--`) attaches upstream of `v-src-ip-10.30.18.42` via `initiated` edge; proposed parent: `{type: process, classification: adversarial}`. Predicts: (1) a successful authentication event (5501 or 5715) from 10.30.18.42 on app-web-07 within seconds/minutes of this attempt, indicating the failed `root` try was one step in a credential-walking sequence that found a valid account; (2) OR lateral movement from 10.30.18.42 consistent with a compromised internal host (e.g., outbound connection patterns, other failed auths to different hosts). Refutation shape: no success events on any host from this srcip in the ±5min window; srcip confirmed as a sanctioned-automation host with an innocent footprint.

**Note on `?credential-guessing` suppression:** The playbook seed `?credential-guessing` is not carried as a standalone hypothesis here. Volume=1 and an internal source both cut against a classic guessing campaign. The adversarial concern is subsumed by `?compromise-followup`, which captures the worst-case (compromised internal host enumerating accounts). If `authentication-history` returns multiple attempts, `?credential-guessing` should be reinstated immediately.

**Selected lead:** `authentication-history` — **single dispatch**.

Measurement: query failed logins from 10.30.18.42 in the last 5 minutes (rules 5710/5716) and successful logins from 10.30.18.42 to app-web-07 within 60s after 2026-04-18T14:22:17Z (rules 5501/5715).

Discrimination:
- A success event within 60s strongly supports `?authentication-mistake` and is the primary refutation trigger for `?compromise-followup` (or, if the success is anomalous, escalates it).
- No additional attempts → weakens `?credential-guessing` further; consistent with `?legitimate-automation` or a one-off mistake.
- Multiple attempts across targets → reinstates `?credential-guessing` and escalates `?compromise-followup`.
- This lead is preferred over `source-classification` because the alert digest has already partially resolved IP classification (10.30.18.42 is internal per environment ranges), so the marginal discriminating power of `authentication-history` is higher — the result of a success/failure pattern immediately narrows three hypotheses at once.

Dispatch mode: **single** — one data source (auth event log), one time window, cleanly bounded query. No need for composite dispatch at this stage; `username-classification` and `source-classification` are deferred because the digest already supplies classification primitives (internal IP; `root` is not on the sentinel list).

**Pitfalls:**

- `?legitimate-automation`: `root` is explicitly not on the sentinel username list (nagios, zabbix, etc.), so the usual monitoring-probe heuristic doesn't apply. Do not dismiss this hypothesis on username alone — some legacy backup or config-management agents run as root. Anchor confirmation (`approved-monitoring-sources`) is needed if this hypothesis is to survive past loop 2.
- `?authentication-mistake`: A 60s window for a follow-on success is a guideline, not a hard cutoff. If the operator is working interactively (SSH client prompting, slow VPN), the corrected login may arrive up to several minutes later. Widen the window to 5min if the 60s window returns no hit and the first-pass pattern still looks benign.
- `?compromise-followup`: Internal source does not mean safe. A compromised internal host is the highest-severity interpretation of this alert. Do not treat the internal IP as a disqualifier — treat it as a constraint on the story (lateral movement, not external ingress). The absence of a 5501/5715 success is the minimum bar for weakening this hypothesis; full refutation requires `--` from the `source-classification` lead confirming the host is sanctioned automation.
- General: The digest notes no prior 5710 from this srcip in 4h — confirm that the `authentication-history` query covers the full ±5min window around the alert timestamp (not just backward), to catch immediate follow-on success events.

---

## Context used

No additional reads were performed beyond the inlined digest. The digest provided all required primitives:
- Anchor edge and vertex identities
- IP classification (internal)
- Username sentinel list
- Archetype scan results with disqualifiers
- Playbook hypothesis seeds and starter leads
- Prior-activity context (no 5710 from srcip in 4h; no 5501/5715 on app-web-07 in 4h)

The deeper-read pointers (full alert JSON, investigation.md, signature knowledge, lead definitions) were not fetched because the digest was sufficient to make defensible hypothesis and lead-selection choices without ambiguity.
