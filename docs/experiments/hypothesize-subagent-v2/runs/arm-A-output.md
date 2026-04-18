## HYPOTHESIZE (loop 1)

**Active hypotheses:**

- `?legitimate-automation` — attaches upstream of `v-src-ip-10.30.18.42` via `originates-from`; proposed parent: internal automation process (classification: sanctioned monitoring or scheduled-job worker). Predicts: (1) `10.30.18.42` classifies as `internal-monitoring-host` or a known automation subnet in `ip-ranges.md`; (2) `srcuser` string `root` matches a service-account or monitoring-sentinel pattern documented in `identity-patterns.md`. Refutation shape: source IP not found in any sanctioned automation registry, OR username is explicitly classified as wordlist-common rather than automation-pattern.

- `?authentication-mistake` — attaches upstream of `v-attempted-user-root` via `typed-by`; proposed parent: human operator or misconfigured client (classification: stale-credential or typo, no malicious intent). Predicts: (1) no additional 5710 events from `10.30.18.42` in the 5-minute window before the alert (single-shot, not a burst); (2) a successful auth (rule 5501 / 5715) from `10.30.18.42` within 60 seconds after the alert (retry-after-correction pattern). Refutation shape: no follow-up success within 60 s, OR burst of multiple failed attempts in the window.

- `?credential-guessing` — attaches upstream of `e-attempted-auth-01` via `initiated-by`; proposed parent: adversarial process on or proxied through `10.30.18.42` (classification: internal-foothold or rogue node probing adjacent hosts). Predicts: (1) `10.30.18.42` does not classify as a sanctioned monitoring or automation host; (2) `root` is a wordlist-common username (not a sentinel or service-account pattern). Refutation shape: source IP is positively classified as sanctioned automation, OR username matches a documented monitoring sentinel.

- `?compromise-followup` (adversarial — must remain active until explicitly refuted) — attaches upstream of `e-attempted-auth-01` via `part-of-chain`; proposed parent: adversary with an existing foothold on or proxying through `10.30.18.42`, using this probe as a stepping-stone toward a successful lateral-movement auth. Predicts: (1) a successful SSH auth (rule 5501 / 5715) from `10.30.18.42` on `app-web-07` occurs within 60 seconds after the alert timestamp; (2) no sanctioned explanation for why `10.30.18.42` would SSH to `app-web-07` at all. Refutation shape: confirmed absence of any 5501 / 5715 from `10.30.18.42` within 60 s, AND source is positively classified as sanctioned automation with a plausible reason to contact this target.

**Selected lead:** `source-classification` — measures the classification of `v-src-ip-10.30.18.42` against `environment/context/ip-ranges.md`. A single edge measurement that immediately partitions the hypothesis space: if `10.30.18.42` is `internal-monitoring-host` or a known automation subnet, `?legitimate-automation` rises sharply and `?credential-guessing` weakens; if the IP is unclassified internal, `?legitimate-automation` weakens, and `?credential-guessing` / `?compromise-followup` remain live. The result also determines which half of the archetype space (monitoring-probe / service-account-rotation vs. credential-stuffing / lateral-probe) is structurally applicable. Dispatch mode: **single** — this one measurement partitions all four hypotheses along the most discriminating axis (source trust), so no parallel dispatch is warranted at this step. Secondary leads `authentication-history` (compromise check) and `username-classification` (identity shape) are deferred conditional on source outcome, per the playbook's starter lead order.

**Pitfalls:**

- `?legitimate-automation`: The IP `10.30.18.42` is internal, which is necessary but not sufficient for the automation story. An unclassified internal host (not in the monitoring or automation registry) could be a rogue or compromised machine — do not short-circuit to benign on internal-IP alone; require positive registry confirmation.
- `?authentication-mistake`: Username `root` is rarely a typo for any real username, and it is not a service-account pattern shape. If `source-classification` returns no sanctioned automation result, this hypothesis effectively merges with `?credential-guessing` as the same evidence then covers both; treat a "no follow-up success + not sanctioned" result as refutation of the typo variant.
- `?credential-guessing`: The internal source already weakens the external-bruteforce archetype story, but internal credential-guessing (lateral movement) is a live reading. Do not dismiss this hypothesis because the IP is RFC1918; the severity framing shifts from "external scanner" to "post-compromise lateral probe."
- `?compromise-followup`: The ticket-context subagent already confirmed no 5501 / 5715 success events on `app-web-07` in the 4-hour window before the alert. This weakens the pre-existing-compromise reading but does not refute forward compromise (success within 60 s after). `authentication-history` must still check the 60-second post-alert window before this hypothesis can be cleared.

---

## Context used

**Files read:**
- `/workspace/docs/experiments/hypothesize-subagent-v2/fixture/alert.json` — alert payload; extracted srcip, srcuser, target host, timestamp, rule details.
- `/workspace/docs/experiments/hypothesize-subagent-v2/fixture/investigation.md` — full CONTEXTUALIZE output including prologue graph, ticket-context correlation, and archetype scan rankings; used to understand the confirmed graph anchor (`e-attempted-auth-01`) and the ASSESS decision.
- `/workspace/soc-agent/knowledge/signatures/wazuh-rule-5710/context.md` — signature logic, threat model, risk axes (source trust + pattern shape), related rules (5501, 5715, 5712).
- `/workspace/soc-agent/knowledge/signatures/wazuh-rule-5710/playbook.md` — hypothesis seeds (`?legitimate-automation`, `?authentication-mistake`, `?credential-guessing`, `?compromise-followup`), starter lead order (source-classification → authentication-history → username-classification), archetype catalog, screen table, signature quirks.

**Files not read:**
- `archetypes/*/story.md` — archetype scan is already rendered in `investigation.md` with explicit story-match scores and disqualifiers; re-reading the story files would duplicate that work without adding discriminating information at the HYPOTHESIZE stage.
- `soc-agent/knowledge/common-investigation/leads/` — the playbook's starter lead order names the leads directly (`source-classification`, `authentication-history`, `username-classification`), which is sufficient to name the selected lead; the lead definition files would be needed at GATHER, not here.
- `field-quirks.md` — quirks relevant to this signature are summarised in `playbook.md §Signature quirks`; no query construction is happening at HYPOTHESIZE, so the detailed field-quirks file is not needed.
