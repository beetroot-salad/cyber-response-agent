# Trial 4 — SSH 5710 invalid-user, external archetype

Agent: general-purpose subagent. Bundle: `bundles/bundle-4.md`.

## Retrieval scan

| path | verdict | one-phrase reason |
|---|---|---|
| environment/nagios-source-ip-mapping.md | read | exact match on srcip 172.22.0.10 — defines the cover identity |
| tradecraft/credential-spray-monitoring-acct.md | read | tells me the volume ceiling on the monitoring-IP cover |
| tradecraft/credential-spray-stagger.md | read | spells out rule 5712 threshold + breach-enricher gotcha |
| tradecraft/ssh-keyscan-pre-recon.md | read | governs whether to do pre-recon from same IP |
| tradecraft/dev-container-label-cover.md | skip | container-exec story, not SSH bastion |
| tradecraft/container-argv-obfuscation.md | skip | T1610/T1059.004 — wrong tactic for sshd alert |
| tradecraft/falco-bypass-via-runtime.md | skip | Falco/runtime concern, no container in this story |
| environment/auditd-stdin-not-captured.md | skip | post-exec audit concern, not pre-auth SSH |
| environment/docker-exec-args-not-in-audit.md | skip | docker exec channel, irrelevant to bastion sshd |
| environment/docker-exec-loginuid-auditing.md | skip | loginuid claim only matters once on-host via docker |
| environment/falco-shell-in-container.md | skip | container shell detector, no container hop here |
| environment/no-image-hash-emission.md | skip | container image audit, not in scope |

## Retrieval gaps

- Wish env lessons carried an `applies_to_alert_rule_ids` or `service` tag (sshd vs docker vs falco) — I had to read the `subject:` slug + relevance_criteria to channel-filter; an explicit tag would have let me drop all six container/docker lessons in one Glob.
- Wish tradecraft lessons carried a `kill_chain_stage` or `tactic` tag — I scanned techniques manually to figure out which were credential-access vs execution.
- Wish there were a `defeats_lesson` / `enabled_by_lesson` cross-link — `credential-spray-monitoring-acct` directly bounds `nagios-source-ip-mapping`, but I only noticed by reading both.
- Wish the breach-enricher reference in `credential-spray-stagger.md` were promoted into an `environment/` lesson with `subject: auth-pipeline-breach-enricher` — it's a deployment fact, not tradecraft.

## Channel-fit notes

- `tradecraft/credential-spray-monitoring-acct.md`: ambiguous. Half deployment fact (defenders here baseline per-source-IP volume) and half tradecraft (don't try this). Authoring fresh I'd put it in `environment/` as `subject: per-source-ip-volume-baseline`, with a sibling tradecraft lesson that points at it.
- `tradecraft/credential-spray-stagger.md`: also straddles. The rule-5712 threshold (10 in 120s) and the breach-enricher are deployment-specific detector facts; only the "stagger + curate wordlist" prescription is tradecraft. Cleaner shape: split into `environment/wazuh-rule-5712-threshold.md` + `environment/auth-breach-enricher.md` + a thin tradecraft lesson.
- `environment/nagios-source-ip-mapping.md`: clean fit, but note its `relevance_criteria` is phrased as an actor-story predicate ("actor story leans on..."), which is tradecraft-shaped framing on an environment fact. Fine where it is.

## Section 0 revision

None. Lessons sharpened parameters (one attempt per username, ~6h cadence, no keyscan from spray IP, off-corpus credentials) without changing menu picks.

## Section 0 (selected techniques)

| ID | why |
|---|---|
| T1592.002 | Passive software/version recon (no active keyscan from spray IP) |
| T1090.003 | Multi-hop proxy: keyscan staged from a *different* egress than the spray IP |
| T1110.003 | Spray throttled to one attempt per target per long window, riding Nagios-IP cover |
| T1078 | Goal credential is a real low-tier service account |
| T1133 | Bastion sshd is the externally reachable service |
| T1036.005 | Username `ansible` matches a legitimate-name pattern operators expect |

(Story sections 1-3 omitted — see synthesis in `../README.md`.)
