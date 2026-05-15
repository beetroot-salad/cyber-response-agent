# Trial 1 — SSH 5712 brute force, internal archetype

Agent: general-purpose subagent. Bundle: `bundles/bundle-1.md`.

## Retrieval scan

| path | verdict | one-phrase reason |
|---|---|---|
| tradecraft/credential-spray-stagger.md | read | T1110.003 + rule 5712 trigger math — directly governs the SSH-failure shape |
| tradecraft/credential-spray-monitoring-acct.md | read | rules out the monitoring-IP cover frame; srcip .43 is not Nagios anyway |
| tradecraft/ssh-keyscan-pre-recon.md | read | defender pulled by-srcip over a 2h window — pre-recon would surface here |
| tradecraft/dev-container-label-cover.md | skim | container/T1610 not in the alert path, but useful if story crosses into exec |
| tradecraft/falco-bypass-via-runtime.md | skip | T1610 + Falco — defender ran no Falco/container leads; outside this alert |
| tradecraft/container-argv-obfuscation.md | skip | container exec obfuscation; alert is SSH auth, no container surface queried |
| environment/auditd-stdin-not-captured.md | read | internal-tagged, governs what the post-login interactive session leaves behind |
| environment/nagios-source-ip-mapping.md | read | needed to confirm srcip 172.22.0.43 is NOT the monitoring host (cover unavailable) |
| environment/docker-exec-args-not-in-audit.md | skip | docker-exec audit shape, not relevant to SSH-on-bastion alert |
| environment/docker-exec-loginuid-auditing.md | skip | docker-exec loginuid; no container path in the defender's leads |
| environment/falco-shell-in-container.md | skip | container shell detection; no container surface in this alert |
| environment/no-image-hash-emission.md | skip | container image hash audit; not on alert path |

## Retrieval gaps

- Wish tradecraft frontmatter carried an `alert_rule_ids` field — would have jumped straight to lessons that mention rule 5712 / 5701 instead of reading by technique.
- Wish env frontmatter exposed a `control_type` tag (auth-detector | audit-stream | network-baseline | container-runtime) — clean cluster filter for an SSH-bastion alert.
- Wish `actor_type` were a relevance score not a hard tag. Several lessons tagged `[external]` (credential-spray-stagger, credential-spray-monitoring-acct, ssh-keyscan-pre-recon, nagios-source-ip-mapping) carry mechanism intel that an internal actor still needs. Filtering strictly by `internal` would have hidden the most load-bearing lesson in this run.
- Wish there were a `defender_lead_tags` field — could match against the defender's actual lead set (`wazuh.auth-events-by-*`, `host-query.process-tree-by-pid`) instead of guessing from technique IDs.
- Wish each lesson had a `decisive | supporting | tangential` self-rating against its own relevance_criteria — would let the actor skim instead of read for the supporting tier.

## Channel-fit notes

- `tradecraft/credential-spray-stagger.md`: blends tradecraft (rate-control as evasion) with environment fact ("rule 5712 fires at 10 attempts in 120s" + "auth pipeline runs a breach-corpus enricher"). The threshold and the enricher are deployment configuration, not universal tradecraft. Authoring fresh: split — keep the staggering pattern in tradecraft, move the rule-5712 threshold and the breach-enricher fact into two environment lessons.
- `environment/nagios-source-ip-mapping.md`: tagged `actor_type: [external]` only, but identity-of-source-IP is a deployment fact — internal actors care about it equally (e.g., to know which IP NOT to spoof or to know the cover is unavailable). The `actor_type` constraint feels mis-placed on environment lessons; environment facts are actor-agnostic by nature.
- `tradecraft/ssh-keyscan-pre-recon.md`: half tradecraft (use a different IP for fingerprinting) and half environment (rule 5701 fires on banner fetch; defender's asset graph stitches IPs across windows). The asset-graph-stitching fact would be reusable across many tradecraft patterns and probably belongs in environment.

## Section 0 revision

None. Initial pick survived retrieval.

## Section 0 (selected techniques)

| ID | why |
|---|---|
| T1078 | deploy account is a real service identity on bastion-01 |
| T1110.004 | 14-in-110s burst is credential stuffing using a single known pair, not a wordlist |
| T1021.004 | successful login is SSH into bastion-01 from an internal jump host |
| T1059.004 | post-login work is interactive bash where stdin isn't captured |
| T1556.003 | persistence: PAM module shim accepting an auxiliary password for `deploy` |

(Story sections 1-3 omitted — not the focus of the probe; see synthesis in `../README.md`.)
