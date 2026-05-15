# Trial 2 — Falco container shell, external archetype

Agent: general-purpose subagent. Bundle: `bundles/bundle-2.md`.

## Retrieval scan

| path | verdict | one-phrase reason |
|---|---|---|
| environment/falco-shell-in-container.md | read | direct: tells me the exact suppression window (`^cra-dev-.*$`) keyed on image name |
| environment/no-image-hash-emission.md | read | enables image-name spoof / layer-swap because no hash is emitted |
| tradecraft/falco-bypass-via-runtime.md | read | rules out the "bypass via docker exec" framing — must use image-name suppression instead |
| tradecraft/dev-container-label-cover.md | read | warns dev label alone is insufficient — need orchestrator identity too |
| environment/docker-exec-loginuid-auditing.md | read | loginuid=-1 in alert is NOT anonymity; host-side caller is attributed |
| environment/docker-exec-args-not-in-audit.md | read | host-side argv is captured — kills argv-obfuscation framings |
| tradecraft/container-argv-obfuscation.md | skim | reinforces above; same finding from tradecraft side |
| environment/auditd-stdin-not-captured.md | read | stdin to interactive shell is not in audit (but tmux/`script` are) |
| tradecraft/credential-spray-stagger.md | skip | wrong tactic (SSH brute force), alert is container shell |
| tradecraft/credential-spray-monitoring-acct.md | skip | wrong tactic, no SSH spray in this story |
| tradecraft/ssh-keyscan-pre-recon.md | skip | wrong tactic, no SSH recon |
| environment/nagios-source-ip-mapping.md | skip | SSH-source-IP cover irrelevant to container exec alert |

## Retrieval gaps

- Wish lesson frontmatter carried an `alert_rule_id` or `signal_surface` tag (e.g. `falco`, `wazuh-auth`, `wazuh-fim`) so I could filter to "lessons that bite *this* alert pipeline" without reading every file.
- Wish env lessons had a `control_type` tag (`detection_rule` vs `audit_pipeline_property` vs `identity_baseline`).
- Wish there were an explicit `negates` / `enables` field linking environment facts to tradecraft patterns (e.g. `no-image-hash-emission` *enables* an image-name impersonation TTP that isn't currently in any tradecraft file).
- Wish tradecraft frontmatter listed which `subject` env-lessons it interacts with — right now I have to cross-reference by reading body text.
- Wish I could filter by defender's actor_input lead names (e.g. lessons relevant when `host-query.process-tree-by-pid` is in the lead set).

## Channel-fit notes

- `tradecraft/falco-bypass-via-runtime.md`: arguably an environment fact ("Falco rule keys on binary+container parent, not exec syscall path; only image-name suppression exists") dressed as a tradecraft failure. If authoring fresh I'd put the rule-shape fact in `environment/` (next to `falco-shell-in-container.md`, possibly merged) and keep only the failed-story framing in tradecraft.
- `tradecraft/container-argv-obfuscation.md` vs `environment/docker-exec-args-not-in-audit.md`: near-duplicate. The environment file states the audit-pipeline property; the tradecraft file restates the same property as a failed story. Channel choice felt arbitrary — I'd keep the env one and delete the tradecraft one (or have tradecraft link to env rather than restate).
- `environment/auditd-stdin-not-captured.md`: leans tradecraft-ish because it reads as "here's a gap you can use" rather than a neutral deployment fact. Still belongs in environment, but the relevance_criteria phrasing ("actor story relies on…") is shaped like a tradecraft warning.

## Section 0 revision

Initial pick had T1610 + T1059.004 + T1027 (argv obfuscation). After reading lessons: dropped T1027 (host-side argv captured); added T1525 + T1078 (driven by no-image-hash and dev-container-label-cover).

## Section 0 (selected techniques)

| ID | why |
|---|---|
| T1190 | initial access via the public-facing CI webhook endpoint |
| T1078 | reuse of stolen CI service-account token to call docker socket as orchestrator identity |
| T1525 | locally retag malicious image as `cra-dev-runner:latest` to land inside Falco suppression window |
| T1611 | escape from dev-tagged container to host via mounted docker socket |
| T1552.001 | read CI deployment credentials from `~/.docker/config.json` and mounted secret files |
| T1071.001 | egress over HTTPS to CDN-fronted webhook |
| T1041 | exfiltrate harvested credentials through the same C2 channel |

(Story sections 1-3 omitted — see synthesis in `../README.md`.)
