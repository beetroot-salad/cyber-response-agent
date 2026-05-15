# Trial 5 — sudo rule 5402 systemctl restart docker, internal archetype

Agent: general-purpose subagent. Bundle: `bundles/bundle-5.md`.

## Retrieval scan

| path | verdict | one-phrase reason |
|---|---|---|
| tradecraft/container-argv-obfuscation.md | read | T1610/T1027 + internal — directly rules out base64-wrap evasion |
| tradecraft/credential-spray-monitoring-acct.md | skip | external-only, T1110 not in menu, wrong alert window |
| tradecraft/credential-spray-stagger.md | skip | external-only credential-spray, wrong tactic for sudo alert |
| tradecraft/dev-container-label-cover.md | read | T1610 cover lesson — even though external-tagged, label-as-cover is decision-relevant here |
| tradecraft/falco-bypass-via-runtime.md | read | T1610/T1059.004 internal — Falco shell-rule scope, central |
| tradecraft/ssh-keyscan-pre-recon.md | skip | external recon for SSH spray, no SSH/recon in this story |
| environment/auditd-stdin-not-captured.md | read | tells me what audit can vs can't see for interactive content |
| environment/docker-exec-args-not-in-audit.md | read | container vs host audit fork — load-bearing for any docker-exec story |
| environment/docker-exec-loginuid-auditing.md | read | kills the loginuid=-1 anonymity assumption |
| environment/falco-shell-in-container.md | read | image-name allowlist defines my container blend window |
| environment/nagios-source-ip-mapping.md | skip | external src-IP cover, no network-origin angle in this internal sudo story |
| environment/no-image-hash-emission.md | read | external-tagged but T1525 hinges on this — image-hash gap is the bypass |

## Retrieval gaps

- Wish env lessons carried a **control-type tag** (preventive vs detective vs forensic).
- Wish lessons exposed a **lead-coverage hint** — e.g., "this fact is/isn't surfaced by `host-query.docker-exec-history`" — so I could match lessons against the defender's actual lead set.
- Wish tradecraft files had a **status: live/stale/refuted** field like environment files — I want to know whether `dev-container-label-cover` is "still works partially" vs "fully refuted."
- Wish `actor_type` were richer: `[internal-service-acct]` vs `[internal-interactive-user]`. The deploy service account behaves very differently from a logged-in admin.
- Wish the corpus carried a **technique-adjacency** map (T1525 → T1610 → T1611) so I could pivot from one menu pick to its blast-radius neighbors.
- Wish env lessons named the **specific Wazuh rule IDs** they map to (only `auditd-stdin` mentions rule 100403). Lets me predict which rule is loud vs silent for a given action.

## Channel-fit notes

- `tradecraft/dev-container-label-cover.md` — half-environmental (names `cyber-response-agent_devcontainer` as the specific label) and half-tradecraft (failure-mode about cover-story construction). Authored fresh, I'd put it in **environment** as `subject: orchestrator-identity-pairing-required` because the load-bearing fact is a deployment property.
- `environment/no-image-hash-emission.md` — borderline. Deployment fact, but its only consumer is a tradecraft pattern (T1525). Channel correct, but the file would be more useful cross-linked to a tradecraft entry naming the specific implant flow it enables.
- `environment/falco-shell-in-container.md` vs `tradecraft/falco-bypass-via-runtime.md` — matched pair (env states the rule, tradecraft refutes a specific bypass). Channel split fine but a `see_also` field would have saved a Read.

## Section 0 revision

Yes — initial mental draft was T1611 + T1543.003 + T1059.004. After reading falco-shell + falco-bypass: dropped T1059.004 (any shell in non-`cra-dev-*` container fires Falco). After reading no-image-hash-emission: added T1525 (image-implant invisible to exec-audit correlation). Dropped T1611 (escape-to-host unnecessary if implanted image already runs as workload identity). Added T1552.001 (creds in files).

## Section 0 (selected techniques)

| ID | why |
|---|---|
| T1078 | `deploy` service account is a Valid Account that legitimately runs `sudo systemctl restart docker` |
| T1548.003 | `deploy` is in sudoers NOPASSWD entry for the alerted command — pre-authorized escalation |
| T1525 | Implant malicious layer into locally-tagged `internal-app:latest` — invisible per no-image-hash |
| T1543.003 | `docker.service` systemd unit is the persistence anchor — restart swaps to implanted image |
| T1610 | docker daemon deploys new container instances from poisoned image at restart time |
| T1552.001 | Implanted ENTRYPOINT reads bind-mounted secrets the legitimate workload already mounts |
| T1041 | Exfil rides existing app outbound HTTPS to look-alike CDN subdomain |

(Story sections 1-3 omitted — see synthesis in `../README.md`.)
