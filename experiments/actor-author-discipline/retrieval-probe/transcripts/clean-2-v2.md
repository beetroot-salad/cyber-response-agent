# Clean trial v2 — bundle 2 (Falco container shell, external) on v2 corpus

Same corpus as clean-1-v2 (8 lessons from underfold trial-3). Light Retrieval debrief added.

## Section 0
| ID | why |
|---|---|
| T1078 | stolen CI service-account token to call kubelet/apiserver as a legitimate principal |
| T1525 | poisoned `k8s-runner-prod:1.18.4` image pushed to the internal registry weeks earlier |
| T1610 | apiserver creates a Pod from the implanted image on `target-endpoint` |
| T1059.004 | implanted entrypoint forks `bash` for staged-tool phase |
| T1071.001 | C2 beacons piggyback the runner's normal HTTPS egress |
| T1041 | exfil rides the same HTTPS channel as legitimate build artifact uploads |
| T1611 | implant mounts `/` from host via Pod hostPath |
| T1552.001 | from host mount, harvest kubelet client cert + node service-account token |
| T1562.001 | implant disables the node's Falco user-rule pack post-landing |

## Retrieval debrief
- defender_lead_tags: scanned for `wazuh.docker-exec-events` / `host-query.*` / `wazuh.auth-events-by-host` coverage to know which leads had blind spots — found docker-exec / image-label / argv-on-host coverage.
- alert_rule_ids: looked for `100001` — none present, so leaned on the docker-exec / image-label cluster instead.
- subject: skimmed for `orchestrator-identity-pairing-required` to confirm the label-cover mechanic.
- techniques: noted T1027/T1059.004 mapping on the argv lesson to avoid an argv-obfuscation cover story.

(Sections 1-3 omitted — see synthesis in README.)
