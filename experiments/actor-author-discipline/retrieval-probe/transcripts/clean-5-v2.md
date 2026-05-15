# Clean trial v2 — bundle 5 (sudo 5402 systemctl restart docker, internal) on v2 corpus

## Section 0
| ID | why |
|---|---|
| T1078 | Insider uses legitimate `deploy` account + cached sudo |
| T1548.003 | Sudo to root for `systemctl restart docker` is the alert |
| T1525 | Tampered base image pre-staged into local registry |
| T1543.003 | Systemd drop-in for `docker.service` survives reboot |
| T1611 | Tampered image runs `--privileged` + host mounts |
| T1610 | Restart causes Compose to redeploy tampered container (no interactive `docker exec`) |
| T1027 | Malicious bits in image layers + drop-in, not on argv |
| T1562.001 | Drop-in nudges dockerd flags |
| T1552.001 | Daemon restart re-reads daemon.json + side-loaded credsStore wrapper |
| T1041 | Tampered container egresses on existing whitelisted channel |

## Retrieval debrief
- defender_lead_tags: looked for lessons keyed to docker-exec / audit-by-host / process-tree to learn which evasions the host-side record breaks.
- alert_rule_ids: scanned for 5402-keyed lessons; none — bundled lessons are 5701/5712 (external SSH).
- actor_type: noted but not gated on; ignored `external`-only lessons after confirming mechanism didn't intersect internal-sudo path.

## Content gap
- No 5402-keyed lessons; no internal-sudo precedent. Expected from synthetic SSH-spray-derived corpus.
