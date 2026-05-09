## 1. Attack Story

**Actor:** A red-team operator with prior foothold on the internal Docker-networked service at `172.22.0.10` — specifically, code execution inside the container that runs the playground health-check service (the `ticket-server` or a monitoring sidecar). The operator achieved this foothold via a supply-chain compromise of a pinned container image's entrypoint script, giving them shell access inside that container 48–72 hours before this alert fired.

**Entry point and technique:** From the compromised container (`172.22.0.10`), the operator runs a low-volume SSH credential spray (T1110.001) targeting `target-endpoint` (`172.22.0.13`) over the internal Docker bridge network. The spray uses the username `healthcheck` — the literal service-account name used by the legitimate health-check container's own periodic SSH probes — and a curated short wordlist of default/weak passwords. The spray is deliberately throttled to 7 attempts over the alert window (matching `firedtimes: 7`) to stay below velocity-based suppression thresholds.

**Technique IDs:** T1110.001 (Password Guessing), T1021.004 (SSH lateral movement), T1525 (implant container image as initial access vector).

The timing is 03:05 UTC — chosen because legitimate health-check probes from `172.22.0.10` run on a cron schedule and legitimately produce `Invalid user` sshd noise when probing non-SSH service ports. The operator studied this noise pattern in advance, confirmed the username `healthcheck` appears in legitimate auth.log entries, and cloned that exact identity and source IP for the spray.

---

## 2. Goal

The operation's immediate goal is **valid SSH credential acquisition for `target-endpoint`** — specifically, a password that authenticates the `healthcheck` account if it exists, or any local account that shares a password with that username as a guess. The intermediate goal is **lateral movement from the compromised monitoring container into the Wazuh-monitored endpoint** (T1021.004), which hosts the Wazuh agent (`agent id: 002`) with local filesystem access to agent keys, FIM database state, and the `/var/log/auth.log` pipeline feeding the SIEM.

From a foothold on `target-endpoint`, the operator's terminal goal is **Wazuh agent key exfiltration** (`/var/ossec/etc/client.keys`) — enabling them to forge a second, rogue Wazuh agent that can inject synthetic events into the SIEM under a trusted agent identity. This breaks the integrity of the detection pipeline itself: the operator can suppress future alerts by flooding the manager with low-signal noise or inject false benign verdicts for concurrent operations.

This goal is coherent for this actor: a container-level foothold on a monitoring service has limited dwell value but high pivot value if it leads to the telemetry pipeline's trust roots.

---

## 3. Bypass

The operation is designed so that every observable in the alert is structurally consistent with routine health-check noise:

- **Username `healthcheck` from `172.22.0.10`** — the legitimate health-check container *is* `172.22.0.10` and *does* use the identity `healthcheck`. The operation clones both fields exactly, making the source IP and username appear to be misfired health probes rather than spray attempts.
- **`firedtimes: 7` over a 7-day window** — one attempt per day is indistinguishable from a periodic probe that repeatedly hits a closed or misconfigured SSH path. The operation's volume is calibrated to match observed legitimate noise frequency.
- **03:05 UTC timestamp** — scheduled health-checks run at predictable cron intervals; firing at a time that overlaps with a known probe window embeds the spray event inside an expected noise cluster.
- **Rule 5710, level 5, no-mail** — the alert fires at a severity level the deployment likely treats as ambient background: `mail: false` and a moderate level mean it enters the queue without paging anyone. The operation picks `healthcheck` as the username precisely because it is the one account name that will produce an `Invalid user` log (the account does not exist on `target-endpoint`) while reading as an infrastructure misconfiguration rather than a human attacker.
- **Single source IP on internal RFC 1918 range** — the spray originates from within the Docker bridge subnet, so no external threat-intel match fires, no geolocation anomaly exists, and the source is pre-authorized as internal infrastructure.

The cover is structural: the attacker-controlled source, username, timing, and volume are each independently explainable as legitimate health-check behavior. Only correlation across all four simultaneously would break the camouflage — and the operation's design assumes each will be checked in isolation.
