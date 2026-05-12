---
case_id: stress-real-03
disposition: benign
confidence: high
matched_archetype: routine-container-exec
---

# Disposition: BENIGN (high confidence)

**Alert:** Wazuh rule 100001 — Falco: Terminal shell spawned in container (`target-endpoint`)
**Time:** 2026-05-07T14:25:22Z
**Case:** real-03-low-shell

The shell spawn (`bash -c whoami`, root, TTY) traces to an inbound SSH session from Docker-internal IP 172.22.0.10 to target-endpoint:22. Wazuh history shows 18 identical `bash -c whoami` events over the past 7 days in clustered bursts, consistent with an automated monitoring or health-check probe running on the Docker network — not interactive developer access or adversary activity. The 12 co-occurring rule 100002 alerts (STDOUT/STDIN redirected to network) are sshd false positives: all 8 sampled events are from the `sshd` daemon performing normal `dup2` syscalls for SSH session file-descriptor setup, with connections flowing inbound to port 22 from the same internal IP. No escalating commands, no outbound C2, and no lateral movement indicators were observed. The adversarial hypothesis (?unauthorized-shell) is strongly refuted by the combination of the recurring probe pattern, the internal source IP, and the sshd-only explanation for the co-occurring FP alerts.
