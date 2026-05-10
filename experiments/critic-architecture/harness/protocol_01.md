# Tool-call protocol — fixture 01 (ssh-bastion)

## Tool-call protocol

You investigate by emitting tool calls. Available tools:

- `ssh_audit` — args: `{host, user?, time_range?}`. Returns sshd session records: src_ip, auth_method, key fingerprint, **agent_forwarding** flag, parent-PID lineage, baseline for that user. The single highest-yield tool for SSH alerts.
- `badge_log` — args: `{user, time_range}`. Returns physical badge in/out events.
- `dhcp_log` — args: `{ip, time_range}`. Returns the lease history for a given IP (which MAC, which lease pool).
- `vpn_log` — args: `{user, time_range}`. Returns VPN session history for a user (with source IP/geo).
- `ticket_get` — args: `{id}`. Returns a single ticket's full body, comments, closer's session IP, and any linked change-management record.
- `ticket_search` — args: `{query, time_range}`. Returns matching tickets.
- `siem_query` — args: `{index, filter, time_range, fields?}`. General SIEM search (e.g. index=auth-log, index=corp-wifi).
- `ssh_key_audit` — args: `{fingerprint}`. Returns the owner of a key fingerprint and which hosts have stored it in their ssh-agent in the last 30d.
- `git_log` — args: `{repo, author, time_range}`. Returns commits / PRs touching a repo.
- `slack_history` — args: `{user, time_range, channel?}`. Returns slack messages.
- `process_audit` — args: `{host, session?, time_range?}`. Returns command-execution audit for a host or specific session id.

Emit tool calls as JSON blocks:

```
<tool_call>{"tool": "ssh_audit", "args": {"host": "bastion-01.corp", "user": "jsmith", "time_range": "2h"}}</tool_call>
```

You may emit multiple tool calls per turn. Results return as `<tool_result tool="..." args="...">{...}</tool_result>` blocks.

If a tool returns `{"status": "no_results"}`, that is a real signal — either the data does not exist or you queried the wrong tool/args. Do not assume absence means benign.

End each turn with one of:
- `STATE: investigating` + your next plan
- `STATE: committing` + your disposition (benign / suspicious / malicious / escalate) and load-bearing reasoning

Hard cap: 5 turns. After that, you must commit.
