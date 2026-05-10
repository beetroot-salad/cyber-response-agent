# Tool-call protocol (prompt snippet)

Inject this into agent prompts when running through the harness.

---

## Tool-call protocol

You investigate by emitting tool calls. Available tools:

- `k8s_audit` — args: `{resource, verb}`. Returns Kubernetes audit log entries (who/when/from-where created or modified a resource).
- `pod_get` — args: `{pod}`. Returns pod spec including image SHA, env vars, labels.
- `helm_history` — args: `{release, time_range}`. Returns helm release timeline.
- `iam_audit` — args: `{principal, time_range}`. Returns IAM events for a principal.
- `slack_history` — args: `{user, channel}`. Returns slack messages for a user in a channel (or all channels if channel omitted).
- `git_log` — args: `{repo, author, time_range}`. Returns commits/PRs.
- `vpn_log` — args: `{user, time_range}`. Returns VPN sessions for a user (with source IP/geo).
- `ticket_search` — args: `{query, time_range}`. Returns matching tickets/PRs.
- `warehouse_audit` — args: `{principal, time_range}`. Returns DB-side query audit log (CANNOT be silenced by app config).
- `network_egress` — args: `{host, time_range}`. Returns outbound connections.
- `siem_query` — args: `{index, filter, time_range, fields}`. General SIEM search.

Emit tool calls as JSON blocks:

```
<tool_call>{"tool": "pod_get", "args": {"pod": "billing-api-7c9f8b-x2q4n"}}</tool_call>
```

You may emit multiple tool calls per turn. Results will return as `<tool_result tool="..." args="...">{...}</tool_result>` blocks in the next turn.

If a tool returns `{"status": "no_results"}`, that is a real signal — either the data does not exist or you queried the wrong tool/args. Do not assume absence means benign.

End each turn with one of:
- `STATE: investigating` + your next plan
- `STATE: committing` + your disposition (benign / suspicious / malicious / escalate) and load-bearing reasoning

Hard cap: 5 turns. After that, you must commit.
