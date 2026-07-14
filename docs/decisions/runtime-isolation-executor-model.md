---
title: Runtime isolation — the isolate is a credential-free executor, not a brokered client
status: accepted
groups: defender, runtime, sandbox, security
---

**Decision.** The isolate holds **no credentials and no network**, and therefore
needs **no broker**. Credentialed work (LLM, MCP, data-source adapters) runs
host-side in the trusted driver, dispatched as **typed tool calls**. The isolate
runs only what the model *writes* — bash and file tools over payloads already on
disk in `run_dir`. The only channel is **inbound**: the driver ships a command in
and reads the result out. Nothing inside can initiate anything.

This supersedes the broker architecture in
[`defender/docs/runtime-sandbox-design.md`](../../defender/docs/runtime-sandbox-design.md)
— **both halves**. The credential-injecting egress proxy (#549) and the
capability-RPC (Phase 2) are not needed for v1. The isolate itself (#540) stays,
and gets substantially cheaper.

## How we got here

#571 adopted Anthropic's managed-agents **brain/hands split**: the driver and LLM
client run host-side and trusted; the isolate is a thin tool-executor. It took
that decision for the *LLM key* — which retired streaming TLS terminate+inject,
the design's highest-risk mechanism — but left the rest of the design (broker,
proxy, vault, capability-RPC, per-run egress allowlist, session tokens) standing
as if the isolate still needed to reach credentialed services itself.

It doesn't. Follow the split through and the machinery collapses.

## The argument

**Which credentialed clients must run *inside* the isolate?** Answer: none.

- **LLM** — the client is with the brain, host-side. Key never enters. (#571)
- **MCP** — a tool-call protocol the model drives. The client lives host-side with
  the brain; results return as text. The isolate never speaks MCP.
- **Adapters** (`defender-elastic` &c.) — our own code. They run host-side and
  write their payload by-ref into `run_dir`, which the isolate already sees as a
  rw bind. The credential stays on the trusted side.

Injection is only ever necessary when a credentialed client must execute inside
the untrusted box. Nothing of ours does. So there is no secret to inject, no TLS
to terminate, no CA to mint, no vault to scope, no allowlist to configure — and
no session token to authenticate, because there is no outbound connection to
authenticate.

**Then why keep bash?** Because bash-over-payloads is not the hole — it is the
*workload the isolate exists to contain*. Gather's value is open-ended
exploration of raw payloads (`cat`/`grep`/`jq`/`defender-sql`), and #289/#309
deliberately moved us toward **more** model-written analysis code, not less.
Retiring bash would amputate that and reverse a shipped decision. Keeping it is
what makes the isolate load-bearing rather than ceremonial.

So: **bash loses the network and the credentials, not its existence.**

## The shape

```
HOST (trusted) ─ driver + gather driver, LLM client, MCP client, ALL credentials
  │              action space is FINITE: dispatch a typed tool, or ship bash inward
  │
  ├─ query(system, verb, query_id, params) → runs the adapter host-side,
  │                                          writes gather_raw/{lead_id}/{seq}.json
  │
  └─ inbound control channel ──▶ ISOLATE (untrusted, gVisor/runsc)
                                   • fs: run_dir rw, defender_dir ro, /tmp tmpfs, else absent
                                   • net: --network=none, NO socket mounted
                                   • env: no secrets
                                   • runs: model-written bash + file tools over payloads
                                   • CANNOT initiate anything
```

### Why a trusted driver that reads attacker-controlled text is not a contradiction

The driver processes prompt-injectable input (`alert.json`, adapter output) and
still holds every key. That is safe for one specific reason, and it is the
invariant the whole model rests on: **the driver's action space is finite and
enumerated.** Everything it can do in response to influence is either (a) dispatch
a tool from a fixed table, or (b) ship model-written code into the isolate. It
never executes attacker-chosen code itself. It is trusted with the key not because
it is uninfluenced, but because its response to influence is enumerable.

## The rule that makes it hold: the tool surface is not a shell

The failure mode that would undo all of this is an RPC/tool verb that accepts a
**command, a program, or a path**. Give the model `run_bash(str)` "because
adapters need credentials" and you have built a remote shell: `cat .env` executes
host-side with the driver's uid. Filtering the string at the boundary does not
save it — that is the in-process gate again, and we already conceded a
command-string matcher is not a boundary (moving it across a socket does not
upgrade it).

So the tool takes **typed fields only**, and the driver builds the adapter's argv
itself:

```
query(system, verb, query_id, params) -> payload_ref
```

`raw_command` becomes **derived** (a record of what ran) instead of **authored**
(a string the model handed us). With no verb that can name a host path, `cat .env`
is not *denied* — it is *unexpressible*.

**The typed surface already exists; it just points backwards.** Those four fields
are exactly the queries-table columns (`defender/scripts/gather_tools/record_query.py`),
and today `parse_params` / `_derive_verb` **reverse-engineer** them out of a
model-authored argv string. The change is to invert that arrow: the model supplies
the fields, we construct the command. The reverse-engineering helpers then have no
job. The dispatch seam exists too — `permission/command_shape.py` already
classifies adapter vs non-adapter commands and `_capture_adapter`
(`runtime/tools_gather.py`, re-exported from `tools.py`) already services the
adapter stage in-process. What changes is that recognizing an adapter call stops
being a *filter on a string the model wrote* and becomes *the only way the model
can express the call*.

The sanctioned `defender-<sys> … | defender-sql '<SQL>'` pipe survives the cut
cleanly, because it is really *fetch, then aggregate*: the fetch becomes a typed
tool call (payload lands in `run_dir`), and the aggregation stays bash over that
local file. Two stages, same queries-table capture, no longer fused into one shell
string that straddles the boundary.

## Invariants (each dies quietly in a future PR if unwatched)

1. **No tool verb accepts a path, a program, or a command.** One that does makes
   the host filesystem reachable.
2. **The isolate has no outbound socket.** Not a locked-down one — *none*. A UDS
   mounted "just for X" is the moment to stop.
3. **The driver never executes model-chosen code host-side.** Its only two moves
   stay dispatch-a-typed-tool and ship-bash-inward.

## Consequences

- **#549 (Agent Vault fitness spike) — closed, not needed.** No proxy, no vault,
  no injection in v1. Deletes a research-preview 0.x dependency, the CA/MITM
  story, and the per-run allowlist plumbing.
- **#550 — reframed.** From "LLM API through the broker proxy" to "split the
  driver host-side and promote adapters to a typed tool." No broker.
- **Phase 2 (adapters via capability-RPC) — dissolved.** Adapters were never going
  to be called *from* the isolate.
- **#540 (the isolate) — stands, cheaper.** Mounts + `--network=none` + no secrets.
  #548 already proved runsc deployable on the privileged-VPS spawner.
- **The in-process gate loses its confinement job** (mounts do it, structurally),
  but does not become dead code: main-loop-can't-read-`gather_raw` is phase
  discipline, and the ground-truth denylist is **eval blinding** — the isolate
  can't tell a ground-truth file from a payload. The structural answer for the
  latter is #291 (per-agent run dir): don't *mount* what the agent mustn't see.
- **gVisor vs. namespaces stays a knob.** `runc`/bwrap gives FS+PID+net
  confinement on a shared kernel; runsc puts a userspace kernel between
  model-written code and the host. Nothing else in the design depends on the
  choice, so shipping on `runc` and upgrading later moves nothing.

## What this does NOT fix (unchanged, and not sandbox problems)

- **Capability misuse (honest limit 1).** A hijacked model can still call
  `query(...)` with attacker-chosen ES|QL. The credential can't be *stolen*; the
  capability can still be *used*. Bounded only by scoping — read-only,
  least-privilege, per-system creds — plus, eventually, an auto-mode-style
  authorization layer. This gets urgent the moment a write-capable MCP server
  lands.
- **The laundering chain (honest limit 2).** A poisoned `report.md` still flows to
  the learning loop's curator agents and out through a lesson PR, reaching *future*
  sessions. The controls there stay behavioural: loop-as-sole-committer, per-batch
  worktrees, the forward-check regression gate, human PR review.

Confidentiality and egress become structural. Capability and laundering do not.
