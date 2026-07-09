# Runtime sandbox: gVisor isolate + host-side credential broker

**Status:** design — not yet implemented. **Decision:** run each defender
investigation inside a per-alert **gVisor (runsc) isolate** whose only route
off-box is a **host-side broker** that owns every credential and every egress
destination. Filesystem scope is the isolate's mount list; network scope is the
broker's egress allowlist; credentials are attached *at the broker boundary* and
never cross into the isolate. The broker's proxy half is **adopted, not built**
(Infisical Agent Vault — see §Build/buy); the capability-RPC half stays ours.
The in-process `runtime/permission/` gate demotes to defense-in-depth / UX.

**Forcing issue:** **#540** (OS-sandbox the run as the real read/write boundary).
Builds on **#535** (the interim anchored read-confinement guard, which this
replaces as the *boundary* and leaves as belt-and-suspenders). Related:
`agent-definition-single-source.md` already names this as the eventual boundary
("The real read/write boundary is OS sandboxing (#540); this gate is
defense-in-depth"), and `tests/test_read_confine_bash.py:494-499` defers the
pre-existing-symlink residual to it.

## Why the in-process gate isn't the boundary

The runtime is an in-process PydanticAI loop (`runtime/driver.py`). It processes
attacker-influenceable input — `alert.json` and adapter output are
prompt-injection vectors — so a hostile payload can drive the model to emit tool
calls. The gate (`decide_read`/`decide_write`/`decide_bash`) is a real
deny-by-default allowlist, but:

- It vets *invocation shape*, not what a **subprocess** then does — an adapter is
  its own process that opens files/network itself (`tools.py:205`,
  `_stub_transport.py`).
- The bash reader lane does no `resolve()`; a symlink target is closed by the
  *convention* that "no allowed tool creates a symlink" (`policy.py:15-20`), not
  by structure.
- Command-string matching is fragile to argument tricks by design (Claude Code's
  own permission docs say so; `bash_policy.json:26` already concedes "OS
  isolation is the eventual boundary").

An OS isolate makes the confinement hold *regardless of what command the model
emits*, because out-of-scope paths are **unmounted → nonexistent** and there is
no default network route.

## The shape

```
run.py (venv re-exec, run.py:29-30)
  └─ startup, UNCONFINED: read creds/.env → broker, materialize run_dir,
     render per-run OCI spec + broker config from the tool manifests
       ├─ BROKER (host-side, trusted): holds ALL secrets; the only thing on the network
       │     • egress proxy (ADOPTED: Agent Vault)  allowlist + TLS-terminating credential injection
       │     • capability-RPC (ours)                brokered subprocesses: docker-exec adapters, local CLIs
       │     • brokered services                    credentialed MCP / DB servers
       │     • per-run egress allowlist (default-deny)
       └─ ISOLATE (gVisor runsc, untrusted): the PydanticAI driver + tools
             • fs: rootfs ro (incl. the broker CA cert), defender_dir ro,
               run_dir rw, /tmp tmpfs, else absent
             • net: --network=none → netstack loopback only; a loopback↔UDS
               bridge to the broker socket is the sole off-box path
             • env: secret-free (extends run_common.py:90-92 to all secrets)
```

Chosen runtime is **gVisor** — a userspace guest kernel (Sentry) services the
isolate's syscalls, so a container escape must pierce Sentry before it reaches
the host kernel. It keeps container density/startup and, unlike a microVM, needs
no `/dev/kvm` (so it survives nested/cloud hosts). The runtime is an **OCI knob**:
the identical fs/broker/lifecycle design runs on `runc` (weakest, any host) or a
Firecracker/Kata microVM (separate real kernel, needs KVM) by swapping the
runtime. See "Isolation-strength knob" below. Deployability caveat: `runsc`
itself needs privilege — default mode wants root, and *rootless* runsc rides the
same unprivileged user namespaces we've observed EPERM on — so where the spawner
runs is a must-verify open question (§Open questions), not an assumption.

## The invariant: secrets never enter the isolate

The point of the isolate is that the model-driven code is untrusted. A credential
*inside* the isolate + any egress = exfiltration. So **only the broker holds
secrets**, and it attaches them at the boundary.

**Honest limit 1 — capability misuse.** We keep the *secret* out of the blast
radius structurally, but we **cannot keep the authenticated *capability* out of
it** if a tool must use it: a hijacked agent can't read the key, but it can make
the tool act authenticated against whatever destination we opened.
Confidentiality is structural; **misuse is bounded only by scoping** —
least-privilege / read-only / short-TTL credentials + a tight destination
allowlist. This is why #540 says "ro credentials."

**Honest limit 2 — the downstream laundering chain.** The isolate bounds the
*run*. The bytes the agent writes into `run_dir` then flow to the learning loop,
whose curator agents are themselves LLMs that write lessons and open PRs — so a
prompt-injected runtime agent still has a *sanctioned* channel toward the repo:
poisoned `report.md`/`investigation.md` → curator → lesson/PR. This design does
**not** close that chain; the controls there remain the loop being the sole
committer, per-batch worktrees, the forward-check regression gate, and human PR
review. Read "the isolate is the boundary" as bounding the run, not the loop.

## Filesystem isolation

| Path | Mode | What |
|---|---|---|
| rootfs | **ro** | minimal base image (python + `.venv` + defender code + the broker CA cert) |
| `defender_dir` | **ro** bind | corpus: skills / lessons / SKILL.md / scripts — ro so a hijacked agent can't poison its own lessons *directly* (the sanctioned learning-loop channel remains; honest limit 2) |
| `run_dir` | **rw** bind | per-alert scratch **and the artifact exit** (below) |
| `/tmp` | **tmpfs**, size-capped | writable scratch SIEM CLIs expect |
| everything else | **absent** | unmounted → nonexistent; no `/etc/passwd` to symlink toward |

**Control surface:** the OCI spec's `mounts[]` + `root.readonly`, generated
**per-run by run.py**. FS scope is data (a mount list), not code. The write set is
exactly one directory, so one alert structurally cannot see another's scratch.

**Mount-ordering trap:** the default runs base is `/tmp/defender-runs`, and the
in-isolate path must **equal** the host path (absolute paths leak into
artifacts, orient's workspace map, and `raw_command`), so the OCI mounts array
must place the `/tmp` tmpfs *before* the `run_dir` bind — the bind lands on top
of the tmpfs.

**The way out for report.md / investigation.md / drafts:** `run_dir` is a
bind-mounted host directory, so everything the agent writes lands on the host *as
written* — the learning loop and visualizer read it straight from the host after
the isolate exits. The writable mount **is** the exit; no copy step. The bytes are
agent-controlled *data*, and "downstream parses/renders, never executes" is
necessary but **not sufficient**: a hijacked agent can plant a **symlink** at an
expected path (`gather_raw/l-001/1.json → /root/.ssh/id_rsa` — the target needn't
exist inside the isolate) and a host-side reader that follows it reads host files
into a rendered/committed artifact. That is the same pre-existing-symlink
residual `test_read_confine_bash.py:494-499` defers here — aimed at host-side
consumers instead of the bash lane. So the exit gets a **reap-time scrub**: after
the isolate exits and *before any host-side consumer opens `run_dir`*, run.py
refuses symlinks and hardlinks anywhere under it (fail the run loudly, don't
sanitize silently). Keep the parse/render-only invariant on top.

## Network isolation

**Default: no network.** The isolate runs with runsc `--network=none`: the
sandbox gets gVisor's netstack with **loopback only** — no route, no DNS, nothing
to allowlist, because the isolate physically cannot `connect()` off-box. (Note:
runsc does **not** honor the OCI `linux.seccomp` profile — Sentry services
syscalls itself — so a `socket(AF_INET)`-deny belt exists only on the `runc`
fallback; on runsc the equivalent is the absent network itself.)

**The only off-box path** is the broker's unix socket, bind-mounted in (runsc
needs `--host-uds=open` for this), plus an in-isolate **loopback bridge**: real
HTTP clients — httpx (which the Anthropic/OpenAI SDKs use) and curl — cannot
speak to a *proxy* over a unix socket, so a tiny listener on `127.0.0.1:<port>`
forwards to the socket and `HTTPS_PROXY=http://127.0.0.1:<port>` points at it.
(This is exactly the socat bridge Anthropic's sandbox-runtime uses; ours can be a
thread in the driver process or a socat sidecar in the isolate.)

Egress is **opt-in and mediated**: a tool reaches `api.foo.com` only because the
broker's proxy has that destination on a **per-run allowlist**, and the broker
injects the auth. Host-level allowlisting lives in the broker (Landlock/seccomp
can't express it — they're path/port/syscall only).

**Control surface:** a declarative egress policy held by the broker
(`{host:port → allowed?, inject-credential?}`), generated per-run, default-deny —
concretely, Agent Vault service definitions plus the RPC capability list.

## Credential injection — three modes, one channel

Every auth-requiring tool maps to one of three modes; the secret lives in the
broker in all three.

**The TLS split (how injection actually works over HTTPS).** A plain CONNECT
tunnel is end-to-end TLS: the proxy can enforce *which* `host:port` but sees only
ciphertext, so header injection is impossible there. The proxy therefore has two
per-destination behaviors, selected by the manifest:

- **allowlist-only** (no `credential:` declared): plain CONNECT tunnel. TLS stays
  end-to-end; no CA involved.
- **terminate + inject** (`credential:` declared): the proxy **terminates TLS
  with a broker CA** (trusted in the isolate's rootfs), strips any credential the
  agent attached, injects the destination's bound credential (header/query/mTLS),
  and **re-originates** a verified TLS connection to the real destination. This
  is the standard MITM-with-CA pattern, and it is what Agent Vault implements.

The **LLM API is a terminate+inject destination** — the one credential *every*
run needs (playground included), on a streaming API — so the injection path is
exercised from day one, not "built but unused." This is the main reason the
proxy is adopted rather than built (§Build/buy).

| Mode | For | How the secret is attached |
|---|---|---|
| **Forward-proxy injection** | HTTP CLIs/libs, the LLM API, MCP-over-HTTP | tool runs in the isolate with `HTTPS_PROXY` at the loopback bridge; makes its normal call; broker tunnels or terminates+injects per the TLS split and forwards only to allowlisted hosts — tool never sees the key |
| **Brokered subprocess** | non-HTTP tools (today's `docker exec … curl` adapters, a CLI needing a keyfile) | tool runs host-side in the broker with the secret in its env; isolate invokes it by name over the RPC and gets back only the result |
| **Brokered service** | credentialed MCP / DB servers | broker launches it host-side with its secret; isolate speaks its protocol through the socket |

This generalizes the one pattern that already exists: adapters run host-side via
`_capture_adapter` (`tools.py:205`) with keys stripped from the isolate env
(`run_common.py:90-92`). The broker is where that logic moves.

Worked examples:
- **A CLI wanting `FOO_API_KEY`** → HTTP: run in isolate, point at the proxy,
  broker injects the header. Non-HTTP: run as a brokered subprocess host-side.
- **An MCP server** → brokered service: broker holds its creds, the isolate's
  pydantic-ai MCP client connects through the socket; the agent gets the MCP
  tools, never the server's secrets.

This is the standard secret-injecting-proxy / credential-helper pattern (BuildKit
`--secret`, git-credential, SSH-agent forwarding).

## The broker surface (proxy adopted, RPC ours)

The broker exposes, over the single bind-mounted unix socket, a small multiplexed
surface. HTTP is the spine (covers the LLM + most tools); the RPC handles
non-HTTP capabilities.

**(a) Forward proxy.** The isolate's httpx/curl point at the loopback bridge as
an HTTP(S) proxy. The broker reads the target `host:port` from the CONNECT line,
checks it against the per-run egress allowlist → 403 on miss (logged), then
either tunnels or terminates+injects per the TLS split above. The isolate never
learns the credential and cannot reach an undeclared host.

**(b) Capability-RPC — line-delimited JSON.** For brokered subprocesses/services:
```
→ {"cap":"adapter.elastic","argv":["search","--query-id","…","--params","…"]}
← {"exit":0,"stdout_ref":"gather_raw/l-001/3.json","status":"ok","digest":"…"}
```
The broker runs the capability host-side (creds in *its* env), captures the
payload into the queries table exactly as `record_query.capture` does today, and
returns a by-ref result — so the two-table contract and `gather_raw/` layout are
unchanged; only *where* the subprocess runs moves (host, not isolate).

**The argv is model-controlled — and this mode moves its execution from inside
the confinement to the credentialed host.** "Unlisted cap refused" gates *which*
binary, not what arguments reach it, so the RPC must also validate **per-cap argv
shape** at the broker — the same anchored-grammar move as `bash_allow`, reusing
the `command_shape` classifiers / `ADAPTER_CLI_RE` that already describe adapter
invocations. Execution is `shell=False`, with a minimal env holding only that
cap's secret; out-of-shape argv is deny+log, same as an unlisted cap. (Running
the brokered subprocess under its own light confinement is a worthwhile
follow-on.)

**(c) Brokered-service passthrough.** For MCP/DB: the broker proxies the service
protocol (MCP framing / SQL) over the same socket to the host-side server it
launched with creds.

Everything on this socket is default-deny: an unlisted cap or an unlisted egress
host is refused and logged. The socket is the isolate's entire off-box surface.

## Build/buy — adopt the proxy, write the RPC

"Sandbox the agent, broker its credentials at the egress boundary" became a
product category in 2025–26 — Cloudflare Sandboxes ships credential injection +
TLS interception + per-instance egress policies; Azure's SRE agent keeps all
tokens in an identity sidecar so "credentials never enter the reasoning context."
The architecture here is the emerging standard, not an invention — so buy the
generic parts:

- **Adopt: [Infisical Agent Vault](https://github.com/Infisical/agent-vault)**
  (MIT + `ee/` exception) as the forward proxy: `HTTPS_PROXY`-shaped, destination
  allowlisting via declared services, strips agent-attached creds, TLS-terminates
  with a local CA and injects, short-lived vault-scoped tokens authenticate the
  isolate to the proxy. This deletes the hardest would-be-custom component — a
  streaming-capable TLS-terminating injecting proxy. Caveats we carry: it's 0.x
  (API churn); it listens on TCP, so it sits host-side behind the UDS↔loopback
  bridge; its CA cert bakes into the rootfs; per-run dynamic allowlists need
  scripting against its config surface (spike below).
- **Still ours (small, domain-specific):** the per-run OCI spec generation; the
  capability-RPC + its argv validation + queries-table capture; the manifest
  compiler (now compiling to Agent Vault service config + OCI mounts + RPC caps);
  the reap-time scrub.
- **Evaluate at the many-alerts phase:
  [OpenSandbox](https://github.com/alibaba/OpenSandbox)** (Apache-2.0): a
  self-hostable sandbox *platform* — gVisor/Kata/Firecracker runtimes,
  per-sandbox egress controls, a credential vault, Python SDK. It would collapse
  the scheduler question too, but restructures the run lifecycle around its
  server + exec API and likely costs the run_dir-bind-mount-is-the-exit
  property. Wrong trade for single-host v1; the natural candidate when "many
  isolates" becomes real.
- **Fallbacks if the Agent Vault spike fails:** Envoy (its credential-injector
  filter + TLS origination) or a minimal mitmproxy-based shim. The architecture
  doesn't move; only the proxy binary does.

## Plugging in tools — the capability manifest

Make the safe path the declarative path. A per-tool **manifest** the user drops in
compiles into: the isolate's tool surface + the broker's capability + the egress
allowlist. The user describes intent and never hand-edits the sandbox spec, so
they cannot open a hole wider than declared. This is the same policy-as-data move
as `bash_policy.json` / `AgentPolicy` / the `/connect` conformance skill.

```yaml
# tools/foo.yaml
name: foo-search
runs: isolate                 # isolate | host | service(mcp)
egress: [api.foo.com:443]     # opens exactly this in the broker allowlist
credential:
  secret: FOO_API_KEY         # a REFERENCE; value lives in the host secret store
  inject: header "Authorization: Bearer {}"   # attached at the proxy, never in the isolate
grants: "authenticated GET to api.foo.com as a read-only token"  # legibility
```

Principles:
- **Declarative, not spec-editing.** Manifest → compiler → OCI mounts + broker
  config (Agent Vault services + RPC caps). Undeclared = denied. Declaring
  `credential:` marks the destination terminate+inject (CA path); omitting it
  leaves the tunnel opaque, end-to-end TLS.
- **Secrets by reference.** The manifest names `FOO_API_KEY`; the value sits in a
  host-side store (`.env` / env / vault the broker reads). Never inline, never in
  git, never in the isolate.
- **Zero-config default.** A credential-less, egress-less tool just runs in the
  isolate with the standard mounts — no manifest fields needed (progressive
  disclosure, like the descriptor catalog).
- **One conformance flow.** `defender connect <tool>` (mirroring `/connect`)
  validates the manifest, checks the secret resolves, dry-runs the egress,
  registers the tool. MCP servers plug in the same way (`runs: service`).
- **Legibility as a feature.** `grants:` states the blast radius — "a possibly
  hijacked agent gets an authenticated channel to api.foo.com as a ro token" —
  which is both the disclosure and the nudge toward least-privilege creds.
- **Local escape hatch.** `DEFENDER_ALLOW_UNSANDBOXED=1` for playground iteration
  (no real secrets); explicit, loud, fail-closed in production.

Payoff: fs scope, network scope, and credentials are **one declarative layer**
(mount list + egress allowlist + secret refs), compiled from manifests,
default-deny, secrets-by-reference.

## The run.py lifecycle seam

The seam is `run.py:29-30` (venv re-exec) → after credential/env setup
(`run.py:77-100`) and before `asyncio.run(driver.run_investigation)`
(`run.py:153`):

1. **Startup (unconfined):** source creds into the broker (not the run env);
   materialize `run_dir`; render the per-run OCI spec (mounts + no-net) and the
   broker config (Agent Vault services + RPC caps) from the tool manifests; mint
   the per-run vault-scoped proxy token; open the broker socket.
2. **Spawn the isolate:** `runsc --network=none --host-uds=open run` the driver
   with the two binds + the socket mounted in (tmpfs `/tmp` ordered before the
   `run_dir` bind); env carries only the proxy pointer + CA path — no secrets.
3. **Broker serves** the proxy + RPC for the isolate's lifetime.
4. **Reap + scrub:** the isolate exits; **scrub `run_dir` (refuse
   symlinks/hardlinks, fail loud) before any host-side consumer opens it**;
   artifacts are already on the host, and run.py continues to cross-check
   tables / enqueue learning / visualize unchanged.

The learning-loop entrypoint (`learning/loop.py`) that re-enters the runtime wraps
the same way.

## Isolation-strength knob

The runtime is swappable OCI; nothing else in the design changes:

| Runtime | Wall | Density / host | Use |
|---|---|---|---|
| `runc` | shared kernel + namespaces | highest / any Linux | playground / dev (input not yet hostile) |
| **`runsc` (gVisor)** | userspace guest kernel | high / no KVM needed | **default** |
| Firecracker / Kata | separate real kernel (KVM) | lower / needs `/dev/kvm` | escalation when the threat model demands hardware-virt and KVM hosts are guaranteed |

One knob-specific asymmetry: the OCI `linux.seccomp` profile (e.g. denying
`socket(AF_INET)`) applies on `runc` but is ignored by runsc — there, the absent
network is the enforcement.

"Scale to many alerts → many isolates" is then a scheduler problem (k8s Job /
Nomad / warm pool — or OpenSandbox, §Build/buy); the per-alert lifecycle is
stateless.

## Rejected alternatives

- **Bubblewrap / rootless podman / gVisor-rootless** — need unprivileged **user
  namespaces**, denied in the container envs we run in (`unshare --user` → EPERM,
  observed). Not portable across our hosts.
- **Claude Code's sandboxing /
  [`sandbox-runtime`](https://github.com/anthropic-experimental/sandbox-runtime)
  (srt)** — evaluated per #540's note. Right *pattern* — a domain-allowlist host
  proxy bridged over unix sockets, whose loopback↔socket bridge we copy — but the
  wrong *primitive*: it's bubblewrap-based (the userns problem above), has no
  credential injection, and its integration targets Claude Code's Bash tool while
  our runtime is the in-process PydanticAI driver.
- **`docker run` against a host daemon** — needs a reachable daemon + socket +
  often `--privileged`; varies by env.
- **Mount creds read-only into the sandbox** — simplest, but puts live secrets in
  the untrusted process; a prompt-injected agent reads and exfils them through the
  very egress opened. Broker instead.
- **Landlock-only self-confinement** — good in-isolate *hardening* (keep it), but
  it's a shared-kernel LSM with no host-level network allowlisting; not the
  primary boundary once we can spawn an isolate.

## Open questions / phasing

- **Where does runsc get its privilege? — RESOLVED (#548, GO).** Default
  `runsc run` wants root; *rootless* runsc needs the same unprivileged userns
  that EPERM'd; inside the devcontainer an outer `--privileged` is typically
  required. **Observed 2026-07-09:** a `--privileged` container on the playground
  VPS runs `runsc release-20260706.0` (systrap, no KVM) with all four knobs —
  ro bind, rw bind, `--host-uds=open`, `--network=none` loopback netstack — exit
  0; the non-privileged devcontainer stays a no-go (both privilege doors shut).
  So the v1 spawner host is *privileged-container-on-VPS* (or root-on-host), with
  the privilege spent once by the trusted spawner and none reaching the guest.
  Evidence + caveats: `docs/decisions/runsc-spawner-host-go-no-go.md`. The design
  is now proven deployable, not just chosen.
- **Fail-closed on capability.** The startup check must *attempt* a runsc probe
  (not just detect the binary) and refuse to process untrusted input unsandboxed
  on failure — only `DEFENDER_ALLOW_UNSANDBOXED=1` opts out, loudly.
- **Agent Vault fitness spike (timeboxed).** Verify: per-run dynamic
  service/allowlist configuration; running host-side behind the UDS↔loopback
  bridge; streaming LLM responses through terminate+inject; mTLS injection.
  Fallbacks in §Build/buy; the architecture doesn't move.
- **Playground tool creds start empty — the LLM key doesn't.** v1 wires isolate +
  bridge + proxy + RPC; tool credential slots stay empty in playground, but the
  LLM key rides the terminate+inject path from day one, so the injection
  machinery is exercised long before production needs it.
- **LLM egress: proxy vs. invert.** (A) terminate+inject via the proxy — day-one
  viable now that the proxy is adopted; `driver.py` intact. (B) invert: run the
  loop host-side and make the isolate a thin tool-executor (cleanest split,
  bigger refactor). Start (A), keep (B) as the target. If (A) hits SDK/CA
  friction, the only fallback is the LLM key *inside* the isolate env — a loud,
  temporary, documented exception that forfeits the invariant for exactly that
  key.
- **gVisor syscall tax on gather.** Gather shells out heavily (`docker exec …
  curl`); those syscalls pay the Sentry tax. Moving adapter egress to the broker
  (mode 2) pulls them *out* of the isolate and largely sidesteps it — measure.
