# Runtime sandbox: gVisor isolate + host-side credential broker

> **⚠️ SUPERSEDED IN PART — read
> [`docs/decisions/runtime-isolation-executor-model.md`](../../docs/decisions/runtime-isolation-executor-model.md)
> first.** Following #571's brain/hands split to its conclusion removes the
> **entire broker** from v1: with the LLM, MCP, and adapter clients all host-side,
> nothing credentialed runs inside the isolate, so there is nothing to inject and
> no outbound channel to authenticate. The isolate is a credential-free,
> network-free executor of model-written bash over `run_dir`; credentialed work is
> a **typed tool call** dispatched host-side. Everything below about the
> credential-injecting proxy, the vault, session tokens, the capability-RPC, and
> the per-run egress allowlist is **retained as history, not as the plan**. What
> still holds: the gVisor isolate, the filesystem mount discipline,
> `--network=none`, the isolation-strength knob, and both honest limits.
>
> **⚠️ SECOND CORRECTION — the box wraps the bash lane, not the driver.** Every
> "spawn the isolate, run the driver inside it" below (see §The run.py lifecycle
> seam) predates #571 moving the brain host-side and is **wrong**. Once the driver
> is the trusted brain and #611 has taken the adapters off the bash lane, the only
> untrusted code execution left in the system is **model-written bash** — so that
> is what goes in the box. The driver never enters it. This makes #540 materially
> smaller than this document implies: a per-run box, two binds, `--network=none`,
> and an exec per bash call. It also removes the reason to invent a credential
> plane: the box is safe because it holds nothing, not because the driver was
> disarmed first. Risk register: [`threat-model.md`](../../docs/decisions/threat-model.md).

**Status:** design — not yet implemented. **Decision:** run each defender
investigation inside a per-alert **gVisor (runsc) isolate** whose only route
off-box is a **host-side broker** that owns every credential and every egress
destination. Filesystem scope is the isolate's mount list; network scope is the
broker's egress allowlist; credentials are attached *at the broker boundary* and
never cross into the isolate. The broker's proxy half is **adopted, not built**
(a credential-injecting proxy + vault — Infisical Agent Vault is the leading
candidate; see §Build/buy); the capability-RPC half stays ours. The in-process
`runtime/permission/` gate demotes to defense-in-depth / UX. **The driver/brain
runs host-side and trusted; the isolate is a thin tool-executor (hands)** — see
§Prior art & the brain/hands/session decision for that split and the
origination-not-MITM stance it implies.

**Forcing issue:** **#540** (OS-sandbox the run as the real read/write boundary).
Builds on **#535** (the interim anchored read-confinement guard, which this
replaces as the *boundary* and leaves as belt-and-suspenders). Related:
`agent-definition-single-source.md` already names this as the eventual boundary
("The real read/write boundary is OS sandboxing (#540); this gate is
defense-in-depth"), and `tests/test_read_confine_bash.py:494-499` defers the
pre-existing-symlink residual to it.

## Prior art & the brain/hands/session decision

Anthropic shipped this exact problem three times in 2025–26. The design tracks
their conclusions rather than re-deriving them.

- **[Making Claude Code more secure with sandboxing](https://www.anthropic.com/engineering/claude-code-sandboxing)**
  — an OS-level isolate (bubblewrap/seatbelt) with the network removed and forced
  through a **unix-socket → host proxy that allowlists by hostname and does *not*
  terminate TLS by default**. Sensitive creds are "never inside the sandbox." The
  git→GitHub path is a credential-injecting proxy: the sandbox git client
  authenticates with a **scoped placeholder credential**, and the proxy *verifies
  the request* (only push to the configured branch) *before* attaching the real
  token — the agent never handles it. This is the socat loopback↔UDS bridge we
  copy, plus the inject-**with-verification** pattern (mitigates honest-limit-1).
- **[Managed Agents](https://www.anthropic.com/engineering/managed-agents)** — the
  architecture we adopt. It **decouples "the brain (Claude and its harness) from
  the hands (sandboxes and tools) and the session,"** the harness calling
  sandboxes over a generic `execute(name, input) → string`. The threat is ours
  verbatim: "a prompt injection only had to convince Claude to read its own
  environment… the structural fix ensures tokens never reach the sandbox where
  Claude's code executes." MCP creds are brokered exactly as we intend: "Claude
  calls MCP tools via a dedicated proxy; this proxy takes in a token associated
  with the session… fetch[es] the corresponding credentials from the vault before
  invoking external services. The harness remains unaware of all credentials."
- **[Claude Code Auto Mode](https://www.anthropic.com/engineering/claude-code-auto-mode)**
  — the *other* layer. Confidentiality/egress isolation does nothing for
  **capability misuse** (a hijacked agent invoking a legitimate-but-dangerous
  tool), which MCP write-tools make urgent. Their answer is behavioural, not more
  sandbox: an input-side prompt-injection probe on tool outputs, a
  **reasoning-blind transcript classifier** that gates each action as a substitute
  approver, tiered permissions, and explicit credential-exploration blocks. Note
  their honest caveat — "sandboxing is safe but high-maintenance: each new
  capability needs configuring, and anything requiring network or host access
  breaks isolation."

**Decisions taken from this:**

1. **Adopt the brain/hands/session split (was "option B / invert").** The
   PydanticAI driver + LLM client run **host-side and trusted**; the isolate is a
   thin **tool-executor (hands)** the host-side loop drives over the
   capability-RPC. Tractable for us because our tool set is small and fixed — the
   general Claude Code harness kept the agent *inside* the sandbox precisely
   because its tool surface is open-ended; ours isn't, so the invert cost we pay
   is one they couldn't. Consequence: the **LLM key never enters the isolate and
   needs no injection** — it lives with the trusted host-side brain. This retires
   the design's single highest-risk mechanism (streaming TLS terminate+inject)
   for the LLM path outright.
2. **Injection is origination-shaped, not MITM.** Because we configure every
   endpoint we care about — the LLM SDK `base_url` (verified: pydantic-ai
   `AnthropicProvider`/`OpenAIProvider` both take `base_url`, and the Anthropic SDK
   honours `ANTHROPIC_BASE_URL`), MCP server URLs, and our own adapters — a
   credentialed tool points at the broker and the broker **originates** the real
   upstream TLS with the credential attached. No per-SNI CA minting, no CA baked
   into the rootfs, for anything we can repoint. Transparent terminate+inject (a
   minted CA) is the **fallback for an un-repointable third-party HTTP client**
   only, not the primary path.
3. **Two boundaries, not one.** The isolate + broker (this doc) is the
   **confidentiality/egress** boundary. **Capability misuse** (honest limit 1) is
   a *separate* layer — scoped/read-only creds now, and an auto-mode-style
   authorization/approval gate when write-capable MCP servers arrive (tracked as
   its own issue; this doc's boundary stays confidentiality/egress).

The body below still describes the isolate/broker/fs/net mechanics, which the
split does not change. Where it says "the driver runs in the isolate" or frames
the LLM as a terminate+inject destination, read it through decisions 1–2 (a fuller
mechanics pass — §The shape diagram, §Credential injection modes, §The run.py
lifecycle seam — is a follow-up, flagged inline).

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
       │     • egress proxy (ADOPT: credential-injecting proxy + vault)  session-token→vault→inject,
       │                                             origination-primary (MITM only as fallback), default-deny allowlist
       │     • capability-RPC (ours)                brokered subprocesses: docker-exec adapters, local CLIs
       │     • brokered services                    credentialed MCP / DB servers (the enterprise tool surface)
       │     • per-run egress allowlist (default-deny)
       │  (the host-side driver/brain + LLM client also live here, trusted — decision 1)
       └─ ISOLATE (gVisor runsc, untrusted): the tool-executor (hands) — runs the
             model-directed TOOL calls; the driver/brain is HOST-SIDE (§Prior art)
             • fs: rootfs ro (incl. the broker CA cert, only if MITM fallback used),
               defender_dir ro, run_dir rw, /tmp tmpfs, else absent
             • net: --network=none → netstack loopback only; a loopback↔UDS
               bridge to the broker socket is the sole off-box path
             • env: secret-free (extends run_common.py:99-101 key-strip to all
               secrets; the LLM key stays with the host-side brain, not here)
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

**Updated 2026-07-17 — the threat class, the control, and the owner.** This residual
is **class 2, not class 1**. Through the sanctioned bash lane a symlink is
*unexpressible* — the grant list has no `ln`, and `write_file` / the `query` tool
create regular files, never call `symlink()` — so a merely-injected model cannot
plant one; it takes an in-box RCE (a jq/parser bug, an executor escape) to reach
`symlink()`. Creation-prevention is therefore not the boundary: the grant list
already covers class 1, and **runsc ignores the OCI seccomp profile**, so there is
no structural `symlink`-deny on the default runtime. The control is **reader-side**,
and the two identities are the point — the box *writes* the string (confined; its
own kernel resolves the target to ENOENT), a trusted host consumer *derefs* it with
the authority to read the secret. The scrub above is the cheap form (`lstat` per
entry, run *after* teardown when the tree is frozen → TOCTOU-free); the structural
form opens every artifact under `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)`.
**Ownership:** #547 (the scrub) was closed NOT_PLANNED, so this is currently
unowned — **#540 re-owns it**. Confining the host-side consumers (renderer,
learning loop) — which need only `run_dir` and hold no key — both closes this and
contains a class-2 RCE in the renderer, and is in scope for #540; **driver
isolation is a separate, larger piece deferred to platformization and gated on
#550** (a box can protect neither the key nor the network the driver holds by
construction). Note in-process read/write gating does *not* survive an RCE (the
exploit calls `open()` directly), so "box the reads/writes" only means anything at
the OS level.

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

**Superseded for the LLM (see §Prior art, decisions 1–2).** Under the
brain/hands/session split the LLM client runs host-side, so the LLM is **not** a
terminate+inject destination and needs no injection at all. Injection now serves
**tools** — MCP servers and credentialed adapters running in the isolate — and is
**origination-shaped** wherever the endpoint is ours to set (MCP URLs, our own
adapters, any SDK exposing `base_url`), which is the common case; terminate+inject
with a minted CA remains only for an un-repointable third-party client. The proxy
is still adopted (§Build/buy) — its first real consumer is a credentialed tool,
not the LLM.

| Mode | For | How the secret is attached |
|---|---|---|
| **Forward-proxy injection** | HTTP CLIs/libs, the LLM API, MCP-over-HTTP | tool runs in the isolate with `HTTPS_PROXY` at the loopback bridge; makes its normal call; broker tunnels or terminates+injects per the TLS split and forwards only to allowlisted hosts — tool never sees the key |
| **Brokered subprocess** | non-HTTP tools (today's `docker exec … curl` adapters, a CLI needing a keyfile) | tool runs host-side in the broker with the secret in its env; isolate invokes it by name over the RPC and gets back only the result |
| **Brokered service** | credentialed MCP / DB servers | broker launches it host-side with its secret; isolate speaks its protocol through the socket |

This generalizes the one pattern that already exists: adapters run host-side via
`_capture_adapter` (`tools_gather.py:204`, re-exported through `tools.py`) with
keys stripped from the subprocess env (`run_common.py:99-101` — `run_env` pops
`providers.api_key_vars()`). The broker is where that logic moves.

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
the `command_shape` classifiers / `ADAPTER_RE` that already describe adapter
invocations. Execution is `shell=False`, with a minimal env holding only that
cap's secret; out-of-shape argv is deny+log, same as an unlisted cap. (Running
the brokered subprocess under its own light confinement is a worthwhile
follow-on.)

**(c) Brokered-service passthrough.** For MCP/DB: the broker proxies the service
protocol (MCP framing / SQL) over the same socket to the host-side server it
launched with creds.

Everything on this socket is default-deny: an unlisted cap or an unlisted egress
host is refused and logged. The socket is the isolate's entire off-box surface.

## Build/buy — adopt a credential-injecting proxy + vault, write the RPC

"Sandbox the agent, broker its credentials at the egress boundary" is now a
product category — Cloudflare Sandboxes, Azure's SRE identity sidecar, and
Anthropic's own **Managed Agents** (§Prior art) all ship it. We buy the generic
proxy+vault and keep the small domain-specific parts.

**What we need from the proxy** (per the brain/hands/session decision): the
*hands* hold a **session-scoped token**, never a real secret; the proxy exchanges
it at a vault for the destination's credential and attaches it — **by
origination** (the tool points its endpoint at the broker; the broker makes the
real upstream connection), falling back to terminate+inject with a minted CA only
for an un-repointable client. Per-run destination allowlist, default-deny. This is
exactly the Managed-Agents MCP proxy shape (`session token → vault → inject`).

- **Leading candidate — [Infisical Agent Vault](https://github.com/Infisical/agent-vault)**
  (MIT + `ee/`): a credential-injecting proxy + vault with session-scoped tokens
  and per-destination inject rules — the `session-token→vault→inject` pattern out
  of the box, and it already streams (HTTP/1.1 `flushingWriter`, HTTP/2 pinned
  off) and mints per-SNI CAs if we ever need MITM. Carry honestly: it's a research
  preview on a ~2-day release cadence (v0.39 as of 2026-06); **fail-open by
  default** (`unmatched_host_policy=deny` is the load-bearing line to set); scoping
  is per-**vault**, not per-run (per-run allowlists mean vault lifecycle, not just
  a session); **no mTLS-to-upstream** in-tree; and it listens on TCP, so it sits
  host-side behind the UDS↔loopback bridge. We depend on it *operationally* (a
  process + config), not as a linked library, so pin a digest and the churn
  blast-radius is its config schema + management API, not our code.
- **Origination-native alternative — Envoy `credential_injector` filter + TLS
  origination.** A shipping, versioned, CNCF-graduated filter that injects a
  Bearer/Basic credential from a `generic_secret` and **fails closed by default**
  (`allow_request_without_credential=false → 401`). Injection-via-origination is
  Envoy's *well-trodden* path (unlike Envoy-as-forward-MITM), so its maturity
  transfers to our config. Cost: an xDS/protobuf config surface + a control plane
  to push per-run allowlists is heavier than scripting Agent Vault's management API
  for a single-host v1. Reasonable to start on Agent Vault and hold Envoy as the
  harden-for-production swap; the architecture doesn't move, only the binary.
- **Secret store:** the vault behind the proxy can be Agent Vault's own store,
  Infisical core, or (v1) the existing `.env` path — a *store*, not the egress
  proxy; don't conflate them. HashiCorp Vault is the mature option if enterprise
  demands it.
- **mitmproxy shim** only if a real destination pins both its endpoint *and* its
  cert, forcing true MITM. Not expected — origination covers the LLM, MCP, and our
  own adapters.
- **Evaluate at the many-alerts phase:
  [OpenSandbox](https://github.com/alibaba/OpenSandbox)** (Apache-2.0) — a
  self-hostable sandbox *platform* (gVisor/Kata/Firecracker, per-sandbox egress
  controls, a credential vault, Python SDK). Collapses the scheduler question but
  restructures the run lifecycle around its server + exec API and likely costs the
  run_dir-bind-is-the-exit property. Wrong trade for single-host v1; the candidate
  when "many isolates" becomes real.

**Still ours (small, domain-specific):** the per-run OCI spec generation; the
capability-RPC + its argv validation + queries-table capture; the manifest
compiler (now → proxy service config + OCI mounts + RPC caps + MCP registrations);
the reap-time scrub.

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

> **Superseded — see the second correction in the banner.** The numbered lifecycle
> below puts the *driver* in the box and spawns a broker beside it. Both are dead:
> there is no broker, and the driver is the trusted brain. Kept as history because
> the *ordering* (materialize `run_dir` → build the box → reap → scrub) survives.
> The current lifecycle is the one under "What it is now".

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

### What it is now

Two things per run, and the driver is not one of the boxed ones. `run.py` is
already one process per run (`main(sys.argv[1:])` → `sys.exit`), so the brain is
ephemeral by construction — there is no long-lived pooled driver to contain, and
nothing is shared across runs.

1. **Startup (host, trusted):** materialize `run_dir`; build the per-run box.
2. **The box lives for the run:** `run_dir` rw bind, `defender_dir` ro bind, `/tmp`
   tmpfs, `--network=none`, no secrets in env, nothing else mounted. **No socket is
   mounted inward** — the channel is inbound-only.
3. **The driver stays host-side** with the keys and the network, running the LLM
   loop and dispatching `query(...)` in-process (#611). Its two moves remain
   dispatch-a-typed-tool and ship-bash-inward; it **execs into the box per bash
   call**, so cwd and `/tmp` persist across calls and the ~0.1 s startup amortizes
   once per run rather than per call.
4. **Reap + scrub:** unchanged from above.

The driver keeping the provider key is deliberate, not an oversight — #550 removes
it by `base_url` origination and is **independent of this issue**, not a
prerequisite. What that key buys an attacker who lands RCE *in the driver* is
class 2 in [`threat-model.md`](../../docs/decisions/threat-model.md); its control is
dependency hygiene, not a box.

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

**v1 is not gated on runsc (resolved 2026-07-17).** #540's boundary claim —
classes 1 and 8 in [`threat-model.md`](../../docs/decisions/threat-model.md),
*which paths are visible* and *no direct egress* — is delivered by the mount list +
`--network=none`, and **`runc` provides both on any Docker host**. runsc's *added*
value is exactly class 2: a parser-bug RCE *inside the box* (jq, coreutils,
`defender-sql`'s python) reaching the host kernel — a modest surface, since #611
left only local-computation bash in the box. So the runtime is genuinely
**runc-capable / runsc-default / microVM-optional**, and the deployment does not
have to wait on a privileged runsc host to make the read/write boundary real: ship
on the runtime the host supports, default to runsc where the daemon path (proven
2026-07-17) is available, and the upgrade moves nothing else. The earlier "blocked
on levering the VPS back up" framing conflated the boundary (runc-sufficient) with
the class-2 hardening (runsc).

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

- **Where does runsc get its privilege? — PARTLY resolved (#548, GO on one path).**
  Default `runsc run` wants root; *rootless* runsc needs the same unprivileged
  userns that EPERM'd; inside the devcontainer an outer `--privileged` is typically
  required. **Observed 2026-07-09:** a `--privileged` container on the playground
  VPS runs `runsc release-20260706.0` (systrap, no KVM) with all four knobs —
  ro bind, rw bind, `--host-uds=open`, `--network=none` loopback netstack — exit
  0; the non-privileged devcontainer stays a no-go (both privilege doors shut).
  Evidence: `docs/decisions/runsc-spawner-host-go-no-go.md`. **runsc is deployable.**
- **Which spawner path? — RESOLVED (2026-07-17): the daemon path, and it is a
  security fork, not a packaging detail.** "*privileged-container-on-VPS* **or**
  root-on-host" are not interchangeable, and #548 only proved the first. Both are
  now tested:
  - **Nested (#548):** `runsc run` *inside* a `--privileged` container. The Sentry
    then lives in a container with host devices, `CAP_SYS_ADMIN` in the bounding
    set, and largely unmasked `/proc`. Also needed `--ignore-cgroups`. **Do not
    build on this.**
  - **Daemon (the one to build):** `docker run --runtime=runsc` against the host
    daemon. **Observed working** — all four knobs, no privileged container, and
    `--ignore-cgroups` unnecessary (it was a nested artifact all along).

  The distinction matters because **gVisor's security model has two layers**, and
  this document only ever described one. Layer one is the Sentry servicing guest
  syscalls. Layer two is that the *Sentry itself* is confined by a host seccomp-bpf
  filter plus namespaces, so that a Sentry compromise is still not host access —
  that layer is what makes "the Sentry has bugs" survivable rather than fatal.
  On the daemon path layer two is now **observed, not assumed**: the Sentry is
  parented by `containerd-shim` under PID 1 with `Seccomp: 2`, `NoNewPrivs: 1`, and
  `CapEff` = six caps with **no `CAP_SYS_ADMIN`**. Evidence:
  `docs/decisions/runsc-spawner-host-go-no-go.md`.

  Also **strike "the privilege is spent once"** — privilege is not spent. On the
  nested path it persists for the container's lifetime with the Sentry inside it.
  It is the *daemon* path that makes the "privilege stays on the trusted side"
  claim true: dockerd spends it to build the box, and the Sentry facing
  model-written bash gets six caps and a seccomp filter.
- **Does the real workload survive the box? — PARTLY TESTED (2026-07-17), no longer
  the biggest unknown.** The rootfs is pinned to `python:3.11-slim`, so the
  binary-compat surface was run against that image with the box's mount discipline:
  - **The flag-grammar alignment is clean.** `python:3.11-slim` ships GNU grep 3.11
    + coreutils 9.7 — the exact binaries `gnu_flags.py` was pinned against — so the
    "silent drift" risk does *not* bite for this image. It bites only if the rootfs
    is swapped to busybox/alpine, which re-pinning `gnu_flags` catches.
  - **`jq` is absent from the base image and must be baked into the rootfs at build
    time** (the box is `--network=none`; it cannot `apt` at runtime — confirmed).
    The `.venv` must be on `PATH` for `defender-sql` / the `defender-*` shims. Both
    are build-time requirements whose failures are loud (`command not found`).
  - **`__pycache__` under a read-only `defender_dir` is a non-issue** — CPython
    imports fine and silently skips the `.pyc` write on EROFS.
  - **The guest runs as uid 0 with `dac_override`**, so inside the box permission
    bits and uid confine *nothing* — the mount list is the only boundary; no in-box
    logic may lean on chmod/uid.

  Still wanting the real box (not blocking): `defender-sql` end-to-end from a
  ro-bound `.venv`.
- **Fail-closed on capability.** The startup check must *attempt* a runsc probe
  (not just detect the binary) and refuse to process untrusted input unsandboxed
  on failure — only `DEFENDER_ALLOW_UNSANDBOXED=1` opts out, loudly.
- **LLM egress: proxy vs. invert — RESOLVED (invert / brain host-side).** Per the
  brain/hands/session decision (§Prior art), the driver + LLM client run host-side
  and trusted; the LLM key never enters the isolate, so there is **no LLM
  injection path** to build or de-risk. This retires the old "start (A)
  terminate+inject, keep (B) as target" plan and its fallback (LLM key inside the
  isolate). Phase intent shifts: #550 ("LLM API through the broker proxy") is
  reframed from *inject the LLM key at the proxy* to *stand up the host-side driver
  so the key leaves the isolate by never entering it* — the proxy's first real
  consumer is a credentialed **tool/MCP**, not the LLM.
- **Proxy fitness spike (#549) — rescoped.** The old spike centred on streaming
  TLS terminate+inject, which the invert decision removes from the LLM path and
  origination removes from repointable tools. What actually needs verifying against
  the candidate proxy (Agent Vault): (a) **fail-closed** — a non-allowlisted host
  is refused (`unmatched_host_policy=deny`); (b) **scoping granularity** — is the
  allowlist per-vault or per-run, and does per-run mean a vault lifecycle per run;
  (c) **`session-token→vault→inject` by origination** for one credentialed
  tool/MCP, driven from `run.py` via the management API (the SDK is TypeScript; we
  script the API). Streaming and CA-minting are *confirm-upstream-claim*, not
  discover-if-possible; mTLS-to-upstream is **absent in-tree** — decide whether any
  destination needs it before it can block adoption. Fallbacks in §Build/buy.
- **First injection consumer is a tool, not the LLM.** In playground the tool
  credential slots start empty, so the injection machinery is first exercised by
  the earliest credentialed tool or MCP server we wire — not, as previously
  planned, by the LLM on day one. Wire one read-only MCP/tool early to keep the
  `session-token→vault→inject` path live before production needs it.
- **Capability misuse is a second boundary (new issue, to file).** The
  isolate/broker gives *confidentiality + egress*; it does nothing for a hijacked
  agent invoking a legitimate-but-dangerous **MCP write-tool** (honest limit 1),
  which enterprise MCP makes urgent. The mitigation is behavioural, per Auto Mode
  (§Prior art): least-privilege / read-only creds + a tight allowlist now, and an
  injection-probe-on-tool-output + reasoning-blind transcript approver (or
  human-in-loop on sensitive actions) when write-capable servers land. Tracked
  separately — this doc's boundary stays confidentiality/egress.
- **gVisor syscall tax.** Gather shells out heavily (`docker exec … curl`); those
  syscalls pay the Sentry tax. Two relaxations under this design: brokered-
  subprocess adapters (mode 2) run host-side and pull their syscalls *out* of the
  isolate, and under the invert decision the LLM streaming runs host-side too — so
  the isolate's hot path is the tool-executor's file/bash ops. Measure the
  residual.
