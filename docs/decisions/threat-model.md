---
title: Threat model — an app that evals attacker input and trusts the client
status: accepted
groups: defender, runtime, security, threat-model
---

**Decision.** This is the risk register the isolation work argues *from*. It exists
because the sandbox rollout ([`runtime-isolation-executor-model.md`](runtime-isolation-executor-model.md),
[`runtime-sandbox-design.md`](../../defender/docs/runtime-sandbox-design.md)) was
scoped mechanism-first — gVisor vs. microVM, broker vs. no broker — without a
written statement of what we are defending, against whom, and which classes the
mechanism does not touch. Every honest limit in those docs is a line item here
instead of a footnote there.

## Strip the mystique

The defender is a standard application that does three unremarkable things:

1. It accepts untrusted input. The alert is attacker-triggered, and adapter output
   carries attacker-chosen fields — **anyone who can write a log line the SIEM
   ingests can write into the model's context.**
2. It passes that input to an interpreter it cannot escape or parameterize (the
   model), and **executes the interpreter's output as shell**.
3. It **uses the interpreter's output as the security decision** (the disposition).

In ordinary appsec vocabulary that is `eval()` on user input, a confused deputy
with ambient authority, and *trusting the client*. Nothing here needs
LLM-specific theory, and reasoning about it in LLM-specific terms is what let the
no-exploit-required classes below get filed as curiosities.

## The axiom

**Assume the model is attacker-controlled: always, 100%, by default.**

Not a probability — an assumption. Injection has no parameterized-query
equivalent; there is no escaping that makes the interpreter safe. Any design that
holds only while the model behaves is not a design.

Two consequences, and they are the whole point of writing this down:

- **"Prompt injection" and "the LLM goes rogue" are the same event.** Never model
  them separately.
- **The security question is never "will the model be subverted."** It is *"what is
  the model authorized to do, and what is reachable from there?"* — authorization
  and blast radius, which we already know how to reason about.

The model is our user. Our user is malicious. Everything the model reaches is a
privilege boundary; everything that parses text on the way to it is attack surface.

### The corollary that keeps getting missed

`runtime-isolation-executor-model.md` justifies a credential-holding driver that
parses attacker text like this: *"its response to influence is enumerable."* That
argument assumes **influence is the only threat**. An RCE does not *influence* the
action space — it *deletes* it. An RCE'd driver does not consult the tool table; it
reads the env, builds its own argv, opens its own socket. Enumerability is a
property of code still running as written.

So the real claim is: *the driver's action space is enumerable **so long as every
parser between attacker text and the tool table is sound.*** That is a
dependency-hygiene claim wearing a structural claim's clothes. Structural claims
survive a CVE; hygiene claims do not. Class 2 below is that gap, and it is nobody's.

## Assets

| Asset | Why it matters |
|---|---|
| LLM provider key | Long-lived, high value, usable from anywhere, spends money |
| Data-source credentials | Read access to the customer's security telemetry |
| Host / spawner | Privileged; reaches everything above |
| Disposition integrity | The product's actual output |
| Corpus + lessons | Written back by the learning loop; poisoning reaches *future* runs |
| Investigation data | Customer telemetry; cross-run and eventually cross-tenant |

## Where attacker text enters

`alert.json`; adapter output (any field an attacker can influence upstream — log
lines, filenames, user agents, process cmdlines); every model output derived from
those; and the corpus, via lessons curated from previous runs.

## The classes

The load-bearing column is **"exploit needed?"** Under the axiom, a class needing
no exploit is not *likely* — it is **certain**.

| # | Class | Appsec name | Exploit? | Owner |
|---|---|---|---|---|
| 1 | Model writes bash in the isolate | `eval()` on user input | No — *by design* | #540 |
| 2 | Parser bug → RCE in the driver | Deserialization / memory safety | **Yes** | unowned |
| 3 | Injected model calls `query()` with attacker's ES\|QL | Broken authorization | **No** | open |
| 4 | Injected model reports the wrong disposition | Trusting the client | **No** | human review |
| 5 | Poisoned report → curator → lesson PR → future runs | Stored injection | **No** | open |
| 6 | Telemetry leaves through a sanctioned path | Exfiltration | No | partly #540 |
| 7 | Token / cost burn | Resource exhaustion | No | accounted only |
| 8 | Run A reaches run B's data | Multi-tenancy | Varies | box-per-run |

**Class 1 — the isolate's whole job.** The model writes bash and the attacker owns
the model, so the attacker has RCE in the isolate. That is not a bug; it is the
workload. Gather's value is open-ended exploration of raw payloads, so the answer
is containment, not amputation: mounts, `--network=none`, no credentials.

**Class 2 — the unowned one.** Attacker text reaches pydantic-ai, pydantic-core,
httpx and the JSON path. Our own code is clean of the classic sins (no unsafe
`yaml.load`, no pickle, no template engine over attacker text, no `eval`/`exec` on
it), so the exposure is the transitive dependency tree. Note what a box does and
does not do here: **a box around the brain reduces blast radius, not probability.**
The controls that move probability are boring — pin and audit the tree, keep it
minimal, watch advisories on pydantic-core and the HTTP stack. And no box protects
the provider key, which the brain holds by construction; only taking the key out of
the driver (#550) changes the *class* of the loss, from "the org's key, valid
indefinitely" to "one investigation plus a short-lived token."

**Three loci, three treatments (added 2026-07-17).** Class 2 is not one place.
(1) *In the driver* — the big surface (pydantic-ai/core, httpx); real defense is
OS-confining the driver, but it protects neither the key nor the network the driver
holds by construction, so it is deferred to **platformization** and gated on #550.
(2) *In the box* — a small surface (jq, coreutils, `defender-sql`'s python); this is
the one class-2 locus a box actually hardens (probability, not just blast radius),
and it is what runsc's userspace kernel is *for*. (3) *In the host-side consumers* —
the renderer and learning loop parse attacker bytes (`report.md`, `gather_raw`) and
need only `run_dir`; **OS-confining them is cheap and in scope for #540**, and does
double duty: it contains a renderer RCE *and* closes the planted-symlink read. That
read is a class-2 amplification of the `run_dir` artifact exit — sanctioned bash
cannot create a symlink (no `ln`; the write surfaces make regular files), so
following one is reachable only after an in-box RCE, and the fix is a reader-side
`RESOLVE_NO_SYMLINKS` / reap scrub, **not** creation-prevention (which runsc cannot
enforce anyway). **In-process read/write gating does not survive an RCE** — the
exploit calls `open()` directly — so "box the reads/writes" only means anything at
the OS level.

**Class 3 — capability misuse (honest limit).** The credential cannot be *stolen*;
the capability can still be *used*. A hijacked model calls `query(...)` with
attacker-chosen ES|QL and no exploit is required. No sandbox touches this. The only
controls are authorization-shaped: read-only, least-privilege, per-system and
eventually per-tenant credentials, and an approval layer. **This becomes urgent the
moment a write-capable tool lands.**

**Class 4 — trusting the client.** There is **no ground truth to compare an
investigation against**, so this cannot be detected by checking the answer. Two
things bound it:

- **The system is read-only.** A wrong disposition does not *act*; it *advises*. The
  human analyst is the decision-maker and therefore the verification layer.
- **That layer only works if the run HTML is actionable.** The analyst must be able
  to read the disposition and report, walk the lead list, and confirm the model's
  reasoning. Legibility is a *security control here*, not a UX nicety — it is the
  only thing standing between an injected model and a believed verdict.

Residual risk is **analyst over-trust** (automation bias): the control degrades
silently as humans skim. It escalates from "misleads a human" to "defeats the
product" the moment the system becomes write-capable or a human stops reading.
**Open idea:** baseline-deviation detection over the investigation itself — never
properly tested, and worth revisiting specifically as an *injection signal* rather
than as a quality metric.

**Class 5 — the laundering chain (honest limit).** A poisoned `report.md` flows to
the learning loop's curators and out through a lesson PR, reaching future sessions
at higher privilege. This is stored injection: the payload persists and fires later,
in a different context. Controls stay behavioural — loop-as-sole-committer,
per-batch worktrees, the forward-check regression gate, human PR review.

**Class 6 — egress.** Sanctioned egress is **the connected tools, nothing else**.
`--network=none` on the isolate closes *direct dial-out*, which is real and worth
having. It does not close egress, and the design's "confidentiality and egress
become structural" is too strong. The precise claim is **unauthorized *direct*
egress becomes structural.** Data still leaves through paths we sanctioned, carrying
bytes an attacker-controlled model chose:

- Everything the model reads goes to the provider by construction; the context *is*
  a channel.
- `query()` params are model-chosen bytes on a sanctioned outbound path.
- The disposition changes what the SOC does, and the attacker is watching.
- **The report is the honest limitation.** It flows to analysts and into lesson PRs,
  and today it is free-form: `report.md` is written through the generic `write_file`
  tool (`runtime/tools.py`), so there is no structure to constrain it. **Validating
  the report's output structure is the control, and it does not exist yet** — a
  schema-constrained report is what stops it being an arbitrary carrier.

**Class 7 — accounted, not enforced.** A per-run budget exists (tool calls,
subagent spawns, wall clock) but **it warns rather than blocks**: the driver's
`after_tool_execute` hook prints `check_budgets` output to stderr and returns the
result unchanged. There is one enforcement path, not two — `hooks/budget_enforcer.py`
is the budget *logic* the driver imports, and its `claude -p` PostToolUse entrypoint
was deleted with that retired runtime. `circuit_breaker` *does* abort, including a
run-wide kill switch, but it is scoped to environment health (exit-2
connectivity/auth failures), not to a model spending money. So against the axiom
this is observability. Blocking posture is designed in #631.

**Class 8 — isolation between runs.** The control is **a box per run**. #291
(per-agent run dir) is *runtime cleanliness*, not the boundary — do not let it stand
in for one. The differentials a box-per-run protects are not static secrets (every
brain holds the same provider key) but **aggregate** — a shared box holds N
concurrent investigations, so one compromise reads every alert and tampers with
every verdict — and **time**: a long-lived shared box is a persistent foothold over
all future runs. Note that "separate processes on one box" is not isolation once
class 2 is live: same-uid processes ptrace each other and read `/proc/<pid>/mem`.

## The two promises

These are different products. We should say out loud which one we are making.

**"An attacker cannot use our defender to break into your SOC."** Achievable, and
what the roadmap is actually building: classes 1, 2, 6, 8 — the isolate, the
forwarder, dependency hygiene, per-tenant credentials. Losing the provider key or
the SIEM credentials is a genuine incident and this work prevents it.

**"An attacker cannot fool our defender."** **Not achievable** with an injectable
model in the loop, and no amount of boxing moves it, because we are trusting the
client. Classes 3, 4 and 5 are all this promise. Their only controls are redundancy
and review: authorization instead of ambient grants, a legible run HTML that lets a
human confirm the reasoning, and human review of anything that persists.

The failure mode this document exists to prevent is banking the second promise
while funding the first.

## Open questions

- **Class 2 has no owner.** Who audits the dependency tree, and on what cadence?
- **Report structure (class 6).** What schema constrains `report.md` without
  amputating the analyst value of prose?
- **Baseline-deviation detection (class 4).** Revisit as an injection signal; needs
  a testable formulation before it is worth building.
- **Budget enforcement (class 7).** Flip to blocking, or accept accounting and say
  so here?
- **Class 3 authorization.** What does an approval layer look like before a
  write-capable tool lands, not after?
