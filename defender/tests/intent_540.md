# #540 — Box the bash lane: typed intent + design

**Revision 2 (2026-07-18).** Incorporates the maintainer's containment-fork resolution and 24 executed probes (Docker Engine 29.5.3, `python:3.11-slim`, runc; plus a privileged sibling container running runsc `release-20260714.0`) together with a code-grounding pass against HEAD. Several statements in revision 1 were **refuted** — they are kept in the ledger with their refutation rather than deleted, because two of them are false *in the design docs at HEAD* and need correcting there as part of this work.

**Scope frozen by the human (2026-07-18).** IN: (A) the per-run box, (B) the exec seam, (C) the reap-time `run_dir` scrub (the re-owned #547). OUT: host-side consumer confinement, driver isolation, the broker/vault/capability-RPC, #291, #550. See §Non-obligations — the exclusions are recorded, not deleted.

**Source precedence.** Executed probes (2026-07-18) beat everything. Then the 2026-07-17 issue comment ([#540 comment 5006561145](https://github.com/beetroot-salad/cyber-response-agent/issues/540#issuecomment-5006561145), cited as `issue-comment §n`). Then the design docs. Conflicts are called out inline. Doc shorthands: `RSD` = `defender/docs/runtime-sandbox-design.md`, `RIEM` = `docs/decisions/runtime-isolation-executor-model.md`, `TM` = `docs/decisions/threat-model.md`, `RSG` = `docs/decisions/runsc-spawner-host-go-no-go.md`.

---

## Intent

### Obligations

**O1. [security]** Code running on the bash lane can read no host path other than `run_dir` and `defender_dir`, and can write no host path other than `run_dir` — every other path is *absent*, not denied. — `issue-body §Goal`; `RSD §Filesystem isolation`; `RIEM L66-71`.

**O2. [security]** Code running on the bash lane can open no outbound connection to any destination whatsoever — there is no permitted network peer, not a restricted one. — `RIEM invariant 2` ("The isolate has no outbound socket. Not a locked-down one — *none*."); `issue-body` header ¶3; `RSD §Network isolation ¶1`. **Conflict resolved:** `RSD §Network isolation ¶2` still mandates a bind-mounted broker UDS as "the only off-box path". That is dead — no socket is mounted inward. `RIEM invariant 2` and `issue-comment §3` govern.

**O3. [security]** No credential, API key, or other secret is readable from inside the box — neither from its environment nor from any mounted path. — `RIEM L7-12`; `RSD §The invariant: secrets never enter the isolate`; `issue-comment §3` ("the box needs none and holds none").

**O4. [security]** O1–O3 hold *regardless of which command string the model emits*, and hold even if the in-process permission gate is wrong, bypassed, or absent — the enforcement is the mount list and the network mode, not a matcher. — `issue-body §Problem`; `RSD §Why the in-process gate isn't the boundary`; `TM class 1`.

**O5. [security]** A write to any path under `defender_dir` from inside the box fails (EROFS) — a hijacked agent cannot poison its own corpus, skills, or lessons directly. — `RSD §Filesystem isolation`; `RSG` evidence row *ro bind*; probe C03/C34.

**O6. [security]** One run's box can see no other run's `run_dir`; the write set is exactly one directory. — `RSD §Filesystem isolation` ("one alert structurally cannot see another's scratch"); `TM class 8` ("the control is **a box per run**").

**O7. [security]** What executes inside the box is exactly the decomposition the host-side gate approved — crossing the process boundary introduces no second parse and no shell re-expansion. — `issue-comment §3`; the property #379/#456 established. **Probed and bounded (2026-07-18, C36):** 24 hostile argv shapes — embedded newlines, single and double quotes, `$(...)`, backticks, globs, the empty string, a leading `-`, a bare `--` — cross `docker exec` byte-exact with no shell re-parse, so O7 holds for valid UTF-8. **Two explicit limits, which are now part of the obligation rather than caveats to it:** (a) an argv element that is not valid UTF-8 is *silently* rewritten to U+FFFD with rc=0 and no warning, changing its byte length — so arbitrary-byte filenames cannot cross the boundary at all; (b) an embedded NUL is rejected earlier, by Python's `subprocess` (`ValueError: embedded null byte`). The honest form of O7 is therefore: **the approved decomposition crosses byte-exact, or the call fails — never silently altered.** Limit (a) violates that as written, so the box executor must reject non-UTF-8 argv explicitly rather than let the runtime mangle it. See fork F5.

**O8. [security]** No host-side consumer of `run_dir` can be induced to read a file outside `run_dir` by a link planted inside it. — `issue-comment §2`; `RSD §Filesystem isolation` (2026-07-17 update); `TM class 2` locus (3). **Sharpened by code grounding (C48):** this is not hypothetical and it has two concrete witnesses at HEAD, neither of which uses any symlink-safe primitive (zero `lstat` / `islink` / `realpath` / `O_NOFOLLOW` across every run-dir consumer):
- `scripts/visualize/visualize_run.py:129-133` guards with `is_file()` — which *follows* the link — then `shutil.copyfile`s the dereferenced content into the **git-tracked** repo at `defender/run-visualizations/`. That is a symlink-follow whose output is committed.
- `learning/lead_repository.py:327` calls `shutil.copytree` with the default `symlinks=False`, dereferencing into the adversarial actor's staging directory.

*In this scope O8 is discharged only by the reap-time scrub (M10); the structural `RESOLVE_BENEATH` form is a non-obligation (NO1).*

**O9. [security]** When the frozen `run_dir` tree contains a symlink, the run fails loudly and no consumer runs — the tree is never silently sanitized. — `RSD §Filesystem isolation` ("fail the run loudly, don't sanitize silently"); `issue-comment §2` (`raise RunTainted(...)`). **Strengthened by probe C37:** the previous assumption that a planted symlink is *already* neutralized because the box's own kernel cannot resolve it (old C21) is **over-broad and refuted**. A symlink to a path that exists *in the image* — `/etc/passwd` — resolves successfully **inside** the box and returns 839 bytes. ENOENT holds only for image-*absent* targets. So the box can both plant *and* read a class of links, and O9 is a live requirement rather than a belt on an already-closed hole.

**O10. [security, operator]** The system refuses to process untrusted input un-boxed; the only way to run un-boxed is an explicit, loud opt-out. — `RSD §Open questions` ("Fail-closed on capability… only `DEFENDER_ALLOW_UNSANDBOXED=1` opts out, loudly").

**O11. [operator]** No box outlives the run that created it, including when the driver crashes, and a leaked box is reapable from the run id alone. — `issue-comment §3`. **Probe-confirmed as a real requirement (C42, C43):** a container genuinely survives its parent's SIGKILL, so the leak is reachable; and `docker rm -f` on a missing name is genuinely idempotent (rc=0).

**O12. [analyst-workflow]** Gather's existing bash repertoire produces the same results inside the box as outside it. **Probe-refined (C13, C14, C38):** GNU grep 3.11 and coreutils 9.7 are confirmed exactly as pinned, and `jq` is confirmed absent; but two substitutions in `python:3.11-slim` were not in any design doc — **`awk` is mawk, not GNU awk**, and **`/bin/sh` is dash, not bash** (bash 5.2.37 exists, at `/usr/bin/bash`). Any grant shape or grammar that assumes gawk extensions, or that reaches a bashism through `sh -c`, is wrong inside the box. — `issue-comment §1`; `RSG §Compatibility`; probes 2026-07-18.

**O13. [analyst-workflow, maintainer]** Artifacts the box writes appear on the host as written with no copy step. — `RSD §Filesystem isolation` ("The writable mount **is** the exit"); `RSG` evidence row *rw bind*. **Qualified by probe C41:** artifacts written through the rw bind land **root-owned on the host**. A non-root host caller cannot read a mode-0600 artifact, cannot delete it, and cannot write into the bind directory. So "no copy step" is true of the bytes and false of the *access*; whoever runs the scrub, the renderer and the learning loop must either be root or the ownership must be handled. This is a deployment obligation the corpus never states. **The second half of the original O13 — "a path names the same file inside and outside the box" — is now conditional, not free:** see C46 (docker-outside-of-Docker) and fork F8.

**O14. [maintainer]** **Resolved 2026-07-18 by the maintainer.** gVisor (`runsc`) is the **v1 default**, sitting behind a runtime knob; v1 is **not gated** on it, because the boundary itself (mount list + `--network=none`) is delivered by `runc` on any Docker host. microVM remains a live later tier, not a rejected one. — `RSD §Isolation-strength knob`; `RIEM §Consequences`; maintainer decision 2026-07-18.

The constraint research behind the resolution, recorded because it is the reason microVM is *deferred* rather than *chosen*: Hetzner Cloud can never do nested virtualization (documented policy, all instance lines), so a microVM tier requires a Server Auction bare-metal box — ~€39/mo, hourly-prorated, €0 setup, but roughly one business day per lever-up and different hardware each cycle. Against that, gVisor's default `systrap` platform needs no KVM at all.

**The consequence that changes this issue's test strategy:** `runsc` installs on stock `ubuntu-latest`, so **the boundary's tests can run under real runsc in CI**, not only against hermetic fakes. Verified green precedents: `microsoft/typescript-benchmarking` does `apt install runsc` → `sudo runsc install` → restart docker; `geomys/sandboxed-step` executes real workloads under runsc. (`/dev/kvm` *is* present on standard GitHub-hosted runners, but it is undocumented and framed only as Android-emulator acceleration — Cloud Hypervisor's own upstream keeps VM execution off hosted runners entirely — which is a further reason not to build the CI story on a microVM.)

**O15. [maintainer]** The in-process gate's non-confinement jobs survive unchanged: the ground-truth/secret read denylist (eval blinding) and main-loop phase discipline (main cannot read `gather_raw`). — `issue-comment §5` ("**#540 must not delete the denylist**"); `RIEM §Consequences`; `TM class 8`.

**O16. [operator]** Box construction cost is paid once per run, not once per bash call. — `issue-comment §3`; `RSD §What it is now` item 3. **Probe-quantified (C35):** `docker exec` median 57 ms vs `docker run` median 201 ms. The amortization argument survives; the *other* half of the per-run rationale does not — see O17 and M6.

**O17. [security, analyst-workflow] — NEW, from probe C39.** Infrastructure failures must never masquerade as program output. **Docker writes its own errors to the container's *stdout* channel, with CRLF line endings, leaving stderr empty and rc=127** (`OCI runtime exec failed: …`). A `(rc, out, err)`-shaped bash tool therefore hands the model daemon text in the same channel the command's own results arrive on — which is both a correctness bug (the model reasons over infrastructure noise as if it were data) and a security-relevant one under the axiom that the model is attacker-controlled: an attacker who can provoke a specific daemon error gains a small, attacker-timed write into the tool-result channel. The box executor must distinguish "the box failed" from "the program produced output", surface the former as a tool error, and never blend the two. — probe 2026-07-18; stated in no design doc.

### Non-obligations

**NO1. Host-side consumer confinement (Landlock / `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)` for the renderer and learning loop).** *Why:* excluded by the human's 2026-07-18 scoping decision — the mechanism is unconverged (Landlock vs. per-open resolve flags vs. a separate process boundary are three different designs with different blast radii). **This contradicts the corpus:** `issue-comment §4` calls it "in scope, high value, cheap… fold into #540's boundary", `TM class 2` locus (3) says "OS-confining them is cheap and in scope for #540", and `RSD §Filesystem isolation` repeats it. The corpus's own framing is that the scrub ships first and resolve-flags are "the upgrade" (`issue-comment §2`) — this scope takes the first half only. O8 is therefore discharged by M10 alone. **Note the cost is now measured, not notional:** C48 names two consumers that dereference outward today, one of them into a git-tracked directory.

**NO2. Driver isolation (OS-confining the host-side driver).** *Why:* a box around the driver protects neither the provider key (held by construction) nor the network the driver needs, so it "reduces blast radius, not probability". Agreed to file separately, timed to platformization, gated on #550. — `issue-comment §4`; `TM class 2` locus (1); `RIEM L96-100`.

**NO3. The broker, the vault, the credential-injecting egress proxy, the capability-RPC, session tokens, the per-run egress allowlist, and CA minting.** *Why:* nothing credentialed runs inside the box, so there is nothing to inject and no outbound connection to authenticate; #549 closed. — `RIEM` (supersedes "both halves"); `RSD` banner ¶1. Everything in `RSD §Credential injection`, `§The broker surface`, `§Build/buy`, `§Plugging in tools` is history.

**NO4. Putting the driver in the box.** *Why:* #571 moved the brain host-side; after #611 the only untrusted code execution left is model-written bash. — `RSD` banner ¶2; `issue-body` 2026-07-17 update. `RSD §The run.py lifecycle seam` is dead in full **except its ordering** (materialize `run_dir` → build box → reap → scrub), which survives — with its insertion point corrected by C47.

**NO5. #291 (per-agent run dir).** *Why:* it is the structural answer to *eval blinding*, not to the read/write boundary; `TM class 8` explicitly warns "do not let it stand in for one". — `issue-body §Current phasing`; `TM class 8`.

**NO6. #550 (taking the provider key out of the driver).** *Why:* independent, not a prerequisite; it changes the *class* of loss from an escape, not whether the boundary exists. — `issue-body` 2026-07-17 update; `RSD §What it is now`.

**NO7. microVM (Firecracker / Kata) now.** *Why:* deferred, not rejected — unchanged by the 2026-07-18 resolution, and now with a costed reason: Hetzner Cloud cannot do nested virt at all (documented policy, all lines), so the tier needs Server Auction bare metal at ~€39/mo with ~1 business day per lever-up and different hardware each cycle, in exchange for closing no class the threat model does not already concede. It becomes table stakes at platform scale where the wall is a *tenant* boundary. The obligation it leaves behind is O14 (keep the runtime a real knob, and keep the lifecycle *behind* the interface, because a microVM is not a pure `--runtime` flip at the fs layer). — `issue-body` 2026-07-17 update; `issue-comment §4`; constraint research 2026-07-18.

**NO8. Preventing symlink *creation* inside the box.** *Why:* on runsc there is no structural way to deny it. **This is now evidence, not assertion (C19, probe 13):** the same OCI bundle with a seccomp profile denying `symlink` via `SCMP_ACT_ERRNO` yields `SYMLINK_DENIED` / `Seccomp: 2` / 1 filter under runc, and `SYMLINK_ALLOWED` / `Seccomp: 0` / no filters under runsc. runsc silently ignores the profile. Creation-prevention therefore cannot be the boundary on the default runtime, and the control must be reader-side. — `issue-comment §2`; `RSD §Filesystem isolation`; probe 2026-07-18.

**NO9. Per-call `docker run --rm` as the shipped lifecycle.** *Why:* per-run is chosen; `docker exec` at 57 ms median beats `docker run` at 201 ms (C35), and `run_dir` is a durable bind either way so the security delta is small. Per-call stays *available behind the same interface* — not deleted, not the default. — `issue-comment §3`; probe C35.

**NO10. Gating v1 on runsc, or on levering the playground VPS back up.** *Why:* resolved 2026-07-17 (PR #639) and re-affirmed by the maintainer 2026-07-18 — the boundary is mounts + `--network=none`, which runc provides on any Docker host, and runsc is the *default target*. The `issue-body`'s "blocked on levering the VPS back up" is superseded twice over: runsc also installs on stock `ubuntu-latest`, so even the runsc-specific tests do not need the VPS. — `RSD §Isolation-strength knob`; O14.

**NO11. Bubblewrap / rootless podman / rootless runsc / Anthropic's `sandbox-runtime`.** *Why:* all need unprivileged user namespaces, observed `EPERM` in our container envs; `sandbox-runtime` additionally targets Claude Code's Bash tool, not an in-process PydanticAI driver. — `RSD §Rejected alternatives`; `RSG §The two hosts`.

**NO12. Nested `runsc run` inside a `--privileged` container as the spawner path.** *Why:* the Sentry then lives in a container with host devices, `CAP_SYS_ADMIN` in the bounding set and largely unmasked `/proc` — gVisor's layer-two confinement is degraded. Build on the daemon path. — `RSD §Open questions` ("**Do not build on this**"); `RSG §The daemon path`; layer-two jail corroborated on a second host by C45.

**NO13. Deleting or relaxing `runtime/permission/`.** *Why:* O15. The gate demotes to defense-in-depth/UX for *confinement*, and keeps eval blinding and phase discipline. — `issue-comment §5`; `RIEM §Consequences`.

**NO14. The honest limits the corpus declines to close here:** capability misuse (`TM class 3`), trusting the client (`TM class 4`), the laundering chain to lesson PRs (`TM class 5`), residual sanctioned egress (`TM class 6` — `--network=none` closes *direct* dial-out only), and budget enforcement (`TM class 7`, warning-only). None are sandbox problems.

**NO15. Byte-transparent argv. — NEW, forced by C36.** Arbitrary-byte (non-UTF-8) filenames and arguments cannot cross the box boundary and will not be made to. *Why:* the runtime silently transcodes them to U+FFFD with rc=0. Rather than build an encoding side-channel to preserve them, the box executor rejects non-UTF-8 argv loudly (O7). Recorded as a deliberate capability reduction, not an oversight — if a real payload filename ever needs it, this is the decision to revisit.

---

## Mechanisms

**Ordering.** The one surviving piece of `RSD §The run.py lifecycle seam`, with its insertion point corrected by code grounding (C47) — the scrub belongs at **`run.py` lines 161–167**, *before* the first host consumer, which is the `sorted(run_dir.iterdir())` at `:167`. Revision 1 placed it after `cross_check_tables`; that was wrong and would have let the first consumer read an untainted-unknown tree.

```
materialize_run_dir(alert, run_id)      # run_dir must exist to bind rw
box = start_box(run_dir, DEFENDER_DIR)
try:
    run_investigation(..., box=box)
finally:
    stop_box(box)                       # reap even on driver crash  (M5 — NO existing hook, see below)
scrub(run_dir)                          # run.py:161-167, BEFORE sorted(run_dir.iterdir()) at :167
sorted(run_dir.iterdir()) / cross_check_tables / enqueue_learning / visualize
```

**M1 — Box spawn + mount list.** One container per run, created at run setup: `run_dir` rw bind, `defender_dir` ro bind, `/tmp` tmpfs, rootfs ro, **nothing else mounted and no socket mounted inward**. *Discharges:* O1, O5, O6, O13. *Source:* `RSD §Filesystem isolation`, `§What it is now`; `issue-comment §3`.

Two probe-driven corrections:

- **The mount-ordering trap is DELETED.** `RSD §Filesystem isolation` warns that the OCI mounts array must place the `/tmp` tmpfs before the `run_dir` bind or the bind is shadowed. **This does not exist (C33).** Docker sorts mount destinations by path depth; CLI order is irrelevant. Both orderings were tested and behaved identically, with host write-through intact. There is no lever here and no shadowing failure mode — and therefore nothing for a test to pin. Revision 1 carried this as a real constraint; it was inherited from the doc and is false.
- **`--tmpfs` implies `noexec` (C40).** Scripts placed on the tmpfs fail rc=126 with `PermissionError` errno 13. The **rw bind is exec-able**, the tmpfs is not. `:exec` opts out. This is a live design choice, not an accident: leaving `/tmp` `noexec` means model-written code cannot stage an executable there, while `run_dir` — which must be writable for artifacts — remains exec-able regardless. Decide deliberately and pin it (fork F3).

**M2 — `--network=none`.** No route, no DNS, nothing to allowlist. On runc a `socket(AF_INET)`-deny seccomp belt is available; **on runsc it is not, because runsc ignores the OCI seccomp profile — now proven (C19)** — so the absent network is the sole enforcement there. *Discharges:* O2. *Source:* `RSD §Network isolation ¶1`; `RIEM invariant 2`; probe 13.

**M3 — Secret-free env.** The box's environment carries no provider key and no data-source credential. **The design's framing is superseded by two probes.** `RSD §The shape` says "extends `run_common.py:99-101` key-strip to all secrets" — a denylist. C27 (now confirmed) shows the current strip removes exactly `{ANTHROPIC_API_KEY, FIREWORKS_API_KEY}` and inherits everything else: SIEM credentials, `GITHUB_TOKEN`, `SSH_AUTH_SOCK`, docker-context variables. But C44 shows **the box inherits no host environment by default at all** — so the natural shape is not "strip harder", it is "build the environment positively". Fork F7 is closed by these two facts. *Discharges:* O3. *Source:* `RIEM L7-12`; probes 21, 18.

**M4 — Stable container name `defender-run-{run_id}`.** On-disk half of the box handle: a crashed driver's box is reapable from the run id alone. **Probe-confirmed with three sharp edges (C42, C43):** `docker rm -f` on a missing name is genuinely idempotent (rc=0) **but writes `Error response from daemon` to stderr** — a reaper that treats non-empty stderr as failure will misfire on the success path. A name collision is rc=125, and **stopped containers collide too**, so a leaked-but-exited box blocks a new run of the same id. *Discharges:* O11. *Source:* `issue-comment §3`; probe 9.

**M5 — Teardown-on-crash.** `stop_box(box)` must run whatever the driver does. **Code grounding says there is nothing to hang this on (C49): `run.py main()` has no `try`/`finally`, no `atexit`, and no signal handlers today.** The crash-safe teardown hook is new surface, not a modification of an existing one — and it must be, because C42 confirms a container survives its parent's SIGKILL, so the leak is reachable in practice. **Naming collision to avoid (C49):** `reap` already means waitpid-on-pipeline-children inside `bash_exec` (`_reap_upstream`) — the very module scope this work modifies. Pick a different verb for box teardown. *Discharges:* O11. *Source:* `issue-comment §3`; code grounding 2026-07-18.

**M6 — `BoxExecutor` handle on `AgentDeps`.** In-process half of the handle: the per-run deps the driver already threads to every tool carries the box. Lifetime = the `run.py` process = exactly one run, so nothing is shared and there is no registry.

**The rationale is now half of what the corpus claims (C35).** `issue-comment §3` and `RSD §What it is now` both justify the per-run box with "cwd and `/tmp` persist across calls and the ~0.1 s startup amortizes". **Only two of those three hold.** `/tmp` persists; the startup amortizes (57 ms exec vs 201 ms run); **cwd does not persist — each `docker exec` is an independent process starting at the container's `WorkingDir`, and a `cd` cannot outlive its exec.** So cwd must be carried caller-side and re-applied per call via `docker exec -w`. Note this is not a regression: `run_parsed` already takes `cwd` explicitly per call, so nothing in the current design actually depended on a persisting `cd`. It is the *documented rationale* that was wrong, and it should be corrected rather than reproduced.

**Threading, resolved (C50):** `AgentDeps` is `@dataclass(frozen=True)`, five fields, no slots, with **seven** production subtypes, all constructed through the single `bind` seam (`agent_definition.py:368-401` → `_for_run`). **Six of the seven are learning-pipeline roles with no box.** So a `BoxExecutor` field must be optional / absent-tolerant, or live on a runtime-only subtype; and threading it touches three signatures (`bind` → `_for_run` → constructor). Revision 1 flagged this as inference — it is now settled fact, and the "optional field vs. runtime-only subtype" choice is a real implementation decision the six box-less roles force. *Discharges:* O16 (with M1); carries O7's seam. *Source:* `issue-comment §3`; probes 2, 22.

**M7 — `_tool_bash` rewiring.** `_tool_bash` stops calling `bash_exec.run_parsed(...)` in-process and calls `deps.box.run_parsed(...)`. `permission.decide_bash(...)` stays exactly where it is, host-side, before each call. This is the single execution seam to wrap. *Discharges:* O4, O15. *Source:* `issue-comment §3` + `§Concrete code findings`. *Note:* the comment cites the seam as both `runtime/tools.py:260` (§preamble) and `runtime/tools.py:284`/`:288` (§3, §findings) — 260 is `def _tool_bash`, the later line is the `run_parsed` call inside it. Same seam.

**M8 — Cross-boundary `shell=False` composition.** `docker exec <box> python3 -m defender.runtime.bash_exec <serialized parsed pipeline>`: the box runs the *same* executor over the *same* parse the host gate approved. A naive `docker exec <box> bash -c '<string>'` would reintroduce the shell-reparse hole #379/#456 closed and is rejected. *Discharges:* O7. *Source:* `issue-comment §3` — **exists only there**, in no design doc.

**Three code-grounded constraints (C51), none of them in the corpus:**
- `Pipeline`/`Stage` are **trivially JSON-round-trippable** — `{connector: str, stages: [{argv: [str], stderr: str}]}`, no `Path`, no regex, no callable. The serialization question (F5) is therefore easy, not deep.
- **`bash_exec` has no `__main__` today.** `python3 -m defender.runtime.bash_exec` is entirely new surface, and it is *security-relevant* new surface: it is the in-box entrypoint that reconstitutes an approved parse.
- Its one non-stdlib import is `defender.hooks._cmd_segments` (line 43), and **`defender` is a PEP-420 namespace package** — so the **parent of the mount point** must be on `sys.path` inside the box, or the module will not import. This is a concrete constraint on the `defender_dir` mount destination that no doc states.

**M9 — The cwd fix.** `_tool_bash` currently passes `cwd=deps.defender_dir.parent` (the workspace root), which is **neither bind** — inside the box that path is unmounted → nonexistent, and the first bash call fails. The cwd must move to a mounted path, and (per M6) be re-applied per exec via `docker exec -w`.

**This is a THREE-site change, and it is the highest-risk unstated coupling in the whole issue (C52).** The corpus mentions only the executor site. The three sites are:
1. `tools.py:288` — the executor's `cwd=` argument;
2. `tools.py:304-313` — `_resolve_operand`'s rebase, **whose docstring explicitly pins the tie to the executor's cwd**;
3. `permission/bash.py:234` — the gate's rebase, `cwd = defender_dir.parent`, whose docstring names a divergence as "the validator/executor differential this package exists to eliminate".

Move fewer than three and the validator/executor differential reopens **at the same moment O12 is fixed** — the change that makes bash work in the box is the change that can silently unmake O7. Any test for M9 must pin that a relative operand names the same file at the gate, at `_resolve_operand`, and in the box.

**One further edge (C35):** `docker exec -w <missing>` fails rc=127, while `docker run -w <missing>` **silently creates** the directory. The strict failure is the desirable one here — but it means the chosen cwd must be guaranteed to exist inside the box before the first exec, and it means an rc=127 from a bash call is ambiguous between "bad cwd" and "the daemon errored" (O17). *Discharges:* O12. *Source:* `issue-comment §Concrete code findings`; probes 2, 19.

**M10 — Reap-time scrub of `run_dir`.** After box teardown (tree frozen, no live writer → TOCTOU-free) and at `run.py:161-167`, **before** the first consumer at `:167`: walk with `followlinks=False`, `lstat` each entry, raise on any symlink; raise on any regular file with `st_nlink > 1`. Fail the run loudly; never sanitize. *Discharges:* O8, O9. *Source:* `issue-comment §2` (the loop verbatim); `RSD §Filesystem isolation`. This is the re-owned #547 (closed NOT_PLANNED).

**Probe C53 validates the design's loop shape and shows two naive variants would be broken:**
- `os.walk(followlinks=False)` yields a **symlink-to-a-directory under `dirs`, not `files`**. A files-only walk misses it entirely — so `issue-comment §2`'s `(*dirs, *files)` is load-bearing and correct, not stylistic.
- Directory `nlink` is filesystem-dependent (tmpfs ≥2, overlayfs 1), so the `S_ISREG` guard before the `st_nlink > 1` test is **necessary, not decorative** — without it the check produces filesystem-dependent false positives on directories.
- Cross-boundary hardlinks are EXDEV in **both** directions (C20 now probed and holding), but **within-bind hardlinks succeed** — which is what fork F2 turns on.

**M11 — The runtime knob.** The box is a narrow interface — roughly `run_bash(pipelines, run_dir, defender_dir) → (rc, out, err)` over `{run_dir rw, defender_dir ro, --network=none, no secrets}` — with **three** things behind it: runtime, rootfs, and lifecycle. **Resolved 2026-07-18: the knob's default is `runsc`; `runc` is the floor that any Docker host provides and on which the boundary claim already holds; microVM is a later tier.** `--platform=systrap` and friends stay quarantined in one config spot. Lifecycle sits *behind* the interface, not hardcoded to gVisor's cost model, because a microVM is not a pure `--runtime` flip at the fs layer (virtio-fs vs. plain bind, different amortization curve).

**Test consequence, new:** because runsc installs on stock `ubuntu-latest` (O14), the knob is not merely a config seam with a fake behind it in CI — **both settings can be exercised against real runtimes.** The runsc-specific behaviours this design leans on (C19's seccomp-ignoring, C54's dropped `CAP_NET_RAW`) are CI-verifiable rather than VPS-gated, which is what makes NO8's justification testable rather than documentary. *Discharges:* O14. *Source:* `RSD §Isolation-strength knob`; maintainer decision 2026-07-18. The knob's key name and type remain unspecified — fork F1, now narrowed.

**M12 — Fail-closed capability check + `DEFENDER_ALLOW_UNSANDBOXED`.** At startup, *attempt* a probe (not merely detect a binary) and refuse to process untrusted input un-boxed on failure; `DEFENDER_ALLOW_UNSANDBOXED=1` is the only opt-out and it is loud. *Discharges:* O10. *Source:* `RSD §Open questions`. **[INFERRED]** the corpus states this only for the *runsc capability* probe; generalizing it to "the box could not be started at all" is reconstruction — fork F6, which C42/C43/C46 have now given concrete failure modes to enumerate.

**M13 — Rootfs build-time requirements.** Rootfs pinned to `python:3.11-slim`. `jq` must be **baked in at build time** — it is absent from the base (C14) and the box is `--network=none`, so runtime install is impossible. The `.venv` must be on `PATH` so `defender-sql` and the `defender-*` shims resolve. **Plus the two substitutions probe 7 surfaced (C38): `awk` is mawk and `/bin/sh` is dash.** If any grant shape depends on gawk extensions or reaches bash through `sh -c`, the rootfs must also bake in gawk / repoint `sh`, or the shape must be corrected. Failures are loud (`command not found`, or a silently different awk dialect — that second one is *not* loud, and is the one to test).

**A build-time trap from probe 8 (C55):** `apt-get update` **exits 0** with no network; only `install` fails, at rc=100. So a rootfs build step that checks `apt-get update`'s exit code as a network sanity gate will pass in a network-less environment and fail later. *Discharges:* O12. *Source:* `issue-comment §1`; `RSG §Compatibility`; probes 7, 8.

**M14 — The gate stays host-side, unchanged.** Only *execution* crosses the boundary. `decide_bash` runs in the trusted driver before each call; the ground-truth/secret read denylist and main-loop phase discipline are untouched. *Discharges:* O15; preserves O7's premise. *Source:* `issue-comment §3`, `§5`.

**M15 — In-box permission bits are not a mechanism.** The guest runs as uid 0 with `dac_override` (C17, confirmed under runsc), so `chmod`/uid confine nothing inside the box. No in-box logic may lean on them; the mount list is the boundary. **One runsc-vs-runc difference worth recording (C54): gVisor drops `CAP_NET_RAW`** where runc keeps it — the one bit by which the guest capability sets differ. It is a small hardening delta in runsc's favour and it is *not* something the design should depend on, since `runc` is the supported floor. Recorded as a *negative* mechanism because it constrains every other choice here.

**M16 — Channel discipline in the box executor. — NEW, discharges O17.** The executor must not return daemon output as program output. Concretely: treat rc=125 (daemon/name-collision), rc=126 (permission — e.g. the `noexec` tmpfs, C40) and rc=127 (exec failure — missing `-w` target, missing binary, or an OCI error) as *candidate infrastructure faults*, and distinguish them from the program's own exit codes rather than passing the tuple through. The distinguishing signal is available: Docker's own errors arrive on **stdout with CRLF while stderr is empty** (C39), which is the inverse of the normal shape. This is heuristic, not structural, and the honest options are in fork F9. Whatever the mechanism, the obligation is that infrastructure text never reaches the model in the results channel unlabelled.

---

## Claims

Every statement this design rests on about *existing* reality, as falsifiable predictions. `status: probed-2026-07-18` marks the executed probes from this revision; `verdict` records what the probe did to the claim.

```yaml
claims:
  # --- RSG observed evidence: nested path, observed 2026-07-09 ---
  - id: C01
    kind: primitive
    claim: "runsc (release-20260706.0, systrap platform, no KVM) runs a trivial OCI bundle to exit 0 inside a --privileged container on the playground VPS."
    source: "RSG §Evidence (observed 2026-07-09)"
    status: probed-in-corpus
  - id: C02
    kind: primitive
    claim: "Under runsc the guest kernel is gVisor's, not the host's (guest `uname` reports `4.19.0-gvisor`)."
    source: "RSG §Evidence (2026-07-09) and §The daemon path (2026-07-17)"
    status: probed-in-corpus
  - id: C03
    kind: primitive
    claim: "A read-only bind into a box is readable from inside and a write to it fails with EROFS."
    source: "RSG §Evidence (2026-07-09); §The daemon path (2026-07-17); re-probed under runc 2026-07-18 (see C34 for the fault's Python type)"
    status: probed-2026-07-18
    verdict: holds
  - id: C04
    kind: primitive
    claim: "A read-write bind is writable from inside and the host sees the written bytes — the writable mount IS the artifact exit, with no copy step."
    source: "RSG §Evidence (2026-07-09); §The daemon path (2026-07-17); re-probed 2026-07-18"
    status: probed-2026-07-18
    verdict: holds-with-qualification
    note: "The bytes cross; the ACCESS does not, for a non-root host caller — see C41. O13 is qualified accordingly."
  - id: C05
    kind: primitive
    claim: "`--network=none` leaves the guest with only `lo`, loopback-only routes, and no reachable external destination."
    source: "RSG §Evidence (2026-07-09); §The daemon path (2026-07-17)"
    status: probed-in-corpus
  - id: C06
    kind: primitive
    claim: "A bind-mounted host unix socket is connectable from inside a runsc box when `--host-uds=open` is passed."
    source: "RSG §Evidence (2026-07-09)"
    status: probed-in-corpus
    note: "Observed, but NOT used — no socket is mounted inward (RIEM invariant 2, NO3). Recorded so a future reader does not re-derive it as available capability."
  - id: C07
    kind: behavior
    claim: "Bare `runsc run` create+run+teardown of `/bin/true` costs ~0.08-0.11 s on the VPS."
    source: "RSG §Evidence (2026-07-09)"
    status: probed-in-corpus

  # --- RSG observed evidence: daemon path, observed 2026-07-17 ---
  - id: C08
    kind: primitive
    claim: "`docker run --runtime=runsc` against a host Docker daemon works with no privileged container; `runsc install` + docker restart registers it and `docker info` reports it."
    source: "RSG §The daemon path — GO (observed 2026-07-17)"
    status: probed-in-corpus
    note: "Independently corroborated by the CI precedents behind O14 — microsoft/typescript-benchmarking runs exactly this sequence on ubuntu-latest."
  - id: C09
    kind: behavior
    claim: "`docker run --rm` under runsc costs ~0.30-0.37 s per invocation."
    source: "RSG §The daemon path (observed 2026-07-17)"
    status: probed-in-corpus
    note: "Same shape as C35's runc numbers (201 ms run vs 57 ms exec): the per-run-box amortization argument is runtime-independent."
  - id: C10
    kind: primitive
    claim: "On the daemon path the Sentry is parented by containerd-shim under PID 1 with `Seccomp: 2`, `NoNewPrivs: 1`, and CapEff = six caps, no `CAP_SYS_ADMIN`."
    source: "RSG §The daemon path — layer-two evidence (2026-07-17); corroborated on a second host 2026-07-18"
    status: probed-2026-07-18
    verdict: holds
    note: "C45 reproduces this and extends it to the gofer."
  - id: C11
    kind: primitive
    claim: "`--ignore-cgroups` is unnecessary on the daemon path; it was a nested-container artifact."
    source: "RSG §The daemon path (2026-07-17)"
    status: probed-in-corpus
  - id: C12
    kind: primitive
    claim: "In the devcontainer both privilege doors are shut, so local runsc iteration requires relaunching the devcontainer privileged."
    source: "RSG §The two hosts (2026-07-09)"
    status: probed-in-corpus
    note: "No longer a blocker for the boundary's tests — O14 puts real runsc on ubuntu-latest in CI."

  # --- Image / compatibility ---
  - id: C13
    kind: census
    claim: "`python:3.11-slim` ships GNU grep 3.11 and coreutils 9.7 — exactly the binaries `gnu_flags.py` pins its flag arities against."
    source: "issue-comment §1 (2026-07-17); RSG §Compatibility; re-probed 2026-07-18"
    status: probed-2026-07-18
    verdict: holds
  - id: C14
    kind: census
    claim: "`jq` is absent from the base `python:3.11-slim` image."
    source: "issue-comment §1 (2026-07-17); re-probed 2026-07-18"
    status: probed-2026-07-18
    verdict: holds
  - id: C38
    kind: census
    claim: "In `python:3.11-slim`, `awk` is mawk (not GNU awk) and `/bin/sh` is dash (not bash); bash 5.2.37 exists but only at `/usr/bin/bash`."
    source: "probe 7, 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "Named in no design doc. Any grant shape assuming gawk extensions, or reaching a bashism via `sh -c`, is wrong inside the box. The failure is NOT loud in the awk case — a mawk/gawk dialect difference produces different output, not an error. Drives M13/O12."
  - id: C15
    kind: behavior
    claim: "Installing jq at runtime inside the box is impossible under `--network=none`."
    source: "issue-comment §1 (2026-07-17); refined by probe 8, 2026-07-18"
    status: probed-2026-07-18
    verdict: holds-with-qualification
    note: "See C55: `apt-get update` exits 0 with no network; only `install` fails (rc=100). A build gate that checks `update`'s exit code is not a network check."
  - id: C16
    kind: behavior
    claim: "CPython imports fine from a read-only `defender_dir` and silently skips the `.pyc` write on EROFS."
    source: "issue-comment §1 (2026-07-17); RSG §Compatibility"
    status: probed-in-corpus
  - id: C17
    kind: primitive
    claim: "The box guest runs as uid 0 with `dac_override` and without `sys_admin`, so file permission bits and uid confine nothing inside the box."
    source: "issue-comment §1; RSG §Compatibility; re-probed under runsc 2026-07-18 (probe 14)"
    status: probed-2026-07-18
    verdict: holds
  - id: C54
    kind: primitive
    claim: "gVisor's guest capability set differs from runc's by exactly one bit: runsc drops `CAP_NET_RAW`."
    source: "probe 14, 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "A small hardening delta in runsc's favour. The design must NOT depend on it, since runc is the supported floor (O14)."
  - id: C18
    kind: behavior
    claim: "`defender-sql` runs end-to-end from a read-only-bound `.venv` inside the real box."
    source: "RSG §Compatibility ('Still wanting the real box (not blocking)'); issue-comment §1"
    status: asserted
    note: "STILL the one O12 leg with no probe behind it, after two rounds of probing. Now cheaper to close than ever — O14 puts a real box in CI. Should be an acceptance test, not a claim."

  # --- The boundary's exec seam ---
  - id: C33
    kind: primitive
    claim: "The OCI mounts array must place the `/tmp` tmpfs before the `run_dir` bind, or the bind is shadowed."
    source: "RSD §Filesystem isolation (§Mount-ordering trap)"
    status: probed-2026-07-18
    verdict: REFUTED
    note: "Docker sorts mount destinations by path depth; CLI order is irrelevant. Both orderings tested identically with host write-through. There is no lever and no shadowing failure mode. DELETED from M1; `RSD §Filesystem isolation` is wrong here and should be corrected."
  - id: C35
    kind: behavior
    claim: "cwd persists across `docker exec` calls into a long-lived box, so a per-run box lets cwd and /tmp survive between bash calls."
    source: "issue-comment §3; RSD §What it is now item 3"
    status: probed-2026-07-18
    verdict: REFUTED-IN-PART
    note: "/tmp persists; cwd does NOT — each exec is an independent process starting at the container's WorkingDir, and a `cd` cannot outlive its exec. cwd must be carried caller-side and re-applied via `docker exec -w` per call. The amortization half holds and is quantified: exec 57ms median vs run 201ms median. Asymmetry: `exec -w <missing>` fails rc=127; `run -w <missing>` silently creates it. Not a functional regression (run_parsed already passes cwd per call) but the DOCUMENTED rationale is wrong."
  - id: C36
    kind: behavior
    claim: "argv crosses `docker exec` byte-exact with no shell re-parse."
    source: "issue-comment §3 (the shell=False preservation claim); probed 2026-07-18"
    status: probed-2026-07-18
    verdict: holds-with-limits
    note: "24 hostile args — newlines, single/double quotes, $(...), backticks, globs, empty string, leading `-`, bare `--` — survive byte-exact. TWO LIMITS: invalid UTF-8 is SILENTLY rewritten to U+FFFD at rc=0 with no warning, changing byte length (arbitrary-byte filenames cannot cross at all); NUL is rejected earlier by Python subprocess (ValueError: embedded null byte). Drives O7's bounded form, NO15, and fork F5."
  - id: C39
    kind: behavior
    claim: "Docker writes its OWN errors to the container's stdout channel with CRLF, leaving stderr empty, at rc=127 (`OCI runtime exec failed: …`)."
    source: "probe 4, 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "A (rc, out, err) bash tool therefore hands the model daemon text in the command's stdout channel. Wholly absent from the corpus. Creates O17 and M16."
  - id: C40
    kind: primitive
    claim: "`--tmpfs` implies `noexec`: scripts on the tmpfs fail rc=126 with PermissionError errno 13. The rw bind IS exec-able. `:exec` opts out."
    source: "probe 6, 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "Affects M1 and fork F3. Not stated anywhere; RSD calls /tmp 'writable scratch SIEM CLIs expect' with no mention of exec permission."
  - id: C41
    kind: behavior
    claim: "Artifacts written through the rw bind land root-owned on the host; a non-root host caller cannot read a 0600 artifact, delete it, or write into the bind directory."
    source: "probe 10, 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "Qualifies O13. Affects everything downstream of the box: the scrub, the renderer, the learning loop. Stated nowhere in the corpus."
  - id: C44
    kind: behavior
    claim: "The box inherits no host environment by default."
    source: "probe 18, 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "Makes the positive-allowlist env (M3) the natural shape rather than an imposition — there is nothing to strip. Closes fork F7 together with C27."
  - id: C46
    kind: primitive
    claim: "Under docker-outside-of-Docker, bind SOURCES resolve in the HOST namespace, and a source path absent there is SILENTLY CREATED as an empty directory rather than erroring."
    source: "probe 11, 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "'In-box path equals host path' (O13, and RSD's whole absolute-path-identity argument) is NOT automatically satisfiable when the driver itself runs containerized — which is how this repo is developed. The silent-empty-dir behaviour turns a misconfiguration into an empty run_dir rather than an error. Drives fork F8."
  - id: C55
    kind: behavior
    claim: "`apt-get update` exits 0 with no network; only `install` fails (rc=100)."
    source: "probe 8, 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "A rootfs build step using `apt-get update`'s exit code as a network sanity gate passes in a network-less environment and fails later. Drives M13."
  - id: C56
    kind: primitive
    claim: "EROFS, ENOSPC and ENETUNREACH all surface as bare `OSError` in Python — no `PermissionError`/`ConnectionRefusedError` subclass — and DNS under `--network=none` raises `socket.gaierror` with errno -3 (EAI_AGAIN), which is NOT present in `errno.errorcode`."
    source: "probe 8, 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "Directly constrains how the boundary's tests assert faults: assert `OSError` + errno, never the subclass; and any errno->name lookup for the DNS case must not assume `errno.errorcode` contains it. This is the single most reusable finding for whoever writes the test spec."

  # --- The symlink residual ---
  - id: C19
    kind: primitive
    claim: "runsc silently ignores the OCI `linux.seccomp` profile — the Sentry services syscalls itself — so no syscall-deny can be enforced through the OCI spec on runsc; such a belt exists only on the runc fallback."
    source: "RSG §Caveats; RSD §Network isolation; issue-comment §2; EXECUTED probe 13, 2026-07-18"
    status: probed-2026-07-18
    probe_kind: executed
    verdict: holds
    note: "Same bundle, profile denying `symlink` with SCMP_ACT_ERRNO: runc -> SYMLINK_DENIED, Seccomp: 2, 1 filter. runsc -> SYMLINK_ALLOWED, Seccomp: 0, no filters. Reproduced via `--security-opt seccomp=`. Revision 1 flagged this as LOAD-BEARING-and-never-probed; it is now the evidenced justification for NO8 and M10."
  - id: C20
    kind: primitive
    claim: "A hardlink cannot be created across the box boundary — cross-device link returns EXDEV."
    source: "issue-comment §2 ('hardlink-out already EXDEV-impossible'); EXECUTED probe 12, 2026-07-18"
    status: probed-2026-07-18
    verdict: holds
    note: "EXDEV in BOTH directions. But within-bind hardlinks SUCCEED — which is exactly what fork F2 turns on, and is the reason the hardlink half of the scrub is not simply dead."
  - id: C21
    kind: behavior
    claim: "A symlink planted inside `run_dir` cannot be dereferenced by the box itself — the box's kernel resolves the target against the box root and gets ENOENT."
    source: "issue-comment §2; RSD §Filesystem isolation (2026-07-17 update)"
    status: probed-2026-07-18
    verdict: REFUTED-AS-OVER-BROAD
    note: "A symlink to a path present IN THE IMAGE (/etc/passwd) resolves successfully inside the box and returns 839 bytes. ENOENT holds ONLY for image-absent targets. The corpus states the ENOENT case as though it were general. Strengthens O8/O9 and M10: the box can plant AND read a class of links."
  - id: C22
    kind: reachability
    claim: "A merely-injected (class-1) model cannot plant a symlink in `run_dir`: no agent's grant list contains `ln`, and the write surfaces create regular files and never call `symlink()`."
    source: "issue-comment §2; RSD §Filesystem isolation; TM class 2 locus (3)"
    status: asserted
    note: "Still unprobed as a census. Two independently falsifiable conjuncts: (a) a census over every agent's bash_shapes for a link-creating program, (b) a behavioural check that no write surface calls symlink()/os.link(). NOTE the interaction with C47/C57: #575 closed the AGENT-side residual, which is adjacent to but not the same as this claim."
  - id: C23
    kind: reachability
    claim: "Every host-side consumer of `run_dir` runs AFTER the point where the scrub sits."
    source: "issue-comment §3 (the run.py main() seam ordering); code grounding 2026-07-18"
    status: probed-2026-07-18
    verdict: CORRECTED
    note: "Revision 1 placed the scrub after cross_check_tables. WRONG. The first host consumer is `sorted(run_dir.iterdir())` at run.py:167, so the scrub's window is run.py:161-167. The corrected ordering is in the M-ordering block."
  - id: C48
    kind: census
    claim: "No run-dir consumer uses any symlink-safe primitive — zero lstat/islink/realpath/O_NOFOLLOW across all of them — and two dereference OUTWARD: scripts/visualize/visualize_run.py:129-133 guards with is_file() (which follows) then shutil.copyfile into the git-tracked defender/run-visualizations/; learning/lead_repository.py:327 uses shutil.copytree with default symlinks=False into the actor's staging dir."
    source: "code grounding 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "This is O8's concrete witness. It also means NO1's exclusion is a real accepted risk with named call sites, not a notional one — worth restating when the follow-up issue is filed."
  - id: C53
    kind: primitive
    claim: "os.walk(followlinks=False) yields a symlink-to-a-directory under `dirs`, not `files`; directory nlink is filesystem-dependent (tmpfs >=2, overlayfs 1)."
    source: "probe 12, 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "Validates issue-comment §2's loop exactly: the `(*dirs, *files)` iteration is load-bearing (a files-only walk misses the symlinked dir), and the S_ISREG guard before the nlink test is NECESSARY, not decorative (without it, filesystem-dependent false positives on directories)."

  # --- Current-tree assertions ---
  - id: C24
    kind: census
    claim: "There is zero spawner/sandbox code in the tree today — every `runsc`/`gvisor` grep hit is the substring `RunScope`."
    source: "issue-comment §preamble (checked against main, 2026-07-17)"
    status: probed-in-corpus
  - id: C25
    kind: behavior
    claim: "#611 is merged: data sources are the in-process typed `query` tool and `_tool_bash` has no adapter branch left."
    source: "issue-comment §preamble (confirmed against main, 2026-07-17)"
    status: probed-in-corpus
  - id: C26
    kind: referential
    claim: "`_tool_bash` executes via one `bash_exec.run_parsed(...)` call site whose cwd is `deps.defender_dir.parent` — the workspace root, which is neither bind."
    source: "issue-comment §Concrete code findings; code grounding 2026-07-18 (tools.py:288)"
    status: probed-2026-07-18
    verdict: holds
  - id: C52
    kind: referential
    claim: "The cwd is coupled at THREE sites, not one: tools.py:288 (executor), tools.py:304-313 (_resolve_operand rebase, whose docstring explicitly pins the tie), and permission/bash.py:234 (gate rebase, cwd = defender_dir.parent)."
    source: "code grounding 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "Revision 1 identified two sites and marked the coupling [INFERRED]. It is three, and it is confirmed. Moving the cwd is a multi-site change or the validator/executor differential reopens — at the same moment O12 is fixed. Highest-risk unstated coupling in the change."
  - id: C27
    kind: behavior
    claim: "`run_common.run_env` returns dict(os.environ) minus providers.api_key_vars() = exactly {ANTHROPIC_API_KEY, FIREWORKS_API_KEY}; everything else — SIEM creds, GITHUB_TOKEN, SSH_AUTH_SOCK, docker-context vars — is inherited."
    source: "RSD §The shape; code grounding 2026-07-18"
    status: probed-2026-07-18
    verdict: holds
    note: "Confirms fork F7's allowlist recommendation and CLOSES the fork. RSD's 'extend the key-strip to all secrets' is the wrong shape: with C44 (the box inherits nothing by default) the allowlist is not merely safer, it is the path of least resistance."
  - id: C28
    kind: referential
    claim: "`AgentDeps` is @dataclass(frozen=True), 5 fields, no slots, with SEVEN production subtypes all constructed through the single `bind` seam (agent_definition.py:368-401 -> _for_run). Six of the seven are learning-pipeline roles with no box."
    source: "issue-comment §3; code grounding 2026-07-18"
    status: probed-2026-07-18
    verdict: holds
    note: "Revision 1 marked this [INFERRED]; now settled. A BoxExecutor field must be optional/absent-tolerant or live on a runtime-only subtype, and threading it touches three signatures (bind -> _for_run -> constructor)."
  - id: C51
    kind: referential
    claim: "Pipeline/Stage are trivially JSON-round-trippable ({connector: str, stages: [{argv: [str], stderr: str}]}) with no Path/regex/callable; but bash_exec has NO __main__ today, and its one non-stdlib import is defender.hooks._cmd_segments (line 43) — and `defender` is a PEP-420 namespace package, so the PARENT of the mount point must be on sys.path inside the box."
    source: "code grounding 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "Makes fork F5's serialization question easy and adds two real constraints: `python3 -m defender.runtime.bash_exec` is new security-relevant surface, and the mount destination is constrained by namespace-package import mechanics."
  - id: C49
    kind: referential
    claim: "`run.py main()` has NO try/finally, no atexit, and no signal handlers — there is no existing crash-safe teardown hook. Separately, `reap` already means waitpid-on-pipeline-children in bash_exec (_reap_upstream)."
    source: "code grounding 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "M5's hook is new surface, not a modification. And the naming collision sits inside the very module scope this work modifies — pick a different verb for box teardown."
  - id: C42
    kind: behavior
    claim: "A container survives its parent's SIGKILL."
    source: "probe 9, 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "Makes O11's leak reachable in practice and makes M4's stable name load-bearing rather than a convenience."
  - id: C43
    kind: behavior
    claim: "`docker rm -f` on a missing name is idempotent (rc=0) but writes `Error response from daemon` to STDERR; a name collision is rc=125, and STOPPED containers collide too."
    source: "probe 9, 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "A reaper treating non-empty stderr as failure misfires on the SUCCESS path. And a leaked-but-exited box blocks a new run of the same run_id. Drives M4/M5 and fork F6."
  - id: C45
    kind: primitive
    claim: "The Sentry's host-side jail is real and reproducible: runsc-sandbox has Seccomp: 2, NoNewPrivs: 1, CapEff 0x8001f; runsc-gofer the same with sys_chroot in place of sys_ptrace."
    source: "probe 15, 2026-07-18 (privileged sibling container, runsc release-20260714.0)"
    status: probed-2026-07-18
    verdict: holds
    note: "Corroborates C10 on a second host and extends it to the gofer. This is gVisor's layer two — the thing NO12 exists to protect."
  - id: C29
    kind: behavior
    claim: "#547 (the reap-time run_dir symlink scrub) was closed NOT_PLANNED, so the residual is currently unowned."
    source: "issue-comment §2; RSD §Filesystem isolation"
    status: asserted
  - id: C30
    kind: primitive
    claim: "A Docker daemon is reachable from wherever run.py runs, and run.py's uid may create containers on it."
    source: "[INFERRED] — implied by start_box/docker exec/docker rm -f in issue-comment §3; stated nowhere."
    status: asserted
    note: "Still the most basic deployment premise of the design, still written down nowhere. C46 makes it sharper: under docker-outside-of-Docker the premise holds but path identity silently does not. Drives forks F6 and F8."
  - id: C57
    kind: referential
    claim: "`runtime-sandbox-design.md:127-128` asserts the bash reader lane does no resolve(), and that a symlink target is closed only by the convention 'no allowed tool creates a symlink' (policy.py:15-20)."
    source: "RSD §Why the in-process gate isn't the boundary; code grounding 2026-07-18"
    status: probed-2026-07-18
    verdict: REFUTED
    note: "Revision 1 marked this stale-suspected. It is REFUTED, twice over. (a) The bash reader lane DOES resolve() — permission/bash.py:238, inside _in_scope. (b) #575 CLOSED the agent-side symlink residual outright: tests/test_read_confine_bash.py:630-669, header 'Symlinks: the residual this file used to DOCUMENT is now CLOSED'. RSD:127-128 is FALSE AT HEAD and correcting it is a design fix that belongs in this work. Note what this does NOT change: the agent-side residual is closed, the HOST-CONSUMER residual (C48) is the live one, and it is untested."
  - id: C32
    kind: referential
    claim: "`RSD:125` cites `tools.py:205` as the adapter-subprocess site the gate cannot see into."
    source: "RSD §Why the in-process gate isn't the boundary"
    status: stale-suspected
    note: "Unchanged from revision 1 — predates #611, which removed the adapter branch from _tool_bash entirely (C25). Both the line number and the argument it supports are stale for the bash lane. Lower priority than C57 because nothing in this design depends on it; still worth correcting while the doc is open."
  - id: C33b
    kind: behavior
    claim: "RIEM describes, in the present tense, that parse_params/_derive_verb reverse-engineer the queries-table fields out of a model-authored argv string, and that inverting that arrow is future work."
    source: "RIEM §The rule that makes it hold"
    status: stale-suspected
    note: "Unchanged from revision 1. #611 shipped the inversion (C25); RIEM's present tense is stale and the helpers should have no job left. Probe before any test asserts on them. (Renumbered from revision 1's C33, which is now the mount-ordering refutation.)"
  - id: C58
    kind: census
    claim: "Only two pytest markers exist (`live`, `e2e`); CI runs `-m \"not live\"`, so `e2e` RUNS IN CI. The e2e replay harness drives the REAL _tool_bash and bash_exec.run_parsed, and its fakes enter through injection seams only (make_model, verbs=) — driver.py:518 is the canonical precedent for a BoxExecutor seam."
    source: "code grounding 2026-07-18"
    status: probed-2026-07-18
    verdict: new
    note: "The most consequential finding for the test spec: a box seam at _tool_bash is exercised by EVERY existing e2e test the moment it lands. That is leverage (broad coverage for free) and risk (every e2e test breaks at once if the seam is wrong). Combined with O14 — real runsc on ubuntu-latest — the boundary can be tested against a real box in CI rather than only against a hermetic fake."
```

---

## Open forks

**F1 — The runtime knob's config key: name and type. — NARROWED by the 2026-07-18 resolution.** The *default* is now settled (runsc), and microVM's status is settled (later tier, NO7). What remains unspecified is the key's name and shape. *Options:* (a) a single env var, e.g. `DEFENDER_BOX_RUNTIME` ∈ `{runc, runsc}`; (b) a field on the run config object; (c) a small dataclass (`BoxSpec`: runtime + rootfs + lifecycle), since M11 names **three** replaceables. *Recommendation (unchanged, now better supported):* **(c) with (a) as its only external lever.** Three separate probe findings have since landed on the other two axes — the rootfs substitutions (C38), the tmpfs exec mode (C40), and the lifecycle asymmetry between `exec -w` and `run -w` (C35) — so the "one string key" option would have grown three more env vars within a release. Anchor the default (`runsc`) in the dataclass per the repo's `lint_unanchored_default` convention, read one env var to override the runtime axis, and keep `--platform=systrap` inside the dataclass's branches so O14's "quarantined in one config spot" is literally true. **New test consequence:** because both runtimes are now CI-reachable (O14), the knob should be exercised at both settings in CI, not stubbed at one.

**F2 — Is the scrub's hardlink half justified? — STILL OPEN, and the probe moved it.** Revision 1 argued this against an *unprobed* C20. C20 is now probed and holds: cross-boundary hardlinks are EXDEV in both directions. So the hardlink half defends nothing at the boundary. **But the same probe found that within-bind hardlinks succeed (C53)** — which is precisely the threat revision 1 reached for speculatively and which is now demonstrated. *Options:* (a) keep both checks with the asymmetric "load-bearing"/"belt" labels; (b) keep the symlink check only; (c) keep both, justified on the *within-bind* threat: a hardlink is a second name for the same inode, so a consumer's per-path assumption ("each `{seq}.json` is a distinct payload") can be violated, and a post-scrub mutation through one name changes a file already validated under the other. *Recommendation:* **(c), now on evidence rather than speculation.** The check costs one `st_nlink` compare in a walk already being performed, and (c) is the only justification that survives C20 holding. Note C53's second finding makes the implementation non-obvious: the `S_ISREG` guard is *required*, because directory `nlink` is filesystem-dependent (tmpfs ≥2, overlayfs 1) and an unguarded `nlink > 1` test produces filesystem-dependent false positives. Do **not** ship (a): a check whose only recorded justification is "belt against an impossibility" is the branch a cleanup PR deletes.

**F3 — The `/tmp` tmpfs: size cap, and now exec mode. — WIDENED by C40.** `RSD` says "size-capped" and names no value; the probe added a second undecided axis. *Size options:* (a) uncapped (default is typically half of host RAM — a host-DoS surface reachable by class-1 alone, no exploit needed); (b) a fixed conservative cap; (c) a field on F1's `BoxSpec`. *Exec options:* (i) keep the `--tmpfs` default `noexec`; (ii) opt out with `:exec`. *Recommendation:* **(b) sized to the workload and exposed via F1's dataclass, and (i) keep `noexec`.** On size: the box's `/tmp` exists for "writable scratch SIEM CLIs expect", and after #611 the SIEM CLIs are gone from the box — what remains is local computation over payloads already in `run_dir`, so the requirement is small. **[INFERRED]** a value in the low hundreds of MB is the right order; the corpus supports no specific number, so pick one, record that it is a guess, and let a real run move it. This is *not* a security boundary — a full tmpfs is `TM class 7` (accounted, not enforced) — so it should fail the run loudly rather than silently. On exec: `noexec` is free hardening that costs the workload nothing, since model-written code that needs to stage an executable can still do so on the rw bind (which is exec-able and cannot be made otherwise without breaking artifacts). Pin both in a test, because C40 shows the exec mode is a *default* nobody chose — and defaults nobody chose are the ones that flip silently.

**F4 — What should the bash cwd be, and how is it carried? — HALF CLOSED by C35.** The "how" is settled: **cwd cannot persist across execs**, so it is carried caller-side and re-applied per call via `docker exec -w`. The corpus's "cwd persists" rationale is refuted and should be corrected wherever it appears. What remains open is the *value*. *Options:* (a) `run_dir`; (b) `defender_dir`; (c) a subdir of the `/tmp` tmpfs. *Recommendation:* **(a) `run_dir`, now more strongly.** It is the rw bind, it is where every payload a pipeline reads lives, and it keeps a bare relative operand resolving into the only writable place — which is also the containment story the grant scopes already encode. `defender_dir` is ro, so any tool expecting to write scratch in `.` breaks there. Option (c) lost two independent legs to the probes: the tmpfs is `noexec` (C40) *and* non-durable, so relative operands would resolve outside the artifact exit onto a volume that cannot run anything.

**The constraint that dominates this fork (C52) — elevated, as instructed.** The cwd is coupled at **three** sites: `tools.py:288` (executor), `tools.py:304-313` (`_resolve_operand`'s rebase, whose docstring *explicitly pins the tie to the executor's cwd*), and `permission/bash.py:234` (the gate's rebase, `cwd = defender_dir.parent`, whose docstring names a divergence as "the validator/executor differential this package exists to eliminate"). Move fewer than three and the differential reopens **at the same moment O12 is fixed** — the change that makes bash work inside the box is the change that can silently unmake O7. This is the highest-risk unstated coupling in the issue: no design doc connects the cwd fix to either rebase site. Any test must pin that a relative operand names the same file at the gate, at `_resolve_operand`, and in the box. Secondary edge: `exec -w <missing>` is rc=127, so the chosen cwd must be guaranteed to exist before the first exec — and that rc=127 is ambiguous with a daemon error (O17/F9).

**F5 — How does a parsed `Pipeline` cross the process boundary? — NARROWED by C51 and C36.** M8 leaves "serialized" undefined. C51 settles the easy part: `Pipeline`/`Stage` are trivially JSON-round-trippable, no `Path`, no regex, no callable. *Options:* (a) JSON on argv; (b) JSON on stdin; (c) pickle — **rejected on sight**, since `TM class 2` cites "no pickle" as evidence our own code is clean, and this would deserialize into the *trusted-parse* side; (d) re-send the raw command string and re-`parse()` in the box. *Recommendation (unchanged, reinforced):* **(b) JSON on stdin**, with a strict schema-checked decode in the box and a hard failure on anything unexpected.

(d) must be rejected explicitly: re-parsing in the box reintroduces a second parse step and therefore a validator/executor differential — the exact property O7 exists to preserve — even though the parser is the same code, because the *input* would cross as a string rather than as the approved decomposition. (a) is now worse than revision 1 judged it: beyond `ARG_MAX` and the `/proc/<pid>/cmdline` exposure (the model can read its own approved parse), **C36 shows argv silently mangles non-UTF-8 to U+FFFD at rc=0**, so putting the serialized parse on argv puts it through exactly the transform that can alter it without signalling. Stdin avoids all three.

**Two new constraints on whatever is chosen.** (1) Per NO15/O7, the encoder must **reject non-UTF-8 argv loudly** rather than let the runtime transcode it — the boundary's promise is byte-exact-or-fail, and C36 shows the runtime will not honour that unaided. (2) Per C51, `python3 -m defender.runtime.bash_exec` is **new surface with an import constraint**: `defender` is a PEP-420 namespace package and `bash_exec` imports `defender.hooks._cmd_segments`, so the *parent of the mount point* must be on `sys.path` inside the box. That is a requirement on the `defender_dir` mount destination, not just on the module. Note the trust direction is unusual and worth stating in the design: the *host* sends and the *box* receives, so the box-side decoder is not a security boundary — but it must still fail closed, or a malformed encode silently becomes a differently-shaped command.

**F6 — What happens when the box cannot be started, or dies mid-run? — STILL OPEN, now with an enumerated failure set.** Fail-closed is stated only for the runsc capability probe (`RSD §Open questions`, M12). The probes turned "unspecified" into a concrete list: daemon unreachable (C30); image missing; **bind source absent under docker-outside-of-Docker, silently created as an empty dir (C46)**; **name collision at rc=125, including with a *stopped* container (C43)**; `docker exec` failing mid-run; and the box outliving a SIGKILLed parent (C42). *Options:* (a) extend M12's fail-closed rule to every box-construction failure — refuse the run, non-zero exit, no investigation; (b) fall back to in-process `bash_exec` with a loud warning; (c) fail closed at start, but degrade a mid-run `docker exec` failure to a tool error the model sees. *Recommendation:* **(a), plus (c) for the mid-run case, and never (b).** (b) is a silent-downgrade path converting O4 from a boundary into best-effort — the exact failure mode `DEFENDER_ALLOW_UNSANDBOXED` exists to make explicit, so an implicit fallback makes that variable pointless.

Two probe-specific behaviours the implementation must get right: the pre-create reap of the stable name is now clearly *necessary* rather than tidy (C43: stopped containers collide, so a leaked-but-exited box blocks the next run of that id) — but it means a *concurrent* run with the same `run_id` would kill its sibling's box, which is safe **only** because `run_id` is unique per run; pin that assumption in a test. And the reaper must **not** treat stderr as the failure signal (C43: the idempotent success path writes `Error response from daemon` to stderr at rc=0) — check the return code.

**F7 — Secret-free env: strip-list or allowlist? — CLOSED by C27 + C44.** Settled in favour of the **positive allowlist**. C27 confirms the current strip removes exactly `{ANTHROPIC_API_KEY, FIREWORKS_API_KEY}` and inherits everything else — SIEM credentials, `GITHUB_TOKEN`, `SSH_AUTH_SOCK`, docker-context variables — so a denylist cannot assert O3 ("no secret is readable"), only "no *enumerated* secret". C44 removes the last argument for the denylist: **the box inherits no host environment by default**, so the allowlist is not an imposition but the path of least resistance — there is nothing to strip, only things to add. Build the box env positively from `DEFENDER_DIR`, `DEFENDER_RUN_DIR`, `DEFENDER_RUNS_BASE`, `PATH`, locale/TZ, and nothing else. **This is a correction to `RSD §The shape`**, which prescribes extending the key-strip; that direction should be struck. Note the denylist does not go away — `run_env`'s provider-key strip still governs host-side subprocesses — and the two must not be conflated.

**F8 — NEW. How is in-box/host path identity guaranteed when the driver itself runs containerized?** `RSD` rests a real argument on absolute-path identity (paths leak into `raw_command`, orient's workspace map, and artifacts), and O13 carried it forward. C46 shows it is **not automatically satisfiable** under docker-outside-of-Docker — which is how this repo is developed: bind *sources* resolve in the **host** namespace, and a source path absent there is **silently created as an empty directory** rather than erroring. So a DooD driver that binds its own view of `run_dir` gets a working container with an empty bind and no error. *Options:* (a) require the driver to run on the host (not containerized) and assert it at startup; (b) detect DooD and translate the bind source via the outer container's mount table; (c) drop the path-identity requirement and make in-box paths canonical, translating on the way out; (d) assert identity at startup with a sentinel — write a known file into `run_dir` from the host, require the box to read it back — and fail closed if it fails. *Recommendation:* **(d) as the immediate mechanism, deliberately not choosing between (a)–(c) yet.** The sentinel is cheap, it is the only option that detects the silent-empty-dir failure *as a failure*, and it converts a whole class of misconfiguration into one loud startup error — which is exactly M12's fail-closed posture applied to a failure mode M12 does not currently cover. (b) is the real long-term answer if the driver stays containerized, but it is unconverged and out of proportion to this issue. Whichever is chosen, note this fork interacts with F6: the sentinel check *is* a box-construction failure and should share its fail-closed path.

**F9 — NEW. How does the box executor distinguish infrastructure faults from program output?** O17/M16 state the obligation; the mechanism is genuinely undecided, because the available signal is heuristic. C39: Docker writes its own errors to **stdout with CRLF, stderr empty, rc=127**. C35: `exec -w <missing>` is also rc=127. C40: a `noexec` violation is rc=126. C43: a daemon/collision error is rc=125. So the return codes overlap with legitimate program exits (127 is also "command not found" *from the program's own shell semantics*, 126 also "not executable"). *Options:* (a) pattern-match Docker's error text on stdout (brittle, and the text is version-dependent); (b) treat 125/126/127 as infrastructure faults unconditionally (over-broad — a legitimate `command not found` inside a pipeline becomes an infrastructure error and the model loses a real, actionable signal); (c) avoid the ambiguity structurally: have the in-box entrypoint (`python3 -m defender.runtime.bash_exec`, M8) emit a **framed result** — a length-prefixed or sentinel-delimited JSON envelope on stdout carrying the program's real rc/stdout/stderr — so that *any* unframed stdout is by definition daemon text and the framing's absence is itself the fault signal. *Recommendation:* **(c).** It is the only option that is not a heuristic, it costs one small envelope in a module being written from scratch anyway (C51: `bash_exec` has no `__main__` today, so there is no legacy output contract to preserve), and it inverts the failure mode in the right direction — a mangled or truncated result is *detected* rather than silently handed to the model as data. It also composes with O7's byte-exactness requirement, since the envelope can carry an explicit encoding declaration rather than relying on the runtime's implicit transcoding. Note (c) does not remove the need to check rc for the *pre-exec* faults (a box that never started produces no envelope at all) — it makes those the residual case rather than the common one.
