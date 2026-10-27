# #1262 — shared workspace mapping for learning roles

Revision R1, approved through the implementation plan. Grounding base:
`5fb8d8fe18e3ee6560ba22d4a8d71c305aeca66d`.
Final implementation checks ran on the R1 working tree over
`4da7d1c8dc998bf5d9d5b60a9671d60e6040be4c`; the original grounding below remains valid.

## Principles

Inherits [engineering principles](../../../docs/principles.md). The owner's requirement
is that learning roles know they participate in the learning loop. This change is about
consistent workspace coordinates, not concealing that identity. One mapping mechanism
serves filesystem roles; permission grants and sandbox mounts retain separate ownership.

## Intent

- **O1 Coordinates:** Model-facing filesystem tools use declared, host-independent roots
  and an explicit working directory. Host-side permission checks and file operations
  resolve those coordinates through the same view.
- **O2 Extra roots:** A granted root outside the existing view requires an explicit model
  name before invocation. A root inside the view needs no additional name. Naming alone
  grants no access and creates no sandbox mount.
- **O3 Execution:** Learning shell commands use the same coordinates in sandbox and host
  fallback execution. Reads, edits and deletions operate on the authoritative tree.
  Arguments containing evidence, code or search patterns retain their literal bytes.
- **O4 Identity and boundaries:** Learning identity remains explicit. Existing confinement,
  write lanes, framing, wire-log refusals, sandbox requirements and batch lifecycle remain
  effective. Investigation paths retain the #1255 contract.

Non-obligations: investigator-style identity blindness for learning roles, rewriting
evidence or historical records, adding filesystem access to prompt-only roles, or changing
the oracle's separate scratch sandbox. No net line-count reduction is claimed.

## Design

`ModelView` owns immutable model/host root pairs and a model cwd. Its factories establish
these layouts:

| Context | Roots | Working directory |
| --- | --- | --- |
| Investigation | `/runs/current`, `/defender`, optional `/agent` | `/runs/current` |
| Learning author | `/workspace`, `/learning/current` | `/workspace` |
| Tenant draft box | `/defender`, `/draft` | `/draft/agent` |

The learning run mapping uses the actual invocation's run directory, which can be the
triggering investigation or a learning stage directory. Existing repo-relative operands
continue to resolve from `/workspace`. Explicit learning instructions accompany the view.

`RunScope.model_roots` declares additional coordinate mappings; `add_dirs`, `read_confine`
and the role's shapes continue to declare permission. Binding rejects unnamed external
roots. Model root overlaps and duplicate host roots are rejected; nested host roots use
the most specific root when rendering. Inbound mapping remains lexical so rooted file
operations and permission checks can refuse links and traversal.

Shared file tools map before permission checks and name the supplied model operand in
refusals. Scoped deletion rules accept the learning coordinates and verify the mapped
host operand. The lower-level operator policy API may still use host operands; this does
not create a host-path fallback at the model tool boundary.

`BoxRequest` retains host code roots for image selection and host work, alongside its
view. Container working directory, environment, mount targets and code-mount probes use
model coordinates. Learning stage directories remain map-only for existing host file
reads; the batch box retains its existing mount sources and writable overlays.

The permitted learning host fallback translates grammar-identified file operands and
the working directory to host coordinates. It does not stage a writable copy or rewrite
grep patterns. Investigation staging remains unchanged; tenant drafts still require a
sandbox. The draft factory covers sandbox geography; no new draft agent-binding flow is
introduced.

Independent review identified an initial fallback translation defect: absolute-looking
grep patterns were being translated. The implementation now uses the permission grammar's
file-operand extractors, with a regression requiring literal `/workspace` pattern matching.

## Grounding and verification

The original design-direction review and implementation interaction review were independent
of authoring and made no edits. Live Docker verification is recorded separately from
hermetic tool, transport and mount-rendering tests; passing the latter does not establish
live container behavior.

```yaml
claims:
  - id: C1
    kind: referential
    claim: "At the grounding base, learning authors anchor relative paths on the worktree."
    probe: "Read investigation/agent_definition.py bind and the two learning author definitions."
    probe_kind: read
    observed: "Both author definitions set anchors_on_tree; bind selects defender_dir.parent."
    verdict: holds
  - id: C2
    kind: referential
    claim: "The legacy drain box is shared across a batch, with writable trees owned by its lane."
    probe: "Read learning/core/drains.py _run_worktree_batch and _drain_box_request at the grounding base."  # lint-stale-ref: ok — a probe recorded at its grounding base
    probe_kind: read
    observed: "One box is created for the batch; mounts use label.writable_trees."
    verdict: holds
  - id: C3
    kind: referential
    claim: "Questioner and family judge deliberately carry no filesystem run scope."
    probe: "Read learning/branch/questioner/__init__.py and learning/judge/run.py at the grounding base."
    probe_kind: read
    observed: "Their deps are not AgentDeps subclasses; bind refuses them."
    verdict: holds
  - id: C4
    kind: behavior
    claim: "Learning tools use model coordinates across host layouts and workspace instructions leave the user message verbatim."
    probe: "At R1: flock /tmp/defender-pytest.lock .venv/bin/python -m pytest tests/runtime/engine/test_1262_learning_workspace.py tests/learning/core/test_hardening_772.py -q (cwd defender)."
    probe_kind: executed
    observed: "42 passed, including real host-fallback reads/deletions and the model instruction/user-message capture."
    verdict: holds
```

The executable regression suite is `tests/runtime/engine/test_1262_learning_workspace.py`.
Legacy framing and sandbox suites migrate model input spellings while retaining their
behavioral assertions. No stored-record migration or new external publishing action is needed.

Live mechanism confirmation used the production `_drain_box_request` and `start_box`, <!-- lint-stale-ref: ok — recorded at the grounding base; removed by #1108 P4 -->
with a temporary checkout carrying the execution modules and `MOUNT_CHECK`, and the
installed product image pinned in `BoxSpec`. Under `runc`, startup code/writable-mount
probes passed; `cat /workspace/defender/lessons/live.md | grep /workspace` returned the
literal matching content, a host file-tool write became visible in the sandbox, and
`rm /workspace/defender/lessons/created.md` removed the authoritative host file. The
executor reported sandboxed and its container was removed afterwards. `runsc` could
not be checked: the daemon rejected it as an unknown runtime. This is a verification
limit, not a change to production's runtime selection or fallback rules.

Final validation covered 4,483 broad regression cases across the broad run and its final
write-lane spelling repair (4,482 passed in the broad run; both tests in the repaired file
passed separately). The additional caller sweep passed 327 cases; its remaining policy
context and instruction-channel checks passed in the 42-case targeted rerun above.
Ruff, mypy (349 source files), all 34 CI custom lint gates, and the final prompt-framing
lint passed. Investigation view/replay, legacy learning framing, held mount ownership,
tenant startup probes and file-tool boundaries are included in those suites.
