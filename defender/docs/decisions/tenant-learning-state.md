# Tenant-owned learning state (#1186)

Design revision 3 implements #1120 D11, inheriting #1078 D6/D10 and the #1135
learning-state handle. Mutable learning records live at
`$DEFENDER_DATA_ROOT/<tenant UUID>/learning/`. Product Python code and the committed
lesson and query corpora keep their existing checkout locations. Moving curator
stage records out of learning state remains #1142.

`Tenant.learning` owns the location. Production code constructs `LoopPaths` with
`LoopPaths.for_tenant(accepted_tenant)` and accesses mutable records through
`LearningState`. Explicit scratch constructors require a `state_dir`; there is
no checkout default, global `DEFAULT_PATHS`, `loop_paths()` factory, or runtime
`DEFENDER_LEARNING_STATE_DIR` selector. Changing an author checkout preserves the
selected tenant and state root.

Run-end writers and lead authors obtain tenant identity from the run; the launcher
and judge use the accepted tenant carried by their run repository. Drains,
standalone lesson/questioner authors, the frontend, trace and revert commands
require an explicit tenant selector. A foreign-tenant curation request is
dead-lettered before author dispatch; valid same-tenant requests still run.

The tenant learning root must be an existing real directory when runtime opens it.
Existing and dangling root symlinks are refused, including when selected paths are
stored before the link is planted or rebound to another author checkout. Runtime
never creates the root. Explicit scratch handles retain their existing
resolve-once behavior. Normal investigation boxes mount the run, product source,
and tenant agent half; they do not mount tenant learning state.

Setup provisions an empty real learning directory when no migration source is
named. It never discovers old state. `tenant.py setup <T>
--learning-state-from <source>` adopts only the eight live state-root entries and
legacy `runs/` bundles, preserving unrelated source files. The inherited D10
protocol holds the learning locks, stages selected entries aside, copies across
filesystems, publishes by a directory rename, and deletes the aside after
publication. Matching adoption tokens support completion after interruption;
unknown partial copies, conflicting tokens, unrelated aside entries, overlap,
occupied destinations and held locks are refused. A recreated source record is
preserved and reported. File and directory modes/times and symlinks are retained;
root migrations also retain owners/groups. Migration requires quiescent writers.

The original executable contract is `8d550a4a019785abb08eeae5c5a3322a5dda0334`
on base `27a5d1fc4b2726907202471f9e30434269d784f3`. Reviewed repairs remain on
`contract/1186-repairs`, separately from production implementation. They correct
finished-tenant and explicit-scratch fixtures, preserve accepted-run producer
observations, and strengthen runtime API removal, stored-path root checks,
unknown-aside refusal, and selected-queue permission discrimination. Repair
requests were informed by implementation failures; the independent test author
did not inspect the honest implementation. The orchestrator reviewed each patch
before integration. Available GPT agents were used; Opus/Sonnet are unavailable.

Independent contract sampling used a detached worktree at the original contract,
without access to the honest implementation. It demonstrated a factory-only root
guard that passes the old configuration tests while stored paths read an outside
queue, and dynamic compatibility exports that bypass the old dictionary-only API
absence check. Those observations led to reviewed test repairs. The agent was
stopped by platform content review before completing its required pass. The
sampling is incomplete, and no full-gate adversarial verdict is claimed. A fresh
independent pass against the final repaired contract is required before readiness
for code review; this work must remain a draft until then.

Implementation-stage environment probes exercised physical cross-filesystem
migration as root and as an unprivileged user, directory metadata preservation,
complete destination publication, and refusal before mutation on an unwritable
source subtree. A real production `runc` investigation box read its mounted run
and agent controls while planted learning records were absent. `runsc` is not
installed locally, so the corresponding isolation check remains for CI or a host
with that runtime. Commands, observations, final check results, and contract refs
are recorded in the pull request.
