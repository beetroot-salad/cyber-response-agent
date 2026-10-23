# Issue 1108 P4 executable contract

Status: **ready for `write-code-from-tests`.** Tests, test fixtures and lint baselines only; no
production code. Almost every P4 case is red today on a missing seam (section 2). This file is
the whole record a code session needs; the working notes it was built from are not committed.

- Branch: `contract/1108-p4`. Base: `0f62791e` (origin/main, P1–P3 and #1186 merged).
- Contract identity: the commit that adds this file (it follows `72f9f2e7d`). The handoff names its SHA.
- Design: issue #1108 comment "#1108 P4 — the switch: current intent + design (r3, 2026-10-22)",
  sha256 `04283016b7fe7cbbe8ee53267b658af111fae0b79dfe3258df5fc3eb8b21efba`, plus **amendment A**
  (human, 2026-10-23, below). P3's amendments 2 and 3 stand except where r3 names otherwise.
- Shared machinery: `_support.py` (fixture tenant `knowledge/tenant-fixture/`, git-init plus a
  **real** P3 publish: `published_tenant`, `second_tenant`, `place_fixture`, `publish_placed`,
  `publish_once`, `bind_forge`/`unbind_forge`, pytest fixture `p4_tenant`), `_s_b_support.py`
  (run start, publish child, report-line vocabulary), `_drain_support.py` (drains, lanes, AppRole
  issuer fake, owner records). Lane helpers over P3 drafts: `support/learning/curation/_curator1134.py`
  (`DraftLane`, `draft_lane`), `_spec773.py`, `_lead_author_1134.py`.
- Run locally with `flock /tmp/defender-pytest.lock` and `PYTHONPATH=<worktree>`; affected files only.

## 1. Design identity

r3 obligations O1, O2, O-A, O-B, O-PIN, O4, O-TEXT, O5, O6, O7, O7b, O-STALE, O-WARN, O-SEE,
O-BUDGET, O8, O9, O-SWEEP, O-U5, O-U6, O11–O14, flows 1–7 and the agent default A-ID (the drain
logs in to OpenBao itself with AppRole). Human decisions U1–U8 are in r3; U9–U12 are amendment A; U13–U15 are the owner rulings of 2026-10-23 (below).

### Amendment A: the owner's rulings (U9–U12), at the scope the owner gave them

- **U9 (owner record): a stage subfolder.** A draft is `<T>/drafts/<id>/{owner, stage/{agent/, <token>}}`;
  a run copy is `<T>/run-knowledge/<run_id>/{owner, settings/, stage/{agent/, <token>}}`. The box
  mounts only `stage/` (exactly `agent/` + token), so the run box no longer sees `settings/`. Each
  is built as a dot-named temporary with the owner inside, then renamed into place. The owner is
  pid + process start time. This changes P3's committed draft-layout assertions.
- **U10 (refused claim):** the draft is reset; the refusal counts one attempt for that row; the row
  stays queued and is retried until #952's attempt ceiling quarantines it; the other claims in the
  batch proceed.
- **U11 (publish child with no valid report line** — crash, non-zero exit, empty or garbage output,
  spawn failure, unknown prefix): `stale:operator` ("publish child failed: <summary>") when a
  snapshot exists; with no snapshot the run refuses before message 0. Never fresh.
- **U12 (host-held knowledge record):** `knowledge_source` is written to a host-held record beside
  the run dir (as the ticket receipt is); the run page, the API and the ticket all read it; the raw
  reason stays host-side, never in the box-readable stamp.

### Owner rulings 2026-10-23 (U13–U15), at the scope the owner gave them

- **U13 (`validate_scaffold` spelling):** one spelling, `validate_scaffold.py <system> --tenant <T>
  --staged <dir>` (the staged directory agent-root-shaped), as `test_connect_propose.py` has it.
  `e2e/test_620_consumers.py` is re-spelled onto it with every case's assertions kept. No second
  flag (`--agent-dir`). Scope: the scaffold validator's command line only.
- **U14 (OD21 consequence):** the saved `runtime.html` (an operator page that may show the raw
  knowledge reason) must never become box-visible when a resume or branch re-binds a source run
  dir. Scope: what a box launched over a source run can read; the page stays an operator surface
  host-side. Test: `e2e/test_920_branch_resume.py::test_od21_a_resumed_box_sees_neither_the_source_run_page_nor_its_raw_knowledge_reason`.
- **U15 (tenant template catalog):** the tenant template ships an empty catalog; the implementer
  adds it. `tests/tenancy/test_1106_layout.py::test_the_templates_lead_zero_names_an_established_template_in_the_catalog`
  stays as written. Scope: the tenant template's `agent/` content.

### Agent decisions (binding for this contract; for the owner to confirm or change)

- **OD1** Run record `knowledge_source: {kind: fresh|stale|pinned, commit, reason, stale_kind:
  transient|operator|null}`; `stale_kind` non-null iff stale.
- **OD2** `run.main(publish=)` returns the child's report line: `fresh <commit>`,
  `stale:transient <reason>`, `stale:operator <reason>`; S-B adds `misconfigured <reason>` (refuse,
  even with a snapshot).
- **OD3** (superseded by U12) ticket got the value in-process; the keyword seam is withdrawn and the
  ticket reads the host record.
- **OD4** One login symbol: `version_control.issuer_login(tenant, *, issuer_config, transport=None)
  -> ForgejoIdentity`; drains, the publish child and `tenant.py update` use it.
- **OD5** `_spec1224.launch`/`Estate.place` build through the real publish helper and stamp the real commit.
- **OD6** Corpus paths are `agent/<corpus>`; `KnowledgePaths(agent_root)` takes no `agent_rel`;
  `of_defender_dir` survives only in the judge's pre-move branch; commit/ChangeSet/handoff paths are
  repo-relative `agent/...`.
- **OD7** `tests/conftest.py::tmp_repo` stays for product-shaped needs; corpus lane tests use a draft.
- **OD8** The writer lease (amendment 3's state=open listing) stays and is covered on both drains.
- **OD9** A branch launch over an `unversioned`/`unavailable` source stamp refuses, even with `--allow-dirty`.
- **OD10** `held_out` resolves `current` once at index creation, records it, and pins every launch of that index to it.
- **OD11** O-BUDGET parent half: the launcher takes `budget=`/`command=`; the child's locked phase has one injectable slow point.
- **OD12** Legacy-test classes: (i) pins only a mechanism P4 removes → delete with a pointer;
  (ii) pins another issue's live obligation → re-spell onto P4 seams; (iii) incidental → leave.
- **OD13** (resolved) `_tenants1106.run_tenant`'s signature-sniffing pre-P4 fallback is removed.
- **OD14** In-process `run.main` callers pass `publish=`; only the CLI binds the real child.
  `_spec1222.run_alert` passes `publish_double` (`fresh <commit>`, or `stale:operator` for a refused planted tenant).
  Clarified 2026-10-23 (for the owner to confirm): the real run command always launches the real
  publish child by default (`publish=` omitted means the real child); only in-process callers
  pass a `publish=` stand-in.
- **OD15** A claim's ChangeSet is draft vs batch base, the draft re-synced per claim; no "pre-run stray tolerated" baseline.
- **OD16** Lane entries take `batch=`; drains hand the tick's batch to triggers and steps; `LoopPaths` stays product-rooted.
- **OD17** The provenance stamp keeps the knowledge commit (O-B) and may carry `knowledge_source
  {kind, commit, stale_kind}` classed informational, never the reason; the host record is
  authoritative for every reader.
- **OD18** U10's scope is ChangeSet/commit-maker refusals only (link, FIFO, device, out-of-lane path,
  forbidden name, oversized). Lane-gate content rejections keep each lane's existing rule.
- **OD19** A tick whose only claim was refused returns rc 0.
- **OD20** The child exits 0 for every outcome it reports, on one line; non-zero means failed (U11).
- **OD21** The saved `runtime.html` is written after the box stops, is an operator surface, and may
  show the raw reason; "never box-readable" covers the box window and non-page files.
- **OD22'** (replaces OD22) Fail closed only where a record should exist. No run → API `knowledge`
  null. Pre-P4 run (no record, no `knowledge_source` in the stamp) → no page banner, today's ticket
  comment, API null. Missing record with a stamp, or a corrupt record → stale/operator "knowledge
  record unreadable", no commit, on page, ticket and API.
- **OD23** ChangeSet derivation precedes attribution (amendment 2 O-D), so a link lesson in the lane
  is a U10 refused claim (rc 0, one attempt, held), not an rc 2 unattributable lesson.
- **A-MISMATCH (refined)** `current` advances only by fast-forward under the lock, so the copy is the
  child's reported commit or a descendant: record fresh at the copied commit, keeping the reported
  commit in the host record. No non-descending stale case is tested. A rewound origin is
  `stale:operator` with `current` unmoved (fast-forward-only pin).
- **Test-only exclusion (REPLAY-WT)** `_tenants1106.run_tenant`'s defaults (`tenant.agent`/
  `tenant.settings`, the clone working tree) stay for ~34 unit-level files passing their own tenant;
  replay and run paths use exports.

## 2. Assumed seams the implementer provides

Spelled as the tests call them. One line each; the test file named holds the full doc.

**Run start and the publish child** (`_s_b_support.py`, `test_run_start.py`, `test_publish_child.py`)
- `run.main(argv, *, publish=...)`: called once per unpinned launch with identifiers only (tenant id, data root); returns a report line.
- `run.py --knowledge-commit <sha>`: starts on `<T>/exports/<sha>/`, skips publish; refuses `../current`, `current`, a short id, and a commit with no export, before the box (not by argparse).
- `run.launch_publish(tenant_id, *, data_root, budget=60.0, command=None, spawn=None) -> str`: default budget 60.0; `spawn` has `subprocess.Popen`'s signature (`test_publish_child.py:683`); waits for the network phase only; never kills a child holding the tenant lock.
- `version_control.publish_for_run(tenant_id, *, data_root, issuer_config, client=None, issuer_transport=None, identity=None, network_timeout=None) -> str`: reads the forge binding and config itself; misconfiguration decided before any network call.
- `version_control.publish_child_main(argv, *, issuer_config=None, client=None, identity=None, network_timeout=None, locked_hook=None) -> int`: `locked_hook` called once under the tenant lock before the clone is touched; rc 0 for every reported outcome (OD20).
- Report-line vocabulary: `fresh <commit>` / `stale:transient <reason>` / `stale:operator <reason>` / `misconfigured <reason>`; the reason is one line; U11 line `stale:operator publish child failed: <summary>`.
- Run copy layout `<T>/run-knowledge/<run_id>/{owner, settings/, stage/{agent/, <token>}}`, removed in `finally`; box mounts `stage/` read-only; startup reads the token back; `DEFENDER_AGENT_DIR=/agent`.
- `RunPaths(run_dir).knowledge_source(runs_base=None) -> <runs base>/<run_id>.knowledge-source.json`, JSON `{kind, commit, stale_kind, reason}` (host-held; U12).
- Stamp `knowledge_source` limited to keys `{kind, commit, stale_kind}`; `STAMP_FIELD_CLASSES["knowledge_source"]` is informational (`test_1204_family_knowledge`).
  The stamp "may carry" it (OD17): `RunProvenance(...).as_json(knowledge_source=<mapping>)` writes the key with exactly those
  three keys (never `reason`); `as_json()` without it omits the key (repair r4, F1).

**Delivery API** (`defender.learning.author.version_control`)
- `issuer_login(tenant, *, issuer_config, transport=None) -> ForgejoIdentity` (`test_live_dev_issuer.py` omits `transport=`; it is a superset, not a conflict).
- Issuer client config: JSON `{"issuer", "ca_cert" (PEM path), "role_id", "secret_id"}`, `issuer.json` under `<repo>/playground-issuer/client/` in dev; identity endpoint `<issuer>/v1/identity/oidc`.
- Tenant row forge binding: `<T>/tenant.json` `forge: {origin, audience, issuer_role}`; origin required even with an injected identity.
- `materialise_export(tenant, commit) -> TenantExport`: no identity/client/origin; refusals `DeliveryRefused`, lock still busy after a bounded retry (assumed ≤60 s) `LockBusy`.
- Draft layout `<T>/drafts/<id>/{owner, stage/{agent/, <token>}}`: `batch.draft_root` is `stage/`; `batch.box_request().workdir` is `stage/agent`.
- Owner record: JSON `{"pid": int, "start": <`/proc/<pid>/stat` field 22, compared as text>}`; same pid with another start = dead; publish sweeps dead owners under the lock.

**Drains and lanes** (`_drain_support.py`, `_curator1134.py:482`)
- `author_drain(paths, *, trigger_author=, client=, identity=, issuer_config=, issuer_transport=, start_box=, stop_box=)`; `branch=`/`scrub=` gone; drain refusal exit 2.
- `lead_author_drain(paths, *, run_lead_author=, run_pitfalls=, client=, identity=, issuer_config=, issuer_transport=, start_box=, stop_box=, git_timeout=)`.
- `trigger_author(paths, state, channel, threshold_env, module_name, pending_label, *, batch, box, ...)`; extra keywords forwarded to the config builder.
- Drain steps: `run_lead_author(paths, state, run, *, batch, box, on_done, ...)` and `run_pitfalls(paths, state, *, batch, box, on_curated, ...)` (the drain's wrapper, today `_invoke_pitfalls`; distinct from the curator function below).
- `open_drain_trees(paths, label, *, batch)`: holds the lanes under `batch.draft_root`.
- Lane builders: `lessons_run.build_author_config(paths, *, state, trees, batch, ...)`, `questioner_run.build_questioner_config(...)`, `lead_author.build_lead_author_deps(paths, *, state, trees, batch, ...)`, `pitfalls_curator.run_pitfalls(*, paths, state, trees, batch, ...)`, `lead_author.run(run, *, label, paths, batch, ...)`.
- `run_under_held_queue_lock(run, *, paths, state, trees, box, on_done, git_timeout=, deps=None)`.
- Gate shapes kept: `_skills_path_rule(root, xy, path, *, systems, tree_for)`, `_verify_skills_state(root, *, change_set, ...)`, `_verify_pitfalls_state(root, *, ...)`; rules see repo-relative `agent/...` (OD6).
- Pitfalls add-on path: `agent/skills/gather/defender-sql.pitfalls.md` (product page is never a tenant write).
- `evaluations/harness.py::run_author(tmp, *, invoke_agent=None)`: drafts plus the drain tests' fake forge, no issuer.

**CLIs**
- `cli/tenant.py`: `update(tenant_id, *, client=, identity=)`; `propose(tenant_id, staged, *, client=None, identity=None) -> int` (add/replace only, `agent/` only, refusals `[tenant.py] ...`); `check_tenant(tenant_id)` reports trail behind `origin/main` and the last publish refusal (O-SEE).
- `cli/learning/revert_lesson.main(argv, *, client=None, identity=None, issuer_config=None, issuer_transport=None)`; drain lock still exit 3.
- `validate_scaffold.py <system> --tenant <T> --staged <dir>`: the skill and template checks read the staged (agent-root-shaped) directory, the adapter checks the code tree (`DEFENDER_DIR`). `--tenant` exists today; `--staged` is the missing flag (U13).

**Readers and run tenant**
- `runtime.run_tenant.resolve_run_tenant(settings_root, *, agent_root, dispatches_lead_zero)`; `RunTenant(..., agent_root=, settings_root=)` whose `.agent`/`.settings` are those roots; `resolved_settings(tenant, *, settings_root=)`.
- `KnowledgePaths(agent_root)` without `agent_rel`; `deps.knowledge.agent_root` is the run's agent root.
- `serialize.build_view(agent_root=)` (posture page; groups `{defender, questioner}`).
- `record_lesson_load.lesson_name(path, agent_root=)` (recognised by the served run copy).
- `tools_gather._template_index(knowledge, system, verb_grant, view=None)`.
- `lessons_push.corpus_dir(deps)` from the deps' tenant agent root, not `of_defender_dir`.
- `defender-lessons` and the lessons engine read `$DEFENDER_AGENT_DIR/lessons` on every lane.
- Judge: `git_show(cwd, rev, path)` stays its only product-repo reader (pre-move test and body read).
- `_replay_harness.drive(..., agent=)` / `_default_tenant`: the run gets `<T>/exports/<commit>/{agent,settings}`.

**Store and API**
- `InMemoryStore.add_run_knowledge(tenant_id, investigation_id, record_text: str | None, *, stamp_knowledge_source: Mapping | None = None)`: `(None, None)` → `knowledge` null; `(None, present)` → stale/operator, commit null; unparseable → stale/operator, commit null; a record → the record→wire mapping.
- `Investigation.knowledge: {status: current|stale|pinned, commit, stale_kind}` (fresh→current).

### Open items in the seams

- **`validate_scaffold` spelling conflict: resolved by owner ruling U13.** The S-D spelling
  `<system> --tenant <T> --staged <dir>` stands; the 10 `e2e/test_620_consumers.py` cases (formerly
  `--agent-dir`) are re-spelled onto it, naming a set-up tenant under a data root of the
  scaffold's own and keeping `DEFENDER_DIR` for the code tree. Their assertions are unchanged.
- `launch_publish(spawn=)` is used by `test_publish_child.py` but absent from `_s_b_support.py`'s docstring; the test is authoritative.
- Two `run_pitfalls` symbols exist by design (drain step vs `pitfalls_curator.run_pitfalls`); not a conflict.
- `run.main`'s default when `publish=` is omitted: the real publish child (OD14 clarification; agent decision for the owner to confirm).
- **`declared_systems` marker half (open, repair r4 item 14).** `learning/catalog/test_869_resolver.py` (4 cases) calls
  `declared_systems(repo)` and expects the marker half read from `repo`'s committed HEAD at `defender/skills/<name>/execution.md`
  (depth one; raises when the skills tree or the repo is unresolvable). P4 moves the markers to the tenant (`agent/skills/<name>/execution.md`,
  O1) and no seam here names how the resolver gets the tenant's committed tree. The implementation took
  `declared_systems(repo_root, *, agent: Mapping | None = None)` (`agent`: a committed tree's repo-relative paths, e.g. `Batch.base`;
  none given, the adapter half alone). Not respelled: the committed-vs-working-tree and unresolvable-marker halves move to the caller
  that builds `agent`, which no test here pins yet. Owner call: adopt that seam in this section and respell the 4 cases onto it
  (plus a lane-level case that the gate hands the batch base, never the draft), or name another seam.

## 3. Coverage map

Files are under `tenant_1108_p4/` unless a path is given.

- O1 layout allowlist → `test_layout.py`, `tests/learning/retrieval/test_corpus_fold_584.py`, `test_lessons_frontend.py`, `tests/tenancy/test_1108_knowledge_owner.py`
- O2 one tenant, one revision, every surface → `test_run_isolation_e2e.py`, `test_run_copy.py`, `tests/runtime/permissions/test_permission.py`, `runtime/engine/test_read_confine_bash.py`, `test_gather_template_discovery.py`, `e2e/test_gather_template_index.py`, `alert_front_door_1222/test_1222_lessons_and_corpus.py`, `layout_contracts/test_1080_*`, `invlang/validation/test_frontier_recall_919.py`
- O-A box mounts stage only, token read-back, in-box `.tenant-id` retired → `test_run_copy.py`, `test_run_start.py`, `tenant_1108_p2/test_run_start.py`, `e2e/test_1106_box_mount.py`
- O-B one export commit for settings/knowledge/stamp → `test_run_start.py`, `test_branch_replay.py`, `e2e/test_1106_run_start.py`
- O-PIN `--knowledge-commit`, branch siblings, held-out → `test_run_start.py`, `test_branch_replay.py`, `test_held_out_pinning.py`, `storage/ids_1187/test_1187_held_out.py`
- O4 symbol census → `test_census.py`, `tests/tenancy/test_1108_knowledge_owner.py`
- O-TEXT model-facing spellings → `test_model_text.py`, `test_connect_propose.py`
- O5 lesson load recorded → `test_lesson_load.py`, `learning/retrieval/test_record_lesson_load.py`
- O6 judge pre/post-move, unreadable → `test_judge_bodies.py`, `learning/judge/test_921_render.py`
- O7 all corpus writes via TenantDelivery, legacy delivery deleted → `test_writers.py`, `test_drains.py`, `test_revert_cli.py`, `test_connect_propose.py`, lane suites (#773/#869/#870/#1134/lead author/pitfalls)
- O7b merged PR read or recorded stale → `test_publish_child.py`
- O-STALE child classification → `test_publish_child.py`, `test_run_start.py`, `learning/branch/test_1204_family_knowledge.py`
- O-WARN page/ticket/API → `test_stale_visibility.py`, `test_run_page.py`
- O-SEE `tenant.py check` → `test_tenant_cli.py`
- O-BUDGET child and parent halves (real subprocesses) → `test_publish_child.py`
- O8 login material host-side only → `test_publish_child.py`, `test_run_start.py`, `test_run_copy.py`, `test_drain_credentials.py`, `test_dev_compose.py`
- O9 refusals named, misconfiguration before model → `test_drain_credentials.py`, `test_drains.py`, `test_publish_child.py`, `test_run_start.py`
- O-SWEEP owner records, dead-owner sweep → `test_drains.py`, `test_run_copy.py`, `tenant_1108_delivery/test_batches.py`
- O-U5 retired corpora gone → `test_layout.py`, `test_lessons_frontend.py`
- O-U6 no lesson-history panel, no git in presentation → `test_layout.py`, `test_run_page.py`
- O11 machinery, `publish=` seam, real-publish fixture → `test_support_selfcheck.py`, `test_run_start.py`
- O12 dev OpenBao auto-unseal, live delivery → `test_dev_compose.py`, `test_live_dev_issuer.py` (live)
- O13 Forgejo bind mount survives `down -v` → `test_dev_compose.py`, `test_live_dev_issuer.py` (live)
- O14 lab continuity → `test_cutover.py` (live; red until F-CUT is done)
- Flow 1 publish → `test_support_selfcheck.py`, `test_publish_child.py`
- Flow 2 materialise → `test_materialise.py`
- Flow 3 run start → `test_run_start.py`, `test_run_copy.py`, `tests/tenancy/test_1106_layout.py`, `e2e/test_1106_run_start.py`
- Flow 4 drain → `test_drains.py`, `test_refused_claims.py`
- Flow 5 revert → `test_revert_cli.py`
- Flow 6 connect → `test_connect_propose.py`, `e2e/test_620_consumers.py`
- Flow 7 branch replay → `test_branch_replay.py`
- A-ID drain AppRole login → `test_drain_credentials.py`, `test_live_dev_issuer.py`
- U9 stage layout → `test_run_copy.py`, `test_drains.py`, `test_run_isolation_e2e.py`, `tenant_1108_delivery/test_batches.py`, `tenant_1108_delivery/test_box.py`, `e2e/test_1106_box_mount.py`
- U10 refused claims (OD18/19/23) → `test_refused_claims.py`, `learning/curation/test_1134_curator_drain.py`, `test_773_commit_list.py`, `test_lead_author.py`
- U11 broken child (OD20) → `test_publish_child.py`
- U12 host record (OD17/21/22') → `test_stale_visibility.py`, `test_run_page.py`, `test_run_start.py`
- U14 (OD21 consequence) resumed box never sees the source's `runtime.html` or its reason → `e2e/test_920_branch_resume.py::test_od21_a_resumed_box_sees_neither_the_source_run_page_nor_its_raw_knowledge_reason`
- Also: P4 wiring (delivery has production callers outside the run process; replaces P3's dormancy ban) → `tenant_1108_delivery/test_architecture.py`.

## 4. Migrated existing suites

About 160 existing files were rewritten onto the fixture tenant, published exports and P3 drafts.
A case was deleted only under OD12 class (i). Each deletion leaves a comment in its file naming
the successor test (search the file for `OD12` or `#1108 P4`). Class (ii) cases keep their
assertions on the new seams.

Wholly deleted files and their successors:
- `e2e/test_local_box_command.py`: pinned the in-box `.tenant-id` read and `AgentReadDocker`; → `test_run_copy.py` (that check no longer runs). Its incidental concern (a host stand-in must not depend on inherited `PYTHONPATH`) is not re-pinned.
- `learning/curation/test_1134_curator_git_bounds.py` (27 cases, git over a writable worktree) → P3 ChangeSet refusals and `tenant_1108_delivery/test_network.py` stalled-forge timeout.
- `learning/curation/test_1134_curator_git_compare.py` → P3 ChangeSet byte comparison and reset (one case moved to `test_1134_curator_drain.py`).
- `learning/curation/test_1134_curator_v3_holes.py` (drain-internal restore) → P3 reset and ChangeSet tests.
- `learning/curation/test_1175_claim_session.py`, `test_1175_adversary_holes.py`, `test_1175_leads_git_liveness.py` → P3 `test_batches.py`/`test_changes.py`/`test_change_set_fuzz.py` and `tenant_1108_p4/test_writers.py`.
- `learning/curation/test_1175_adversary_r2.py`, `test_1195_worktree_batch.py`: pinned legacy worktree delivery; successors are the same P3 batch/change tests and `test_drains.py`. The pointer here is thin.
- `learning/retrieval/test_corpus_split.py`: validated `lessons-actor`/`lessons-environment`, deleted by U5; no successor.

Deleted in the post-implementation contract repair (r2, OD12 class i):
- `learning/curation/test_drain_byte_identity.py` (2 cases): pinned only `drain._byte_identical_to_head`, the checkout-HEAD byte comparison P4 removes → the ChangeSet compares the draft's raw bytes with the batch base's blobs: `tenant_1108_delivery/test_changes.py::test_change_set_is_the_draft_against_the_batch_base_and_commits_as_plain_files`, `::test_the_commit_maker_stores_the_boxs_bytes_whatever_mains_attributes_say`, `::test_claim_after_claim_the_box_sees_exactly_the_committed_bytes` (eol=crlf).

Deleted (OD12 class i) or re-spelled in contract repair rounds 1–2 (merged as r1–r3); each site carries a pointer comment:
- Deleted, class (i):
  - `learning/curation/test_drain_byte_identity.py` (whole file, above).
  - `learning/stages/test_frames_680_lifecycle.py::test_revert_lesson_driver_holds_shared_author_lock_and_calls_through` (`revert(branch=)`)
    → `test_revert_cli.py::test_flow5_revert_cli_opens_a_revert_pr_on_the_tenant_forge_deleting_the_agent_lesson`, `::test_flow5_revert_cli_waits_out_a_running_author_drain`.
  - `tenant_1108_delivery/test_forgejo.py::test_the_writer_lease_is_not_held_by_a_fork_pr` (lease on `AuthorBranch`)
    → `test_drains.py::test_od8_an_open_tenant_pr_of_the_lane_holds_the_writer_lease_and_nothing_else_does` (`_LEASE_ROWS`, both drains).
  - `learning/curation/test_curator_glm_engine.py::test_marker_commit_message_with_trailer_rejected` (`commit_corpus` trailer guard; the commit-maker composes none);
    the result's commit message stays pinned by `::test_marker_empty_commit_message_rejected`.
  - `learning/curation/test_drain719_hardening.py::test_a_git_failure_in_a_read_only_probe_does_not_spend_an_attempt` (`GitProbeError` over a worktree index)
    → `tenant_1108_delivery/test_changes.py::test_change_set_is_the_draft_against_the_batch_base_and_commits_as_plain_files`. Its infra-fault half is open: §6 L1.
  - `learning/curation/test_drain719_config.py`: the third leg (a write under the checkout's `defender/learning/` seen as a stray)
    → `test_changes.py::test_a_claim_holding_anything_but_in_lane_regular_files_is_refused_whole`.
  - `learning/curation/test_curator_glm_survival.py`: the staged-index half (unrelated staged work not swept into the commit)
    → `test_changes.py::test_change_set_is_the_draft_against_the_batch_base_and_commits_as_plain_files`.
  - `tenancy/test_1204_knowledge_revision.py`: the six `materialize_run` clone-stamp cases (versioned, plain-copy `unversioned`, unreadable `.git`,
    two read-fault rows, fork sibling) → `test_run_start.py::test_o_b_the_stamp_is_the_export_copied_never_the_clones_head`,
    `::test_o11_o_b_...`, `::test_o_a_no_current_and_a_failed_publish_refuses_before_message_zero`, `::test_o_pin_...`, `test_branch_replay.py::test_flow7_...`,
    `::test_o_b_the_live_capture_...`; the arm's no-lineage fields → `storage/ids_1187/test_1187_roster_sibling.py::test_natural_and_arm_stamps_carry_no_world_lineage`.
  - `learning/branch/test_1204_family_knowledge.py`: the two `--allow-dirty` waiver rows for an `unversioned`/`unavailable` source (OD9)
    → `test_branch_replay.py::test_od9_a_source_with_no_knowledge_commit_refuses_naming_why_even_with_allow_dirty`.
  - `learning/retrieval/test_1195_lessons_run_windows.py`: the `before-the-run` rows (a pre-run stray tolerated, OD15)
    → `test_changes.py::test_change_set_is_the_draft_against_the_batch_base_...`, `::test_claims_commit_and_reset_one_after_another_within_one_batch`.
  - `e2e/test_771_write_backstop.py`: the planted-component case and the leaf-alias case of `drain._restore_corpus`
    → `test_changes.py::test_a_claim_reset_resyncs_the_draft_and_never_follows_box_links`.
  - `tooling/layout_contracts/test_1080_episode_frontend_and_pricing.py::test_1080_values_derived_from_a_moved_files_location_resolve_as_before`:
    the `lessons_fm` `REPO_ROOT` cell → `learning/retrieval/test_lessons_fm.py`.
  - `tenancy/tenant_1120_piece1/test_1120_check.py::test_1159_check_says_this_machines_git_failed_and_exits_1`: the half pinning that the grant
    census goes blind with git (the census no longer starts git); r4 pins the converse (no census-not-taken line, no git cause).
- Re-spelled, class (ii), assertions kept or made stricter: `test_1178_run_gate.py` link/out-of-lane rows (`LeadAuthorError` → `DeliveryRefused`, OD18/OD23),
  exec rows (mode 100644, P3), the two "larger than any read commits" cases → `..._is_refused`; `test_1134_lead_author_adversary.py` link rows
  (`DeliveryRefused`); `test_1134_curator_drain.py` hard-linked base lesson → refused claim (owner ruling 2);
  `test_frames_680_lifecycle.py::test_lead_author_bash_reads_cross_agent_artifact` onto a batch-draft scene; `test_1195_lessons_run_windows.py`
  out-of-lane stray rows → refused claim (`test_a_stray_the_box_writes_outside_the_lanes_once_started_is_a_refused_claim`);
  `test_curator_manifest.py::test_p4_both_callers_forward_the_abs_corpus_path` over a draft; `tenancy/test_1204_knowledge_revision.py`'s pointer.

Repair round r4 (this round), all additive or stricter:
- `learning/branch/test_1204_family_knowledge.py::test_1204_the_stamp_table_classes_every_record_field_exactly_as_d4_states`: the table is the
  bare record's wire keys plus the one optional `knowledge_source` (OD17 "may carry"), whose class and carried keys are asserted (F1).
- `test_run_start.py::test_o_b_a_broken_tenant_clone_does_not_stop_the_run_or_reach_its_stamp` (gitfile to nowhere, `.git` removed, uncommitted edit; F3).
- `test_1120_check.py` git-absent V16 loop: no census-not-taken line and no census git cause (F4).
- `runtime/state/test_1255_clock_box.py`: the run copy's stage is told by source prefix (one mount or several), and the mounts set aside are only
  the agent and token mounts, read-only, each kind once (F5).
- `tenant_1108_delivery/test_changes.py`: LF→CRLF rewrite of an existing lesson is a change of those bytes; a chmod-only edit is none (R-4);
  `_REFUSED_OUTPUT` gains `hardlink-to-host`, `hardlink-in-lane`, `replace-file-with-hardlink`, `replace-file-with-hardlink-same-bytes`, and the
  refused-whole reset asserts every draft file single-linked (L3, owner ruling 2).
- `test_refused_claims.py`: lead claim refused for an out-of-lane path; pitfalls claim refused → rc 0, one attempt, dead-lettered at the
  ceiling naming `DeliveryRefused` (with its unrefused control) (L4).
- Support: `_tenants1106.plant_census_catalog(folder)` plants the lead-zero template into each tenant folder's `agent/skills/gather/queries/` (R-2);
  `_spec1107.plant` re-plants in place keeping `.git`, and the publish stand-in `_launch_publish_p4` fails a lost `.git` (`pytest.fail`) instead of
  starting the remote anew, and reads `LockBusy` as `stale:transient` (R-3); the fixture tenant ships
  `agent/skills/tacit-knowledge/SKILL.md`, re-asserted by `tenancy/test_tacit_knowledge_registry_983.py` (R-5).
- Older suites reading the product content P4 deleted (item 13), re-spelled, nothing deleted: `invlang/validation/test_lessons_frontier_scale_935.py` (4)
  and `learning/retrieval/test_986_container_lesson_recall.py` (7) rank against the pre-P4 shipped lessons, now the committed test fixture
  `tests/fixtures/pre-p4-shipped/agent/` (byte-identical to base `0f62791e`; helper `support/shared/_pre_p4_shipped.py`);
  `invlang/validation/test_frontier_shared_walk_930.py`'s straddle case recalls from the run copy's `agent/lessons`;
  `integrations/test_scaffold_rules_901.py`'s template sweep covers every committed `knowledge/*/agent` catalog plus that fixture's (which carries
  the `_draft`); `learning/curation/test_tacit_registry_authoring_991.py` gates the fixture tenant's and the pre-P4 registry and reads its worked
  example from the pre-P4 copy; `tooling/layout_contracts/test_1080_lints_and_pointers.py::test_staying_commands_import_modules_that_have_moved`
  runs `tacit_cli check --defender-dir knowledge/tenant-fixture/agent` (an agent root under the existing flag; not yet named in §2).
- Deleted with production code the cleanup removed (OD12 class i):
  - `shared/process/test_git.py`: the `git_rev_list_count` half of the head-sha case, `test_git_commit_pathspec_scoped_and_trailers`,
    `test_git_commit_no_op_returns_none`, `test_git_worktree_add_remove`, `test_git_worktree_add_branch`, `test_git_push_sets_upstream`,
    `test_git_fetch_advances_tracking_ref` (callers were `AuthorBranch` and the legacy drains) → `tenant_1108_delivery/test_changes.py`,
    `test_delivery.py::test_finish_pushes_the_commit_maker_branch_and_opens_its_pr_without_product_write`, `test_publish.py`.
  - `e2e/test_771_lifecycle_and_scope.py::test_a_quarantined_tainted_tree_carries_its_verdict_beside_the_archive` and its driver
    `_spec771.quarantine_a_tainted_tree` (`quarantine.preserve_tainted_tree`, whose only caller was `AuthorBranch`): no successor, §6 owner item.
  - Dead support `support/learning/curation/_claim1175.py` (imported the deleted `defender._claim_git`; its suites were deleted with the contract).
- Re-spelled with the cleanup: `tenant_1120_piece1/test_1120_operator_commands.py::test_1186_learning_operator_cli_uses_the_explicit_tenants_lock`
  rows for `lessons/run.py` and `questioner/run.py` now meet `.author-drain.lock` ("another drainer holds the lock", rc 0), as those commands run the
  author lane's tenant batch; census rows naming the deleted `version_control/restore.py` dropped (`e2e/_spec771.py`, `_census1134.py`);
  `_census_1107.py`/`test_1107_census_lint.py` homonym docs pruned to `skills/connect/SKILL.md` (the others moved to tenants);
  `tooling/layout_contracts/_pointers1080.vanished_folder_mentions` counts a name live in a tenant's agent half (`agent/lessons/`) as ambiguous,
  so a bare `lessons/` is not a stale pointer; stale-name test data reworded or suppressed with a reason (`lint_stale_refs` clean).

Collateral still naming deleted files: `tests/_shard_weights.json`, `learning/state_contracts/rewritten_tier_map.yaml`.

## 5. Expected reds and masking

- Nearly every P4 case fails today on a missing seam from section 2. A red for any other reason is a broken test.
- **Masked, must go green unchanged once the seam exists:**
  - about 190 #1222/#1243/#1256 drive cases, behind `run.main(publish=)` (`_spec1222.run_alert`);
  - 81 replay cases, behind `resolve_run_tenant(agent_root=)` (82 with the U14 resume case, which
    passes on base `0f62791e` and turns red when the page is carried into the sibling);
  - about 10 run-page and 26 ticket cases, behind `resolve_run_tenant(agent_root=)`.
- **Never run against a stand-in:** the run-page cases, the host-record cases, and the box-tamper cases (stamp forged during the box window). Check that they reach their own assertions.
- Controls that pass today only because the seam fault is dead-lettered (the U10 `gate-rejection`/`unrelated` lead controls) become meaningful after P4.
- `test_1106_layout::test_the_templates_lead_zero_names_an_established_template_in_the_catalog` is red by **owner ruling U15**: the tenant template ships an empty catalog; the implementer adds it. Not a seam; the test stays as written.

## 6. Known gaps (not covered)

- (low) Run copy removal on the UNSERVABLE exit path.
- (minor) Routing of a commit-maker ref-lock (`update-ref`) fault. Not a content refusal; only #773 M5 is pinned (branch unmoved, nothing lands, nothing consumed).
- **(open owner decision, L1) Does an infrastructure fault in a claim spend an attempt?** Reproducer: `Batch.change_set` raising
  `GitError("index.lock contention")` on its second call with `max_attempts=1` → `run_batch` rc 0, the row dead-lettered
  `refused-claim: git update-ref failed`: the implementation folds infra faults into `DeliveryRefused` (`version_control/model.py` `_refusals()`),
  so U10's one-attempt rule spends the row's attempts on a fault that is not the claim's. The case that pinned "a git failure in a read-only
  probe does not spend an attempt" (`learning/curation/test_drain719_hardening.py::test_a_git_failure_in_a_read_only_probe_does_not_spend_an_attempt`)
  was deleted with `GitProbeError`. U10/OD18 scope refusals to content; nothing decides the infra case. Not tested either way.
- **(open owner item) No production writer preserves a tainted tree for forensics.** `quarantine.preserve_tainted_tree` was deleted with
  `AuthorBranch`, its only caller; the case pinning the verdict beside the archive was deleted with it (§4). Decide whether a draft whose
  claim is refused for a box-planted entry should be archived before the reset.
- (minor, TRI-3) The author-drain half of the deleted `test_1179 ... non_member_raises_before_any_batch_work`; the label is an enum.
- (accepted, test-only) `_tenants1106.run_tenant` defaults to the clone working tree for unit-level callers (section 1).
- The API reading the host record is enforced only through the stub seam `InMemoryStore.add_run_knowledge` until a real store exists; the design text should say so.
- Census residuals: tuple-unpack/loop targets, computed names, `importlib`/`getattr`/aliases, call-time joins, extension-less shims; mitigated by the O1 layout test and behavioural clone-unreadable checks. Also: no `ls /agent` control on the listing check, and the reason needle is an exact match.
- Budget tests use real subprocesses and wall-clock bounds, so they may flake under load.
- `declared_systems` split-root gap: 4 `@sys` folder-gate cases in `test_1134_lead_author_holes.py`.
- Evals `expect.json` assertions are vacuous until the harness resolves against a draft.
- `Investigation.knowledge` nullability for queued/running investigations (G-C3).
- (closed by owner ruling 2) F-HARDLINK P3 half: a regular file with nlink>1 in a lane refuses the claim whole and the
  reset leaves every draft file single-linked: `tenant_1108_delivery/test_changes.py::test_a_claim_holding_anything_but_in_lane_regular_files_is_refused_whole`
  rows `hardlink-to-host`, `hardlink-in-lane`, `replace-file-with-hardlink`, `replace-file-with-hardlink-same-bytes`
  (P4 half: no inode shared with the export).
- (closed by U14) OD21 consequence: covered by `e2e/test_920_branch_resume.py::test_od21_...` on the resume re-binding (`drive(resume=)`, the path a branch sibling runs). The branch CLI's spawned siblings are observed only as argv (`test_branch_replay.py`), so the in-box half is pinned on the resume path alone.

## 7. Review record

- **Panel:** one whole-contract Opus reviewer plus three Sonnet lenses (run-start lifecycle and staleness; isolation and secrets; learning writes and coverage conservation). Candidate `08378806`.
- **Round 1:** about 25 findings. Blocking: F-SWEEP (the tests jointly forbade every r3 placement of the owner record) and O8-PARENT (the parent-side leak check could not detect a leak). Also: refused-claim routing (R-L5/TRI-1), child with no valid line (R-S1), reported vs copied commit (R-S2), page reading the box-writable stamp (G-C2), O-SEE triggers, run-copy removal, a same-process live-owner control, missing child outcome rows, O8 child never reading its own config (R-I1), census evasions (R-I5).
- **Dispositions:** design questions went to the owner as D1–D5, which became U9–U12 and A-MISMATCH; the rest were repaired in `90421c042` and `9cf973fc1`. OD13 resolved to removal; OD16 adopted.
- **Recheck at `dc89318b` (all four reviewers):** all round-1 findings resolved except REPLAY-WT (recorded as the test-only exclusion) and TRI-3 (minor). No new blocking findings. Raised OD18–OD22 and the fast-forward-only pin.
- **After the recheck:** OD18–OD23 cases added in `9b2b4243d`/`72f9f2e7d`, with OD22' and the OD20 follow-ups in this commit. A final targeted recheck confirmed the OD18/19/20/22/23 cases are not vacuous. Its two gaps are now closed: a misconfigured child with a snapshot still refuses, and the later lines of a multi-line forge error survive in the one-line reason. Its pre-P4 "unreadable" consequence led to OD22'. Nothing pending.

## 8. Operator items before merge

- **F-CUT:** lab origin `main` (`75b5e6a`) has `agent/.tenant-id = playground`. The lab clone is 2 undelivered commits ahead (`c6cdf9f` UUID tenant-id migration; `1784b0f` integration transports, which may touch `settings/`). Push or PR them with an operator credential before cutover; `test_cutover.py::test_o14_lab_main_is_publishable_for_the_lab_tenant_before_merge` is the gate.
- **F-FJ:** the running Forgejo is 15.0.9 and the compose default is 17.0.0, so U2's volume→bind move coincides with a 15→17 upgrade that is not automatic.
- **F-DI:** `.dockerignore` should exclude `playground-issuer/` and `playground-knowledge/` (the seal key and `secret_id` would otherwise enter the build context).
- **P4-C13/C14/C15** are unprobed: lab `main` protection, OpenBao static seal/identity tokens/AppRole, and Forgejo accepting an issuer on a non-443 port with a private CA. Verify them first through `test_live_dev_issuer.py` and `test_cutover.py`. C14/C15 failing changes dev wiring only.
