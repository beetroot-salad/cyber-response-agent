# #1108 P2 executable contract and handoff

Design: issue comment 6063781627, edited four-piece order, SHA256 `e2c7f1d791d243230ad7b8ec046759ac8513fe4ddad78f91c8a3548ca36af740`; binding latest P2 handoff 6065435835. Base `c0ceb90d`, branch `tests/1108-p2-run-start`, worktree `/workspace/1108-p2-contract`. Skill `spec-flow/skills/write-tests/SKILL.md` and authoring/contract references at base. Profile `.claude/spec-flow.json` and `docs/principles.md` read. Interpreter `/workspace/defender/.venv/bin/python`; every pytest under flock and explicit worktree PYTHONPATH. Inherited claims C1–C23 preserved by root in grounding.md, not silently reclassified here.

## Mapping

| Obligation | Scenario / real entry point | Enforcing assertions | Current verification |
| --- | --- | --- | --- |
| O3 correct identity | `_run_investigation_lifecycle` → actual `start_box(docker=)` → real driver / ReplayFn; LF, CRLF, no ending | `test_matching_identity_is_read_only_and_precedes_message_zero`: model request occurs, mount identity read occurs, no clone mutation at every Docker call or after lifecycle, same-path readonly bind, own agent env allowlist/value | 3 expected reds: no identity read; later snapshot/mount/env assertions pending implementation |
| O3 wrong mount + strict owner grammar | Independent physical daemon-mapped agent source; wrong id, missing, empty, whitespace, second ending/line, BOM, bare CR, 129 bytes, invalid UTF8, directory, symlink to valid host marker | `test_wrong_or_malformed_box_identity_refuses_before_message_zero`: named refusal, zero real model calls, exactly one mounted read, no clone mutation; mismatch names found/expected id, missing names cause, nonregular/link cause named, malformed text names format/line/encoding details, oversize names bound/size | 13 expected reds: no refusal; all post-refusal assertions pending implementation |
| O3 opt-out | Accepted tenant then host marker correct CRLF / wrong / absent / directory, actual Docker create failure + explicit allow-unsandboxed env | `test_explicit_unsandboxed_lane_reads_the_accepted_path_before_message_zero`: correct reaches real model; returned executor actually runs printenv and returns own agent path despite inherited wrong path; invalid refuses before model, names file/cause, no Docker identity read, no clone mutation | 4 expected reds: correct inherits wrong path; three invalid reach model instead of refusal. Correct model/actual transport observed |
| D1 env host orient | Actual driver opening prompt calls real orientation with capture-only ShimRunner | `test_orient_host_shims_receive_the_run_tenants_agent_path`: shim invoked, its control output enters message 0, every actual passed env names Tenant.agent despite inherited wrong path | Expected red at env equality; control output and shim path reached |
| D2 same path / DooD | Real create builder with real run input directory and covering shared mount | `test_daemon_path_translation_preserves_the_run_process_agent_target`, migrated `test_1106_box_mount` | 5 expected reds collectively: fixed /tenant/agent remains; uncovered C46 control green |
| O2 tenant read root and actual MAIN/GATHER wiring | Actual driver, actual gather dispatch, file tool / bash gate and real host shell; independent lesson/system-skill/query files | `test_own_tenant_corpus_reads_work_and_other_tenant_and_settings_reads_refuse` 12 cases: own bytes present, neighboring tenant/settings bytes absent + explicit blocked return, checkout corpus still returns content | 12 expected reds at own content; all scripted calls completed. Later other/settings/checkout assertions require code-stage run |
| O2 existing shape/deny rules | Same role/surface partition, allowed tenant lesson paired with secret filename, .py, YAML registry, outside-corpus markdown | `test_tenant_root_preserves_secret_extension_and_corpus_shape_denies` 16 cases: denied content absent and explicit Blocked, positive same-root lesson content observed | 16 expected reds at positive tenant control; negative assertions reached, but current outside-root rejection cannot yet establish inner shape discrimination |
| O2 role restrictions | Actual MAIN/GATHER dispatch raw payload shape `gather_raw/l-abc123/0.json` + own tenant control | `test_raw_payload_permissions_keep_the_existing_role_partition` 4 cases: MAIN denies raw, GATHER obtains raw, both get tenant lesson | 4 expected reds at own tenant control; actual role partition assertions reached/passed |
| O2 confined role | Actual `CuratorDeps.for_run` binds production corpus-author definition to separate worktree corpus | `test_confined_curator_binding_keeps_tenant_knowledge_outside_its_read_scope`: read and bash allowed own corpus, both deny tenant corpus | Green; must remain green when tenant root is added |
| O10/D6 retire roster and misleading guidance | Actual product tree and module namespace + actual model-read enumeration | `test_committed_roster_and_generation_loading_api_are_retired`, `test_invlang_capability_guidance_names_adapter_declarations_and_no_grant_roster`, `test_retired_roster_guidance_is_removed`, `test_no_model_facing_instruction_advertises_a_roster_file` | 5 expected reds; module API absence checks follow file absence and require later execution; stale invlang/connect/adapter text observed |
| D6 audit survives | Actual `model_read_surfaces` / `audit_read_surfaces` on minimal literal adapter + skill, withheld then clean control | `test_model_surface_enumeration_and_withheld_verb_audit_survive`: enumerates file, emits named withheld call hit, clean returns () | Green |
| Scope partition | Actual start_box BoxRequest for learning and oracle request built by oracle_box_request, no agent source | `test_box_request_and_oracle_lanes_do_not_require_a_run_tenant`: both start sandboxed, no identity reads/fixed-agent target/stale inherited env | Green; requires code-stage regression after allowlist addition |

## Checks and triage

`author-collection.log`: 67 cases collected (62 new + 5 migrated). `author-pytest.log`: 63 expected reds, 4 passed, 7.63 seconds. `author-ruff.log`: all checks passed. Root owns further graph/type/baseline checks and independent review. No test collection/import/signature failure or unexplained harness failure remains in final run.

Final four greens: confined curator, retained audit, non-run lanes, uncovered mount refusal. Expected reds are missing P2 behavior: tenant root, identity probes, env forwarding, same-path target, roster/text retirement. Failure groups above enumerate each family and exact first assertion. The gate cases execute their entire scripted model sequence before assertions, so later observations exist; assertions following an earlier failure are still individually pending code-stage execution, not certified by existing recordings.

Initial authoring defects repaired before candidate freeze: draft was mistakenly classified as denied (it is readable and query drafts get untrusted framing), removed that expectation; oracle sentinels had different target/source paths, added mechanical mount-table translation to fake; plain `Path.read_text` normalized CR, replaced marker fake with actual subprocess execution; old migrated fake was incompatible with encoded probe output, now shares AgentReadDocker. These are fixture/assertion repairs, not design amendments. PT018 combined asserts split. No production edits/stubs.

`author-helper-probe.log` validates unexercised new marker fake directly: actual cat normalizes bare CR as real Docker subprocess does; actual encoded helper preserves bytes; malformed UTF8 replacement matches errors=replace; actual existing parser accepts CRLF and rejects bare CR through substituted-path exec. This validates machinery only, not future production wiring.

## Binding implementation constraints / outstanding checks

- Identity must be compared against the accepted tenant id, never against another read of potentially corrupt host marker bytes. In the unsandboxed mismatch case acceptance precedes corruption, so comparing file to itself cannot pass the contract.
- Existing tenant-id format has one owner. Implementation must reuse that owner's rules, preserve byte fidelity across `_docker(text=True, errors=replace)` and bounded/nonblocking/no-follow file behavior; don't invent another independent parser. Grammar/symlink/directory/oversize tests enforce outcomes; single-owner architecture and read bound are code-stage review checks, not claimed test coverage. No new helper API prescribed.
- Marker read fake currently expects the `.tenant-id` operand as final argv word, and one read command (fail-fast, no retry). It executes that actual command locally on mapped fixture path. A different equivalent command interface requires a contract machinery adjustment and targeted re-review; don't change intended behavior to satisfy fixture shape.
- Correct comments: startup planting would dirty the tenant clone; readonly is not a valid reason a host cannot plant. Correct both lifecycle and daemon-source guidance (code-stage review, no brittle prose equality assertion).
- P2 retains .md corpus shapes and checkout content. The YAML tacit registry is consumed host-side by its adapter; permitting arbitrary typed/bash YAML is not a P2 promise. Draft access wasn't changed or pinned as denied.
- `write-code-from-tests` must rerun every currently unreachable assertion after adding real behavior, including readonly/no-transient-plant snapshots, boxed env, refusal diagnostics/request count, other/settings/checkout observations, retired module API, and migrated same-path isolation. Existing baseline checks must pass too.
- Root owns contract migration now: remove obsolete `tests/test_verb_roster_632.py` entirely; remove only roster-generation/load arm (430–436), its import and stale docstring claims from `test_tacit_knowledge_registry_983.py`, retaining actual dispatch/registry assertions. Existing `test_1035_one_roster_read.py` audit checks and RosterError stay. Adjust exact argv `test_1092_box_mark_env` if emitted optional agent env changes its run-lane baseline. Update exact-count `_P2_GATE` allowances in test_1108_knowledge_owner only when source literals are removed.
- This is a tests-only contract; production behavior remains at the recorded base. Independent review and durable handoff disposition are recorded below.

Final reviewer R3 repair adds meaningful malformed/encoding/size diagnostic assertions; generic filename plus "invalid" alone does not satisfy them. Root final run supersedes author-pytest.log for this assertion-only revision.

## Reproduction

From the contract worktree, substitute its absolute path if moved. The interpreter is shared with the original checkout, so explicit PYTHONPATH is required.

```sh
PYTHONPATH=/workspace/1108-p2-contract flock /tmp/defender-pytest.lock /workspace/defender/.venv/bin/python -m pytest defender/tests/tenant_1108_p2 defender/tests/e2e/test_1106_box_mount.py -q --tb=short
```

## Mechanical checks and limits

- Collection: 67 cases, no import/setup failures.
- Final frozen contract execution: 63 expected failures, 4 passing controls, 7.50 seconds. No collection/setup errors. Retained authorization/census/template regressions: 15 passed. Unaffected environment/knowledge-owner baselines: 19 passed.
- Changed test files pass Ruff and git diff whitespace checks.
- Repository monkeypatch gate: 14 findings, all baselined, zero new. UTF8 text-I/O and bounded-whole-read gates: zero findings/new findings. No lint baseline changed.
- `spec-graph calls` against public box, driver and verb_roster reports six NO-CALL test functions: four drive production through the external replay harness and two inspect instruction files. The independent reviewer followed the real driver/gather/orient construction and inspected the structural instruction assertions. The tool does not traverse these external helper chains; its findings are not counted as runtime reachability failures or clean tool coverage.
- `spec-graph nullstub --target defender.runtime.verb_roster` exits 2: the regular parent package shadows the temporary stub; the tool explicitly voids its verdicts. It supplied no discrimination evidence. Independent assertion review and actual wrong-input/control probes are the discrimination evidence.
- Docker server is available (29.5.3). No live container run is claimed by this tests-only stage. Code stage must confirm the actual same-path read-only bind and marker read through a real daemon, including DooD source translation where applicable, after implementation.
- Tests do not claim exhaustive production source census or whole-project type validation. No production or policy-bearing skeleton was added. Full CI and applicable type/owner/lint gates belong to implementation after expected reds become green.

## Independent review and current handoff

**Ready for `write-code-from-tests`.** Local branch `tests/1108-p2-run-start`; base `c0ceb90dccb1d87c8c4783000ffbe887d41e46c5`. Contract ref: the commit carrying this record, also tagged `contract/1108-p2` after commit. Neither branch nor tag has been pushed. Both honest and adversarial implementers must start from that exact contract commit; retain it when creating implementation branches.

Author and independent reviewer were separate `gpt-6.1-sol` instances, high effort, as requested. The reviewer derived obligations before inspecting the candidate and rechecked the final material revision. No blocking findings remain; no design amendment was needed.

| Finding | Resolution |
| --- | --- |
| R1 host environment wiring | Actual fallback executor child and independent ORIENT shim environment now assert the tenant path overrides inherited state. |
| R2 confined roles | Actual curator construction has allowed-confine and denied-tenant controls on typed and bash gates. |
| R3 refusal diagnostics | Mismatch identifies found/expected IDs; absence/nonregular/encoding/format/size failures require informative reasons. |
| R4 parser ownership | Binding code-stage architecture review and ownership lint; black-box grammar cases do not claim to prove one owner. |
| R5 encoded-read fake mismatch | Migrated mount tests use actual-command execution, which supports byte-safe reads and models text conversion. |
| O10 broad scope | Actual model-read surfaces are scanned for roster-file promises; audit dirty/clean controls remain. |

Reviewer independently ran the four passing controls (4 passed in 1.02 seconds) and demonstrated the encoded-read fixture counterexample before its repair. Final material test hashes reviewed:

```text
2fe75589b120cbcb563b8a27f7a43960b204fb1eaa43ff346efb427dab7a9a8a  defender/tests/tenant_1108_p2/_support.py
70c8cb012387e15167cff4eddbc71f141d73d1b15b34b27fd6a12536800d1761  defender/tests/tenant_1108_p2/test_read_gate.py
5a7e26fa5dd2235162841350c82612953f332c5e15353c1136ad4b439db164a5  defender/tests/tenant_1108_p2/test_roster_retirement.py
d529bf88552de0d1491305459f182f378ee1ae7028c3f75fcdaf649575f9bead  defender/tests/tenant_1108_p2/test_run_start.py
17e5f03c9e8f1f95cc910c15003683c1e3995cde9968ef5be0e608216c12e962  defender/tests/e2e/test_1106_box_mount.py

```

The reviewer also inspected the narrow retirement edits and final execution evidence. Deferred acquisition/ownership/live checks and later assertions above remain mandatory code-stage completion conditions. The next action is `write-code-from-tests` on this local contract ref. Publication is a separate next action if remote access to the contract is needed.

## Supporting grounding

# #1108 P2 grounding and provenance

- Contract base: c0ceb90dccb1d87c8c4783000ffbe887d41e46c5 (main at start).
- Branch/worktree: tests/1108-p2-run-start, /workspace/1108-p2-contract.
- Design: https://github.com/beetroot-salad/cyber-response-agent/issues/1108#issuecomment-6063781627 (updated 2026-10-08T16:26:56Z).
- Scope/handoff: https://github.com/beetroot-salad/cyber-response-agent/issues/1108#issuecomment-6065435835 (updated 2026-10-11T08:36:12Z).
- Design body SHA256: e2c7f1d791d243230ad7b8ec046759ac8513fe4ddad78f91c8a3548ca36af740.
- User affirmed P2 now, including environment path handout, and requested write-tests with Sol instances.
- Original inherited claims below retain their original d2f7aeb8 base; unrelated P3/P4 claims are not revalidated by this P2 run.
- Interpreter: /workspace/defender/.venv/bin/python (3.11.15; pytest 9.0.3; pydantic 2.13.4); verified defender.runtime.box imports from this worktree with PYTHONPATH set.
- Baseline command: PYTHONPATH=/workspace/1108-p2-contract flock /tmp/defender-pytest.lock /workspace/defender/.venv/bin/python -m pytest defender/tests/e2e/test_1106_box_mount.py defender/tests/test_1092_box_mark_env.py defender/tests/test_1108_knowledge_owner.py -q --tb=short
- Baseline: 24 passed, 3.61 seconds.
- Tools: skill and spec-graph at base c0ceb90d; no generated spec graph required.

## Current P2 observations

```yaml
claims:
  - {id: P2-C1, kind: referential, claim: "Run lane mounts tenant_agent at fixed /tenant/agent and does not probe it", probe: "read runtime/box/_lifecycle.py:119-126,188-248,378-422 at c0ceb90d", probe_kind: read, observed: "TENANT_AGENT_TARGET used for target; no tenant marker probe", verdict: holds}
  - {id: P2-C2, kind: referential, claim: "Run lifecycle starts box before investigation", probe: "read defender/run.py:351-400 at c0ceb90d", probe_kind: read, observed: "start_box(...tenant_agent=tenant.agent) returns before investigate", verdict: holds}
  - {id: P2-C3, kind: referential, claim: "Marker parser has one owner and enforces regular nofollow bounded file plus strict UTF-8 id and at most one LF/CRLF", probe: "read defender/_tenant.py:682-723 at c0ceb90d", probe_kind: read, observed: "os.open O_NOFOLLOW|O_NONBLOCK, fstat, capped os.read, TenantId validation", verdict: holds}
  - {id: P2-C4, kind: referential, claim: "Existing permission construction roots corpus names at defender_dir", probe: "read runtime/agent_definition.py:106-130, runtime/driver/_build.py:157-205, permission/policies/_common.py:21-52 at c0ceb90d", probe_kind: read, observed: "checkout corpus roots/shapes; no tenant agent root", verdict: holds}
  - {id: P2-C5, kind: referential, claim: "DEFENDER_AGENT_DIR is absent from box allowlist and run environment handouts", probe: "read runtime/box_codec.py:19-29, runtime/box/_docker.py:123-150, run_common.py:326-338 at c0ceb90d", probe_kind: read, observed: "existing keys exclude new handout", verdict: holds}
  - {id: P2-C6, kind: behavior, claim: "Existing mount/env/census tests work in dedicated worktree", probe: "baseline pytest command above", probe_kind: executed, observed: "24 passed in 3.61s", verdict: holds}
```

## Inherited claims (verbatim, historical base d2f7aeb8)

```yaml
claims:
  - {id: C1, kind: census, claim: "Nothing reads tenant.agent / RunTenant.agent except the box mount", probe: "grep tenant.agent|\\.agent\\b|TENANT_AGENT_TARGET over defender/ excl tests", probe_kind: search, observed: "run.py:315 → _lifecycle.py:94-101 only; run_tenant.py:84 unused", verdict: holds}
  - {id: C2, kind: referential, claim: "The run box mounts run_dir and defender_dir at their own paths, the tenant half at fixed /tenant/agent", probe: "read _lifecycle.py:40-101", probe_kind: read, observed: "target={run_dir}, target={defender_dir}, target=/tenant/agent", verdict: holds}
  - {id: C3, kind: referential, claim: "The unsandboxed lane drops tenant_agent", probe: "read _lifecycle.py:316-397", probe_kind: read, observed: "unboxed_executor(spec, env=run_env(defender_dir, run_dir)); tenant_agent unused", verdict: holds}
  - {id: C4, kind: referential, claim: "Typed read, read gate, lessons push, lesson-load hook and orient run in the run process, not the box", probe: "read tools/_files.py:72-88, permission/files.py:126-187, lessons_push.py, tools/_deps.py:208-228, orient.py:25", probe_kind: read, observed: "all host-side; only bash commands and the defender-lessons/invlang shims execute in the box", verdict: holds}
  - {id: C5, kind: referential, claim: "record_lesson_load requires a `defender` grandparent", probe: "read hooks/record_lesson_load.py:19-28", probe_kind: read, observed: "p.parent.parent.name == 'defender'", verdict: holds}
  - {id: C6, kind: census, claim: "generate_roster/load_roster have no production caller", probe: "grep verb_roster over defender/ excl tests", probe_kind: search, observed: "only a docstring mention at tacit_knowledge_adapter.py:86", verdict: holds}
  - {id: C7, kind: referential, claim: "nothing-to-try's cap= is checked against the adapters' declared roster, not verb-roster.md", probe: "read invlang/validate/_gating.py:625-700", probe_kind: read, observed: "known_capabilities() = held read_roster(adapters_dir)", verdict: holds}
  - {id: C8, kind: referential, claim: "The run lane plants a sentinel only into the run dir; the BoxRequest lane plants into every mount source, read-only included", probe: "read runtime/box/_lifecycle.py:112-158,199,289-292", probe_kind: read, observed: "as stated; no read-only exemption in code (first draft cited _docker.py: wrong file, corrected after review)", verdict: holds}
  - {id: C9, kind: referential, claim: "The judge reads lesson bodies from the product repo at the code commit", probe: "read judge/__init__.py:619-626, judge/render.py:533-558,630-642", probe_kind: read, observed: "git show REPO_ROOT <provenance.commit>:defender/<corpus>/<name>.md", verdict: holds}
  - {id: C10, kind: referential, claim: "#1204's knowledge stamp exists and is read from .git files", probe: "read _provenance.py:81,166,322-341", probe_kind: read, observed: "KnowledgeRevision; capture_knowledge reads HEAD/refs by hand", verdict: holds}
  - {id: C11, kind: census, claim: "Forge is constructed in one place; no Forgejo code in defender/", probe: "grep GhForge|forgejo over repo", probe_kind: search, observed: "GhForge only at branch.py:56; forgejo only in .devcontainer", verdict: holds}
  - {id: C12, kind: referential, claim: "origin and main are literals in learning's git calls", probe: "read branch.py:20-21, _git.py:388,392", probe_kind: read, observed: "_BRANCH_BASE='origin/main', _PR_BASE='main', fetch/push origin", verdict: holds}
  - {id: C13, kind: referential, claim: "The drain box derives DEFENDER_DIR from workdir/defender and mounts only the worktree", probe: "read _docker.py:135-142, _lifecycle.py:329-348, drains.py:528-544", probe_kind: read, observed: "as stated", verdict: holds}
  - {id: C14, kind: census, claim: "D1's reader list is every production reader of the corpus", probe: "three grep sweeps over defender/ excl tests (lessons, skills/<system>, queries, registry, roster), 2026-10-08", probe_kind: search, observed: "list in D1; first draft of #1120's census missed orient.py and _corpus.query_catalog_dir; cold review found evals/scenarios_lead/*/expect.json and connect's commit step, now added", verdict: unrefuted}
  - {id: C15, kind: census, claim: "~174 test files name a corpus path", probe: "grep -rlE corpus-path pattern over defender/tests", probe_kind: search, observed: "174", verdict: holds}
  - {id: C16, kind: referential, claim: "A golden replay records model reads of defender/lessons/*.md", probe: "regex count over fixtures-e2e/golden-sshpivot-ab3/tool_trace.jsonl", probe_kind: search, observed: "8 distinct defender/lessons/*.md paths (first draft said 7)", verdict: holds}
  - {id: C17, kind: referential, claim: "The runtime image has no git", probe: "read .devcontainer/Dockerfile.runtime:66-70", probe_kind: read, observed: "'this image has neither git nor .git, by design'", verdict: holds}
  - {id: C18, kind: behavior, claim: "The lab clone's push authenticates as its bot", probe: "config key names read only (credential.http://forgejo:3000.helper is set); no executed push or ls-remote", probe_kind: read, observed: "helper configured; behaviour not exercised (2026-10-06 comment reports it verified by hand)", verdict: unprobed}
  - {id: C19, kind: behavior, claim: "Forgejo's PR list API cannot filter by head-branch prefix", probe: "none run", probe_kind: read, observed: "assumed from #1120 review; drives A5's client-side filter", verdict: unprobed}
  - {id: C21, kind: behavior, claim: "A write-only bot token can read the repo's branch protection through the API", probe: "none run", probe_kind: read, observed: "decides A10's branch", verdict: unprobed}
  - {id: C22, kind: referential, claim: "No tenant.py pull exists; start_batch fetches but never updates the clone's tree", probe: "read scripts/tenant.py:507-516, branch.py:111-121", probe_kind: read, observed: "subcommands scaffold/setup/check/migrate; fetch then worktree add only", verdict: holds}
  - {id: C23, kind: referential, claim: "BOX_ENV_ALLOWLIST filters what env reaches a box", probe: "read runtime/box_codec.py:19-28, _lifecycle.py:106-107", probe_kind: read, observed: "8 keys; only those are passed", verdict: holds}
  - {id: C20, kind: behavior, claim: "A4's discriminator: the product tree at a pre-move commit has defender/lessons/, at a post-move commit does not", probe: "deferred to P4 (the move commit does not exist yet)", probe_kind: read, observed: "", verdict: deferred}
```
C19, C21 and C18 are the Forgejo implementer's first probes, against the dev Forgejo. If the API can filter by head prefix, use that instead of client-side filtering. C21 picks A10's branch.


## P2 byte-transport probe

```yaml
claims:
  - id: P2-C7
    kind: behavior
    claim: "The current text-mode subprocess transport normalizes even a forbidden bare CR into LF"
    probe: "Python subprocess.run([sys.executable, '-c', stdout.buffer.write(raw)], capture_output=True, text=True) for raw acme LF, CRLF, bare CR; read _docker.py:159-163"
    probe_kind: executed
    observed: "All three outputs become acme LF; current _docker hardcodes text=True and ignores caller kwargs"
    verdict: holds
```

D3 already requires byte-preserving strict marker parsing. Implementation must preserve or safely encode marker bytes across the Docker boundary. A fake returning newline-preserved text for a raw text-mode cat would fail to model this constraint. This is a local transport consequence of the adopted grammar, not a new product decision.

Profile SHA256: `0ed34f09127ea22f8c1fcdf178fbb1f732b5c2b41c4f3ed74688c98439d1941d`.

## Implementation handoff — current result, 2026-10-14

Implementation branch `impl/1108-p2`, worktree `/workspace/1108-p2-contract`. Immutable executable contract `9281cbe2d258e5e7d0c7a78d3f31c2315f74667c`, base `c0ceb90dccb1d87c8c4783000ffbe887d41e46c5`. The original 166-line contract record and existing executable assertions are unchanged. Current repaired contract: `52ba761e0a2e3d4010d5db28f096724d1c5852b7` (`contract/1108-p2-ci`); its tests-only lineage repairs the marker subprocess environment and adds four regression cases. See [CI repair provenance](CI_REPAIR.md). **Draft publication requested; verification remains incomplete.**

Both inputs remain `OWNER` authored: design 6063781627 (`2026-10-08T16:26:56Z`) and handoff 6065435835 (`2026-10-11T08:36:12Z`). Their four-piece scope is unchanged. The fetched design API body plus its trailing LF matches SHA256 `e2c7f1d791d243230ad7b8ec046759ac8513fe4ddad78f91c8a3548ca36af740`; omitting that LF explains the initially different digest.

### Ownership, consumers and deferred verification

- The run lifecycle passes the accepted `RunTenant.agent` and `tenant_id` inward. The box binds that agent half read-only at the same process-visible path; DooD translates only its source. Settings and the clone's `.git` are not exposed. Startup never plants into the agent clone. Direct bare-path callers without an accepted record capture an expected id before create; the real lifecycle never rereads a possibly corrupt host marker as its expected identity.
- `_tenant.parse_tenant_id_bytes` is the sole `@owns tenant-id` grammar owner, shared by acceptance, boxed read-back and host opt-out. The owner's byte reader uses `O_NOFOLLOW | O_NONBLOCK`, requires a regular file, and reads once with a 129-byte request against the 128-byte cap. The actual in-box command base64-encodes those bytes; the host decodes and invokes the owner. Docker text-mode newline conversion/UTF-8 replacement cannot change marker bytes before validation. There is one read command, with the marker as its final operand, and no retry.
- `DEFENDER_AGENT_DIR` is allowlisted and handed directly from `Tenant.agent`. Inspected consumers include run create argv, host `run_env`, orientation/opening prompt, MAIN/GATHER host bash, ticket calls and `bash_exec.main`'s real allowlist filter. Request fallback clears inherited agent state before applying explicit allowed request env. Tenant-free request/oracle boxes gain no identity requirement; host adapter replay preflight clears inherited agent env.
- MAIN, normal GATHER and harness lead-zero GATHER explicitly bind the tenant root. `resolve_roots` and `_resolve_corpus_dir` include its corpus metadata; `_common` applies the existing `.md` shapes under it. Typed/bash gates share the compiled policy. Checkout corpus access stays live in P2. Confined scopes suppress the automatic tenant root; real curator bindings retain their own worktree corpus. Review roles declare no tools/corpus and gain no tenant lift.
- Roster file/path/generation/loading APIs are retired; model-surface enumeration/audit and `RosterError` remain. Invlang names adapter-declared capabilities. Connect guidance accurately distinguishes the retained template-id check from warn-dropped id-less files.

All previously unreachable contract assertions now execute successfully: actual mounted read before message zero; same-path readonly bind and env; no transient clone writes; refusal diagnostics/zero model requests; real host fallback transport/env; own/other/settings/checkout reads; secret/extension/corpus/raw-role partitions; confined curator; retired APIs; retained audit; non-run lanes; uncovered-source refusal. Source review closes the deferred single-parser, bounded-I/O, byte-fidelity and construction/caller census obligations. Live checks below close actual daemon bind/read-only mechanics at the explicit `runc` floor; no native-host or `runsc` qualification is claimed.

### Reviewed baseline machinery and environment repairs

The baseline repair author had already seen implementation. A separate `fixture_review` role statically reviewed the repairs; root's focused runtime run then passed them. At that stage, no immutable P2 executable assertion/helper was edited, no skip added, no production runtime workaround introduced, and no lint baseline addition/suppression used.

Repairs preserve existing assertions/selection while completing prerequisites: actual marker-command execution in `RecordingDocker` through its captured longest-covering bind (unmounted reads refuse; no parser stub or alias-reply consumption); early marker delegation in `AliasProbeDocker`; owner-produced marker in the fsize fixture; local shared-directory fixtures only for three alias-ban, seven mounted-image and one stopped-box live cases; exact tenant-free env expectations excluding optional agent state, with explicit absence; old fixed-target expectation migration; retained audit/discovery prose cleanup; and the knowledge-owner `skills` allowance tightened from 3 to 2 for the retained audit walk. `_P2_GATE` counts remain unchanged. Two obsolete lint-baseline entries were pruned.

The shared fake is named/re-exported by nine other test modules: `_spec1092`, `_spec771`, box geography, scrub lifecycle, original tenant mount, image-name, create-fault, alert-place and frozen P2 support. Only the exact new marker-read branch changes behavior; the P2-specific fake retains its own interception. AST comparison confirms prior exec branches are identical after extraction, excluding the new marker arm; live test bodies/decorators/probes are identical after normalizing only fixture arguments, apart from the intentional env expectation migration. The actual shared anchor is covered by production's mount predicate. Native paths, image-only checks and stopped-box private state retain their original locations.

Root also provided the ignored worktree `defender/.venv` symlink to the existing shared venv, satisfying the existing own-location reexec prerequisite; no source assertion was changed for it. A whole-suite shared-basetemp experiment was abandoned after 349 failures/9,851 passes (462.80s, `/tmp/1108-full-tests-shared.log`) because it violated private-temp episodes-root assumptions and exhausted inotify resources; only that generated tree was removed, and the kernel watch probe recovered.

### Actual checks

| Check | Current observation / evidence |
| --- | --- |
| Final affected rerun | **164 passed, 5 skipped, 59.99s**, `/tmp/1108-affected-final.log`: all 67 frozen P2 cases plus every available failure repaired from the full run. |
| Completed whole suite | **20,359 passed, 23 failed, 260 skipped, 17 xfailed, 1357.11s**, `/tmp/1108-full-tests-final.log`. The 21 fixture/env/count/venv failures subsequently pass in the focused rerun; the two mandatory missing-`runsc` failures remain. No later whole-suite green is claimed. |
| Gate-marked suite | **43 passed, 1 skipped, 2 failed**, `/tmp/1108-gate-tests.log`. Wrapper census passes after staging the intended deletion: **1 passed, 5.87s**, `/tmp/1108-wrapper-gate-final.log`; no census code/assertion change. Historical graph failure remains below. |
| Final Ruff / mypy | Both Ruff gates pass; mypy succeeds on **291 source files** with CI-equivalent API dependencies, `/tmp/1108-ci-mypy.log`. The earlier shared venv lacked FastAPI and misleadingly reported its intentional hook annotation as unused. CI exposed that dependency gap; the original annotation was restored and verified in `/tmp/1108-ci-venv`, created with `uv sync --extra dev --extra runtime --extra api --locked`. |
| CI-derived checks | Earlier 37 custom/artifact checks passed. All eight fixture-sensitive final rechecks pass—both Ruff gates, jscpd, duplicate helpers, vulture, shippable surface, monkeypatch and stale refs—`/tmp/1108-final-fixture-checks-summary.log` and `/tmp/1108-final-fixture-checks.log`. |
| Spec-flow scripts | **148 passed, 17.39s**, `/tmp/1108-spec-flow-tests.log`. |
| Actual daemon | **6/6** marker scenarios pass with readonly/same-target/translated-source inspection and actual write refusal, `/tmp/1108-live-probe.py` and `.log`. LF/CRLF/no-ending accept; wrong id/bare CR/invalid UTF-8 refuse; clone bytes remain unchanged. |
| Live boundary | **26 passed, 2 skipped, 62.67s**, `/tmp/1108-boundary-tests.log`; unavailable host DNS positive control and absent `runsc` parity are explicitly unverified. |
| Generated guard inputs | **12,014** parser/file marker inputs plus nonblocking FIFO refusal; **1,801** corpus/sibling/extension/traversal/symlink paths across MAIN/GATHER typed/bash gates, `/tmp/1108-marker-fuzz.log`, `/tmp/1108-path-probe.log`. These are generated-input/fuzz checks, not mutation/adversarial verdicts. |
| Fake command discrimination | Actual longest-bind read, CRLF fidelity, missing-bind refusal and reply preservation pass; prior exec AST equivalence passes, `/tmp/1108-recording-docker-probe.log`. |
| Hygiene | Ruff and `git diff --check` pass; the original 166-line record is byte-for-byte unchanged and existing frozen executable assertions remain unchanged; the subsequently reviewed helper repair is recorded below. |

Every pytest invocation used `flock /tmp/defender-pytest.lock` and explicit worktree `PYTHONPATH`. The completed whole command ran from `defender/` with `DEFENDER_BUDGET_ENFORCE=1 DEFENDER_BOX_RUNTIME=runc PYTEST_XDIST_AUTO_NUM_WORKERS=6`, `/workspace/defender/.venv/bin/python -m pytest tests/ -v -m 'not live and not gate' -n auto --dist loadfile --durations=25 --ignore tests/e2e/test_540_box_boundary.py`, using the normal private temp base. The final affected rerun used four workers. Original contract reproduction remains the command recorded above.

### Prior completion blockers and CI repair disposition

1. **Required `runsc` verification is unavailable.** The daemon registers only `runc`. `test_a1_runsc_box_cannot_change_the_alert_or_its_record` and `test_p151_production_runtime_meets_every_write_shape` intentionally fail when their required runtime is absent; their assertions were preserved.
2. **Archived graph retirement — repaired after CI inspection.** Retirement `24bc8b98` removed the direct graph gate but left its corpus smoke marked `gate`; CI's complementary gate job still executes it. `441e218f` moved configuration into `docs/archive/`. The legitimate frozen-contract roster-test deletion adds five archived orphan targets: graph 632 reports **21 findings against ceiling 16**. The untouched immutable contract independently reproduces **2,036 findings over 58 graphs, one over ceiling**, `/tmp/1108-baseline-graph.log`. Archived files/ceilings remain unchanged; the independent author/reviewer repair now removes only the obsolete whole-corpus smoke from collection, preserving all seven injected ratchet/blindness cases and the standalone historical CLI. No counterfeit replacement tests or graph regeneration was used.
3. **Required independent adversarial sampling did not execute.** The platform content filter blocked that worker before any sample ran: **zero executed samples, no clean verdict, no completed independent mutation evidence**. Guard fuzzing, ordinary review and passing runtime checks do not replace this stage.

Root owns final integration and subsequent independent code review. The outstanding independent adversarial stage prevents a readiness verdict; production-runtime CI results are recorded below. Available focused implementation checks pass; draft publication does not discharge them.

### CI repair, 2026-10-14

CI run `38581978493` failed 16 tests across both shards because the local Docker stand-ins inherited CI's defender/ cwd without a subprocess PYTHONPATH. Pytest's own import-path setup did not reach those children. Both stand-ins now execute the actual script and mapped operand with the current test interpreter and an explicit worktree import root; byte transport, parser ownership, read count and refusal assertions remain intact. No production source changed.

The honest repair author had seen implementation; fixture_review independently approved design fidelity and observed discrimination. Four new environment regression cases failed with the exact CI import error before the fix. The repaired tests-only contract `52ba761e0a2e3d4010d5db28f096724d1c5852b7` descends directly from the original contract and is merged without rebasing implementation. Existing contract assertion files and original record are unchanged. The shared baseline call site is integrated separately. The archived graph retirement follows commits `24bc8b98` and `441e218f`; no graph, ceiling, skip or lint suppression was added.

Focused verification: **90 passed, 4 skipped, 69.37s**, `/tmp/1108-ci-author-green.log`; new regression red evidence: **4 failed**, `/tmp/1108-ci-author-red.log`. The full gate suite passes under CI Python 3.11: **44 passed, 121.18s**, `/tmp/1108-ci311-repair-gate.log`; new regressions plus retained checker units: **11 passed, 3.08s**, `/tmp/1108-ci311-repair-focused.log`; alert startup: **1 passed, 2.56s**, `/tmp/1108-ci-repair-alert.log`. All eight fixture lint checks pass, `/tmp/1108-ci-repair-lints.log`. An earlier Python 3.14 gate attempt passed all 44 selected tests but hit 16 unrelated pytest assertion-rewrite collection errors; it is not a clean gate result, and the corrected Python 3.11 rerun supersedes it. Final CI result will be recorded in the PR. This environment repair does not discharge the missing independent adversarial sample; no readiness verdict is claimed.
