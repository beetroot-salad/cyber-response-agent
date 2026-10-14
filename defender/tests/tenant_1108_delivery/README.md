# Issue 1108 P3 executable contract

Status: reviewed contract repair ready for `write-code-from-tests` integration and implementation verification. The original 49-case contract is revised on its contract-only lineage after implementation-stage adversarial findings; production implementation is absent from this branch.

- Branch: `contract/1108-p3-repair`.
- Original immutable contract: `810b70d8a5c8c9935c5eaeb3bdb9b4b311abbdeb`; this repair descends directly from it and retains the original base.
- Base: `d4fea4cfd53a89fcdfff93f1c4ca6ef9c943e490` (merged P2).
- Design: [issue design comment](https://github.com/beetroot-salad/cyber-response-agent/issues/1108#issuecomment-6063781627), fetched 2026-10-14, plus the user's session clarification: the tenant bot can read protection but cannot modify it.
- Workflow: `spec-flow/skills/write-tests/SKILL.md` at base. No production skeleton or policy substitute is included.
- Contract identity: the immutable git commit containing this suite and record; the final handoff names its SHA.
- Next stage: `write-code-from-tests`, beginning from that contract commit. P3 stays dormant; P4 performs production wiring and removes GhForge.

Design snapshot SHA256: `e5b00f610d2faa408f46da6920621272be3ff09c5faea54b9ba7b94ca1fdff26`. Project profile SHA256: `0ed34f09127ea22f8c1fcdf178fbb1f732b5c2b41c4f3ed74688c98439d1941d`. Skill SHA256: `fe077f6f53b31e2aef672e351e442260cfdde16b23ce56ecec9fa1e3c6f095e2`.

## Repair record (2026-10-14)

The repair author read the approved design and original contract, without opening honest or adversary implementation source. After authoring was finalized, adversary failure tracebacks exposed source snippets while classifying the results; no executable expectations were changed afterward. A1–A5 came from independent adversary findings. The root orchestrator also reported G1 after inspecting honest code; its exact filenames were independently translated into O7 cases. These are repairs after implementation exists, not a new pre-implementation run. Current supplied design snapshot SHA256: `da42522d8569964cea03db5a5e4edd0efd0f2e06008996c9c7f51c5b91aa94f7`; the original authoring hash above identifies the earlier snapshot. No behavioral design amendment was adopted. The orchestrator confirmed repository-scoped pagination follows D7/O7, beyond A5's minimum transport-origin comparison.

| Finding / obligation | Repair assertions and complementary control |
|---|---|
| A1 / A10, O9: non-object JSON protection escaped normalized refusal | Existing direct ForgeError and delivery DeliveryRefused tests now include literal `null`, array, string, boolean and numeric JSON roots. The HTTP fixture serializes actual JSON bytes, including `null`. Existing valid-protection read and successful delivery remain controls. |
| A2 / O7: retained delivery skipped commit policy | `test_retained_delivery_refuses_forbidden_commit_added_after_failed_pr`: an allowed commit is pushed, PR creation fails, a real marker/settings/product bypass commit advances the retained branch, and its worktree is removed; retry must refuse, preserve the remote's good SHA and issue no extra PR POST. Existing successful retained retry controls the same flow. |
| A3 / O7: net diff hid forbidden pushed history | `test_delivery_refuses_forbidden_history_even_when_reverted_before_allowed_lesson`: marker/settings/product bypass commit, revert and allowed lesson leave exactly one allowed net path; finish and retained deliver both refuse before creating a remote branch or PR. Existing valid lesson delivery is the control. |
| A4 / O8: writable lane escaped agent | `test_drain_request_refuses_writable_lane_outside_agent`: parent traversal, nested traversal, absolute settings path and filesystem symlink all resolve to the existing settings directory and must refuse. Existing exact mount-set test proves a lessons lane succeeds. |
| A5 / O7, O8: untrusted next-page Link redirected authenticated requests | `test_pagination_refuses_outside_origin_repository_before_request`: scheme/host/port changes and same-origin other-repository Link are refused before any second request, on both prefix and exact-head listing. First page does not satisfy exact head. Existing same-origin prefix pagination and added exact-head pagination authenticate and return the second-page result. MockTransport performs no policy checks. |
| G1 / O7: Git output trimming normalized forbidden root names | Finish and retained retry bypass cases include exact root names `" agent/rogue"`, `"\tagent/rogue"`, `"\nagent/rogue"`. Real files and Git argv preserve these names; expectations do not use stripped Git output as a filename oracle. The paths must remain outside literal `agent/`. |
| A6: protection changing after factory open | Deferred design ambiguity. No new timing or revalidation requirement is asserted. The original factory-time protection requirement remains unchanged. |

Independent intent review accepted these exact executable tests and the repair record, without inspecting honest or adversary source. Reviewer Ruff passes, and an independent real-Git byte-level fixture probe confirmed space/tab/newline root names retain their exact bytes. Author Ruff, diff-whitespace checks, tests-only ancestry checks and monkeypatch lint pass (14 historical findings, zero new). Collection succeeds: 87 cases. The repaired full suite against unchanged adversary source reports **35 failed, 52 passed, zero setup errors** in 20.71s. A1 reaches ten wrong-type `AttributeError` failures, including literal null/array at both error boundaries; A2 has six missing refusals; A3 six; A4 four; A5 eight; G1 also rejects the leading-space finish bypass. The original 49 cases, added same-origin exact-head pagination control, and tab/newline finish negatives pass. Evidence: `/tmp/1108-adversary-evidence/repaired-contract.log`, produced with the documented pytest command using the adversary worktree import root. Subsequent honest green and implementation-stage checks below remain required. The adversary's original 49-case green result is not a verdict on this repair. Source implementation remains exclusively on other branches; only tests/test machinery and this declared coverage record belong here.

## Local test API seams (implementation choices, not new persisted models)

`defender.learning.author.tenant_delivery` exports `DeliveryRefused` and `TenantDelivery.open(accepted_tenant, defender_dir=Path, client=httpx.Client)`; this is a dormant factory, never production default wiring. One credential read belongs here. The object owns real `AuthorBranch` as `.branch`, and `start_batch(id)`, `commit(wt, relative_paths, message)`, `finish_batch(id,wt)`, `deliver(id)`, `box_request(wt,id,writable_dirs=agent_relative_lane_names)`, `start_box(request,docker=...)`. Host-only credential material must be absent from representation. Delivery errors normalize to DeliveryRefused; box startup faults remain BoxFault.

`ForgejoForge(origin=network_url, token=loaded_token, client=httpx.Client)` is in existing forge module, retains three-method dict-shaped Forge interface and adds `verify_main_protection()`. It does not read the credential file itself. Protection reads `/branches/main` (C21 actual endpoint), requires strict true `protected` and strict false `user_can_push`, fails on missing/invalid evidence. PR normalization remains `number/headRefName/url`, retaining GhForge for P4.

`BoxRequest.defender_dir` explicitly owns code geography. `TenantDelivery.box_request` uses code ro + agent ro + explicit lane rw, workdir agent, DEFENDER_AGENT_DIR agent. Existing `_render_argv` and `_host_fallback_env` must honor explicit code. Existing `_check_mount_sentinel` readonly handling reads `.tenant-id` for agent and chosen fixed `SKILL.md` for product; product file choice is a local deterministic probe seam, not content migration. `start_box` must not return an unsandboxed executor for tenant requests.

## Obligations and enforcing assertions

| Obligation | Scenarios / target | Assertion groups / discriminated violation | Status |
|---|---|---|---|
| O7 real delivery | test_tenant_batch_commits_pushes_and_opens_tenant_main_without_product_write | real git batch under tenant worktrees + quarantine; exact commit path; remote batch SHA equals local; remote main unchanged; HTTP repo path/base/head; product SHA unchanged | target missing |
| O7 commit gate | test_commit_gate_refuses_forbidden_paths_before_staging_or_commit; test_mixed_allowed_and_forbidden_commit_is_atomic_and_does_not_include_staged_settings | actual forbidden edits, marker/settings/product/traversal; unchanged HEAD/index; scoped allowed commit excludes staged forbidden with positive SHA/path assertion; mixed requested forbidden atomic refusal | target missing |
| O7 push gate | test_finish_refuses_out_of_policy_commit_that_bypassed_gate | real bypass marker/settings/product commits cannot push or create PR; exact branch ref absent | target missing |
| O7 retained delivery | test_failed_pr_creation_can_deliver_retained_branch_without_reauthoring | real push followed by HTTP failure, cleanup, retry branch without author, same remote SHA | target missing |
| O7b | test_next_batch_fast_forwards_clone_before_creating_worktree; test_refresh_refuses_local_state_without_creating_batch | remote human merge reaches clone and batch; tracked dirty/untracked/diverged refused without HEAD change or worktree | target missing |
| O8 credentials | test_credentials_require_scheme_host_and_port_agreement_before_http; test_credentials_loaded_once_and_token_not_in_representation | scheme/host/port negatives before HTTP; process-local audit hook counts one file read (with read_bytes positive control); modify file after open yet HTTP token same; repr/env exclusion with successful request control | target missing |
| O8/P3 architecture | test_git_credential_location_has_one_production_owner; test_tenant_delivery_has_no_production_callers_until_p4 | AST census excludes docstrings/tests; credential literal only delivery owner or layout path construction; production imports/names/dynamic-import strings cannot wire dormant target; target import prerequisite prevents zero-implementation pass | target missing |
| O8 git credential source | test_git_operations_explicitly_reset_helpers_and_use_only_tenant_file | real Git Trace2 fetch/push argv helper sequence equals exactly reset + store credential path; no token argv | target missing; local transport does not invoke helper, argv enforces by-construction commitment |
| O8 box isolation | test_drain_request_mounts_only_code_agent_and_explicit_lane | exact mount set excludes all ancestors of settings/git/forge; explicit code and agent env, token/forge absent in actual rendered argv | target missing |
| O8 unsandboxed | test_tenant_drain_refuses_unsandboxed_even_when_operator_opted_out | opt-out set + real startup fault seam still raises, no unboxed return | target missing |
| O9 | test_delivery_refuses_unusable_tenant_with_named_reason | unversioned/local-origin/missing credentials/missing main individually named | target missing |
| A10/C21 | test_main_requires_known_protected_and_bot_cannot_push; test_protection_read_failure_or_unknown_push_permission_refuses; test_protection_verification_reads_branch_but_never_changes_rules | unprotected/pushable/unknown/API denied/malformed refused; valid branch read only exact endpoint | target missing |
| A5/C19 | test_open_pr_listing_traverses_pages_and_filters_head_prefix; test_exact_head_lookup_does_not_accept_prefix_match; test_create_sends_all_pr_fields_to_origin_repository | real HTTP adapter observes page Link, filters head.ref, exact head matching, PR POST body/path/url | target missing |
| D7 RO probes | test_readonly_probe_reads_existing_file_and_never_plants | product/agent positive/mismatch/read fault; snapshot during boundary detects transient plants; exact existing file read | current behavior rejected by no-plant assertion |
| D7 RO startup wiring | test_drain_start_wires_real_lifecycle_readback_before_returning_executor | real lifecycle via existing FakeDaemon, successful sandbox control, wrong agent readback refuses/reaps; git clean after success | target missing |
| D7 explicit code env | test_explicit_defender_dir_also_owns_host_fallback_environment | host fallback DEFENDER_DIR/PATH/PYTHONPATH come from code, not workdir | BoxRequest field missing |

## Grounding

C18: the existing playground bot credential succeeds at `ls-remote` and a dry-run push using an explicit helper reset and this tenant's credential file. No remote ref was created. Actual branch writes are exercised by the isolated real-git fixture; completed dev-Forgejo push remains a code-stage integration check.

C19: the dev Forgejo swagger lists state/sort/milestone/labels/poster/page/limit for PR listing, with no head-prefix filter. The contract exercises paginated client filtering and normalized `head.ref` / `html_url` fields.

C21: the bot can GET `/repos/tenants/playground/branches/main`, which returns `protected` and `user_can_push`. The protection-management endpoint returns 403 and is not the enforcement interface. Use the read-only branch endpoint. The current lab repo reports `protected=false`, `user_can_push=true`; operator protection setup is required before activation. This stage did not change it.

## Original contract review and validation (historical)

The independent intent reviewer derived obligations from the design before reviewing the authored suite. Its findings repaired real-file negative fixtures, staged-file isolation, startup read-back wiring, settings/product bypass commits, and exact credential-helper exclusivity. Runtime single-read auditing and narrow ownership/dormancy censuses cover the remaining architectural commitments. Final independent review: accepted with no remaining material findings. Reviewer inspected the final test revision; execution evidence below comes from the orchestrator.

The existing baseline (`test_1108_knowledge_owner.py`, `test_author_shared.py`) passes: 39 tests. Final execution: 49 collected cases, all expected red: 35 missing delivery-module failures, 7 missing ForgejoForge failures, 1 missing BoxRequest field, and 6 no-plant assertion failures. Zero setup errors. Its expected red classes are missing `tenant_delivery`, missing `ForgejoForge`, missing `BoxRequest.defender_dir`, and current read-only startup probes planting files. No fixture setup errors were observed. The six direct read-only probe cases reach and reject the existing transient plant; their subsequent mismatch/read-error assertions remain unexercised until implementation.

Ruff passes. Injection and shared-oracle custom lints report no new findings. Mypy excludes this test directory by project configuration, so it provides no test typing evidence. `spec-graph calls` cannot follow these lazy imports through shared helpers and reports false NO-CALL results. `nullstub` reports its generated forge stub shadowed by the real module; its verdict is void. Neither tool result is claimed as discrimination evidence.

All assertions downstream of absent production targets require implementation-stage execution. The code-stage owner must make the complete suite pass, inspect the positive and negative startup and credential cases, run existing affected branch/box/commit regressions, and perform a real dev-Forgejo branch push/PR integration using protected main. This contract does not claim live Docker confinement or completed Forgejo writes from its HTTP/daemon fakes. Narrow AST censuses cannot prove arbitrary dynamic dataflow; the independent code review must also preserve the single credential owner and dormant boundary.

Run from the worktree root with the project interpreter and worktree import root:

```sh
PYTHONPATH="$PWD" flock /tmp/defender-pytest.lock /workspace/defender/.venv/bin/python -m pytest defender/tests/tenant_1108_delivery -q
```

The interpreter path above is this dev host's existing venv; other machines use their project interpreter. Product CI needs no tenant repository, credential, or dev Forgejo for this suite.
