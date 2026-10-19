# defender/

Experimental alert-triage product: an in-process PydanticAI investigation runtime plus an offline learning loop. Product agent prompts under `skills/` are distinct from Claude Code skills. The lab environment is maintained separately under `playground-v2/` and `playground-v2/infra/`. <!-- lint-shippable: ok — developer documentation identifies the separate lab, not a product assumption. -->

## Design and authority

- `SKILL.md` defines runtime-agent behavior. Code and executed probes establish current behavior; the current approved design establishes intended behavior. Report disagreements rather than silently letting implementation override intent.
- Read `docs/principles.md` at the repository root for design work. Issue decisions may explicitly add to or override those principles.
- Read `defender/docs/learning-loop.md` before changing loop shape, questioner/judge/curator prompts, or lessons.

## Shared conventions

- Product code is tenant-neutral: no assumptions about a tenant's systems. System-specific behavior belongs with its adapter; shared product modules do not import adapters for data. Elastic is an explicit vendor-specific product integration. <!-- lint-shippable: ok — documents the explicit product-integration exception. -->
- Use existing seams: `_git` for git, `_io` for bounded UTF-8 reads and JSONL, `_frontmatter` for frontmatter, and guarded I/O for model-writable trees. Consult the relevant checker or `docs/development-lints.md` before implementing a competing helper.
- Diagnostics use `_log` and `logging.getLogger(__name__)`; command results remain stdout, refusals remain visible stderr or API errors. Entrypoints configure logging. Detailed rules are in `docs/runtime-development.md`.
- Runs live under `$DEFENDER_DATA_ROOT/<tenant>/runs/`, outside tracked source; no default data root or tenant. Devcontainer bind-mount details and existing CLI procedures are in `docs/development-operations.md`.
- Tests live in `tests/`, including runtime unit tests and hermetic e2e replay. Run affected files and relevant replay locally, not the full suite; every pytest invocation here uses `flock /tmp/defender-pytest.lock`. In worktrees, verify imports and set `PYTHONPATH=<worktree-root>`. <!-- lint-hygiene: ok — shared host test lock, not a product data path. -->
- `.github/workflows/ci.yml` at the repository root defines current CI gates; `.claude/spec-flow.json` records the project profile. Fix new lint findings; never hide them by updating a baseline. Regenerate baselines only for pre-existing findings moved/refingerprinted by an unrelated change, and explain why.

## Find the relevant context

| Work | Start here |
|---|---|
| Runtime, permissions, close-time review | `runtime/`; its scoped instructions and `docs/runtime-development.md` |
| Branch replay, questioner, judge, curators | `learning/`; its scoped instructions and `docs/learning-development.md` |
| Platform API and tenant registration | `api/`; its scoped instructions |
| Tests and fixtures | `tests/`; its scoped instructions |
| Gather prompts and per-system knowledge | `skills/gather/`, `skills/<system>/` |
| Evals | `../evaluations/README.md` |
| Detailed vocabulary, layout, change locations | `docs/development-map.md` |
| Lint seams and suppressions | Relevant `tooling/lint/lint_*.py` at the repo root; `docs/development-lints.md` as needed |

Load only the references relevant to the task. Historical explanations live in `docs/archive/`.

## Upgrade from before #1187

Tenant, run and episode ids are opaque UUIDs and episodes live under each tenant's data root. Before upgrading a
shared data root, stop every run, fork, and drain, and drain or clear its curation queue with
the old code. Upgrade every checkout using that root together; mixed versions are unsupported.
For a tenant already identified by a UUID, run
`python3 defender/cli/retire_legacy_runs.py --tenant <T>` once, adding
`--old-episodes-root <old DEFENDER_EPISODES_BASE>` when retiring that tenant's old external
episodes. The command renames old entries into `runs-legacy/` and `episodes-legacy/`; runs
listing refuses until they have been retired. `DEFENDER_EPISODES_BASE` and `_tenant.json` are
retired.

Named tenants instead require the explicit offline UUID migration in
`docs/development-operations.md` before UUID tenant setup; their old directories remain archived
and are not passed to the retirement command. No legacy name is an alias.
