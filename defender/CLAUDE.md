# defender/

Alert-triage product: an in-process PydanticAI investigation runtime plus an offline learning loop. Product agent prompts under `skills/` are distinct from Claude Code skills. The lab environment is maintained separately under `playground-v2/` and `playground-v2/infra/`. <!-- lint-shippable: ok — developer documentation identifies the separate lab, not a product assumption. -->

## Design and authority

- `SKILL.md` defines runtime-agent behavior. Code and executed probes establish current behavior; the current approved design establishes intended behavior. Report disagreements rather than silently letting implementation override intent.
- Read `docs/principles.md` at the repository root for design work. Issue decisions may explicitly add to or override those principles.
- Read `defender/docs/learning-loop.md` before changing loop shape, questioner/judge/curator prompts, or lessons.

## Shared conventions

- Product code is tenant-neutral: no assumptions about a tenant's systems. System-specific behavior belongs with its adapter; shared product modules do not import adapters for data. Elastic is an explicit vendor-specific product integration. <!-- lint-shippable: ok — documents the explicit product-integration exception. -->
- Top-level packages form one order, bottom to top, declared in `tooling/lint/lint_import_order.py` (`ORDER`); imports point down it. Place a new package there; an upward import needs a design change, not a baseline entry.
- A leading underscore below a top-level package (the module `tenancy/_tenant.py`, a `_helper` in `systems/verbs.py`) means private to that package. Another package imports the package's door (its `__init__`, or `records/formats.py` for record formats) or a public module, never the underscore name: add a name another package needs to the door (see `lazy_door.py`), or drop the underscore. The root seams (`_io`, `_git`, `_log`, ..., `_filesystem`) are shared; tests are exempt. `tooling/lint/lint_private_imports.py` enforces it, with no baseline.
- Use existing seams: `_git` for git, `_io` for bounded UTF-8 reads and JSONL, `_frontmatter` for frontmatter, and guarded I/O for model-writable trees. Consult the relevant checker or `docs/development-lints.md` before implementing a competing helper.
- Diagnostics use `_log` and `logging.getLogger(__name__)`; command results remain stdout, refusals remain visible stderr or API errors. Entrypoints configure logging. Detailed rules are in `docs/runtime-development.md`.
- Runs live under `$DEFENDER_DATA_ROOT/<tenant>/runs/`, outside tracked source; no default data root or tenant. Devcontainer bind-mount details and existing CLI procedures are in `docs/development-operations.md`.
- Tests live in `tests/`, including runtime unit tests and hermetic e2e replay. While working, run only what your change can reach: `pytest --testmon` plus the relevant replay (see `tests/CLAUDE.md`). Before shipping, run the full suite locally as CI's `test` job does. In worktrees, verify imports and set `PYTHONPATH=<worktree-root>`.
- `.github/workflows/ci.yml` at the repository root defines current CI gates. Fix new lint findings; never hide them by updating a baseline. Regenerate baselines only for pre-existing findings moved/refingerprinted by an unrelated change, and explain why.

## Find the relevant context

| Work | Start here |
|---|---|
| Runtime, permissions, close-time review | `investigation/`; its scoped instructions and `docs/runtime-development.md`. What a run may call and whether it is up is `systems/`; model clients are `providers/`; the session store is `records/session_store/` |
| Branch replay, questioner, judge, curators | `learning/`; its scoped instructions and `docs/learning-development.md` |
| Platform API and tenant registration | `api/`; its scoped instructions |
| Tests and fixtures | `tests/`; its scoped instructions |
| Gather prompts and per-system knowledge | `skills/gather/`, `skills/<system>/` |
| Evals | `../evaluations/README.md` |
| Detailed vocabulary, layout, change locations | `docs/development-map.md` |
| Lint seams and suppressions | Relevant `tooling/lint/lint_*.py` at the repo root; `docs/development-lints.md` as needed |

Load only the references relevant to the task. Historical explanations live in `docs/archive/`.

## Upgrade from before #1163

Runs reach `http-proxy` systems through the credential proxy with a request token the run signs
as the tenant's own sign-only AppRole, and publish now also refuses a repository whose bot can
**merge** `main`. On a #1214 deployment, once:

1. Run migrations (revision `0003_sign_login` adds the generation's sign-login columns; every
   entry point refuses a database still at `0002_tenancy`). Mount transit at `transit/`.
2. Extend the lifecycle's management policy with create, read, update and delete on
   `transit/keys/request-token-*`.
3. Create the policy `defender-tenant-sign`: `update` on
   `transit/sign/request-token-{{identity.entity.metadata.tenant_id}}`.
4. Set the proxy's policy to KV read plus `update` on `transit/verify/request-token-*`, and
   replace the proxy config's `tenant_keys`, `tenant_exports`, `transit_mount` and
   `openbao_addr` with `data_root` (an old config refuses to start).
5. Rotate each existing tenant's forge credential
   (`POST /admin/tenants/<T>/rotate-forge-credential`). Rotation gives it the sign
   login, its signing key `request-token-<T>` and the merge whitelist on `main` (the
   organisation's `Owners` team, never the bot). Until then its runs that reach an `http-proxy`
   system refuse at start, and its publish refuses. A tenant whose repository is owned by a user
   rather than an organisation fails rotation at `protect`: move the repository to an
   organisation first.

A create or rotate job in flight across the upgrade finishes normally.

## Upgrade from before #1279

`run.py --run-id` is gone: the system mints every run id, announced as the first stdout line
`run_id=<uuid>`. A run dir is created exclusively and never resumed. Learning pages are published per tenant
(dev only) under `<publish root>/<tenant>/learning/`, and the dev run-page copy under
`<publish root>/<tenant>/runs/<run id>/`. The publish root is no longer worked out from the
checkout: a `dev` host sets `DEFENDER_RUN_VISUALIZATIONS_DIR` (the devcontainer sets it to the main
checkout's `run-visualizations/`); unset, nothing is published. By hand, once: delete
`defender/learning/frontend/{lessons,queues}.{json,html}` and the pre-#1186 debris under
`defender/learning/` (`_author.lock`, `.author-drain.lock`, `author-queue/`); delete old flat
`run-visualizations/<run id>/` folders.

## Upgrade from before #1214

Tenants are rows in PostgreSQL that the lifecycle (`python -m defender.lifecycle serve`) creates, rotates
and offboards; the on-disk `tenant.json` is retired, and so are `tenant.py setup`, `new-id`,
`scaffold` and `migrate` (and `setup --learning-state-from`). Every host entry point reads the tenant
records from `DEFENDER_DATABASE_DSN`, at exactly this code's revision, and works only for an
`active` tenant. The lab tenant moves once:

1. Forgejo 17 or newer first (the dev image is 17.0.0; back up and follow Forgejo's upgrade notes, see
   `docs/development-operations.md`), then run migrations. Migration 0002 only updates the rows
   already in `identity.tenants` (it turns each into a failed create at its first step, which no
   worker takes until it is resumed), and nothing ever wrote the lab's row there, so the lab has no
   tenant row after it. Check: `SELECT id, state FROM tenancy.tenants WHERE id = '<T>'`. If that
   returns the row, skip step 2.
2. Insert the lab's row by hand, as the failed create the backfill would have made (the lifecycle has
   no adopt command). The state/pending-action CHECK allows `creating` only with `create` pending;
   `created_at` is NOT NULL and every other column stays NULL:
   `INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor, failure)
   VALUES ('<T>', now(), 'creating', 'create', 'names', 'service', 'registered before #1214: record
   its forge wiring if it has a repository, then resume')`.
3. Record the lab's repository by hand, so the create job keeps it and its clone instead of making
   `tenants/<T>`: `INSERT INTO tenancy.forge_wiring (tenant_id, repo, origin) VALUES ('<T>', '<repo>',
   '<origin>')`, where `<origin>` is exactly what `git -C <data root>/<T>/knowledge remote get-url
   origin` prints (prepare keeps only the clone at `<T>/knowledge`, and refuses a clone of anything
   else) and `<repo>` is its `<org>/<name>` path. It refers to the row from step 2.
4. With the lifecycle's settings in place and `serve` running, `POST /admin/tenants/<T>/resume`
   and wait for `active` (`GET /admin/tenants/<T>`).
5. Then delete by hand what the old setup left: `<data root>/<T>/tenant.json`, `client/<T>/` in
   the old issuer directory, and the unsalted OpenBao entries
   (`bao delete` each of `identity/oidc/role/tenant-<T>`, `auth/approle/role/delivery-<T>` and
   `identity/entity/name/tenant-<T>`).
6. Learning starts empty: prepare creates `<data root>/<T>/learning/` and nothing is copied. By
   hand, once: delete the old learning state left under the checkout's `defender/learning/`
   (queues, markers, locks, deliveries, legacy `runs/` bundles).

## Upgrade from before #1187

Tenant, run, episode and world ids are opaque UUIDs and episodes live under each tenant's data root. Before upgrading a
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

World declarations use `label` as metadata. The host assigns `world_id` UUIDs once before
preflight and publishes the manifest create-only; every world artifact uses that UUID.
Pre-UUID world manifests and label-keyed arm rosters require a fresh episode; readers never
derive or mint missing IDs or translate an old roster. `arms.json` maps world UUIDs to arm
UUIDs; labels remain manifest metadata and CLI selectors. Family admission checks the roster
byte budget before publication or preflight, independently of label length.
