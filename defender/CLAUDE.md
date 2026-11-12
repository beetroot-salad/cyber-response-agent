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
- Tests live in `tests/`, including runtime unit tests and hermetic e2e replay. While working, run only what your change can reach: `pytest --testmon` plus the relevant replay (see `tests/CLAUDE.md`). In worktrees, verify imports and set `PYTHONPATH=<worktree-root>`.
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

## Upgrade from before #1366

A tenant's systems and its case record are versioned records in the database, written only by
`defender/cli/tenant.py` (its top describes the subcommands); nothing reads a tenant's
`settings/systems/` or `settings/case-record.yaml` any more, and a tenant's systems are only those
its records name (`tenant.py catalog` lists the adapters a record may name). Credentials live at a
per-generation path `<tenant>/<system>/g<N>`. Once:

1. Run migrations (revision `0013_system_records`). It also creates the NOLOGIN role
   `defender_proxy_reader` (SELECT on `tenancy.system_versions` and `tenancy.records_mark` only):
   create a login that is a member of it and set the proxy config's `records_dsn` to that login's
   DSN in place of `data_root` (an old config refuses to start).
2. Per tenant that existed before this change (one created after it needs none): publish its
   merged knowledge (`tenant.py update <tenant-id>`: the import reads the published export, not
   the clone), then `python3 defender/cli/tenant.py import <tenant-id> --dry-run`, fix every file
   it names in the tenant's repo, publish again, and `tenant.py import <tenant-id>`. It runs once
   per tenant, writes every system and the case record at version 1, credential generation 1, and
   copies no credential. Until then the tenant's runs are refused and `tenant check` reports it,
   each naming the import.
3. Per system, at generation 1: `tenant.py set-credentials <tenant-id> <system> <file> --for-version 1
   --token-file <operator token file>` (the file is JSON `{"kind": ..., "fields": {...}}`). The set
   at the old path `<tenant>/<system>` is never read again; until this is done the proxy refuses the
   system and `tenant check` reports it.
4. Delete `settings/systems/` and `settings/case-record.yaml` from the tenant's repository:
   `tenant check` reports them as retired until they are gone.

From then on: change a system with `tenant.py systems <tenant-id> --export <dir>`, edit the
folder, `tenant.py set-system <tenant-id> <system> <dir>/<system> --replaces <its version>` (it
keeps the system enabled or disabled as it is; `--disabled` or `--enabled` changes that); a
change of its base, CA or auth block raises its credential generation, and its credentials are
set again. Connect hands its result to the operator as such a folder: its validator takes
`--handoff <folder>` and no longer `--tenant`.

## Upgrade from before #1454

Programs (#1307) now have their own table, `identity.programs`; users and memberships are people only. Run migrations
(revision `0012_programs_table`). It stops, changing nothing, while any program row exists (a `users` row of kind
`program`) or any membership's role is not `admin`: no deployment created a program through the #1307 API, so
remove any left in a development database first. Stop the API and the
lifecycle service before migrating; an older process fails on every program read once the columns are gone.

## Upgrade from before #1170

The worker no longer runs a job as its own child process. For each claim it starts a per-job host helper
(`python -m defender.job_host`), which runs the job in a container of its own, scoped to the job's tenant. Before
upgrading a worker:

1. Build the job image on every execution host: `docker build -f .devcontainer/Dockerfile.job -t defender-job:latest .`
   from the repository root, or set `DEFENDER_JOB_IMAGE` to an image you built from it. The helper never pulls. Without
   the image every job fails its row (an investigation `worker_error`, a learning job `failed: entry_error`), and no
   job runs outside a container.
2. Register gVisor with `--host-uds=open` on every execution host: `runsc install -- --oci-seccomp --host-uds=open`, then
   restart Docker. The job's socket is a host unix socket mounted into the job's gVisor guest, and gVisor refuses the
   guest's connection to it without this. The flag is daemon-wide, so every box gets the capability; a follow-up issue
   weighs a job-only runtime.
3. Job containers start under the box runtime (`DEFENDER_BOX_RUNTIME`). Set `DEFENDER_JOB_NETWORK` to the Docker network
   from which the job reaches the credential proxy and the model provider. Leave OpenBao and the database off that network.
4. The job container runs as the uid that owns the data root, and its socket lives under
   `<data root>/.job-sockets/<claim>/`. A data root whose socket path would exceed 107 bytes fails every job as a start
   failure: keep the data root's path short.

`run.py --job` is now only a job container's entry. From a host shell it does nothing and exits non-zero. Queue the
investigation for the worker instead, or run it by hand with `run.py <alert> --tenant <id>`, which is unchanged.

## Upgrade from before #1414

Feedback issues on the tenant's Forgejo repository need the bot to write issues, labels and comments. Run
migrations (revision `0011_merge_eligibility`), then rotate each existing tenant's forge credential once
(`POST /admin/tenants/<T>/rotate-forge-credential`): only an integration created or rotated by this code is granted
`write:issue`. Until a tenant rotates, its issue calls are refused (403) and logged every feedback tick; its
open-issue requests and replies wait in the queue and are all served on the first tick after the rotation. Nothing is
given up. The first feedback tick after the upgrade lists each existing feedback issue's comments once; after
that, a tick reads only the issues the forge lists new comments on.

The management service reads each active tenant's merge whitelist when its record is older than 20 s, and the feedback
tick reads no comments from a record older than `LEARNING_FEEDBACK_ELIGIBILITY_MAX_AGE` (default 60 s). Keep that bound
well above 20 s, or the tick will find the record stale between the service's reads.

## Upgrade from before #1345

The tenant's alert mapping lives in the database; nothing reads `settings/alert-mapping.yaml` any more. After migration
`0007_alert_mapping`, investigations and runs for a tenant are refused until, once per tenant:

1. Add `title` and `description` to the tenant's `settings/alert-mapping.yaml`, if its alerts should have them: the file
   does not name them, and an entry left out is unmapped, so its alerts would list with neither.
2. `python3 defender/cli/tenant.py set-alert-mapping <tenant-id> <that file>`. The top of `defender/cli/tenant.py`
   describes the six entries.
3. Delete the file from the tenant's repository.

## Upgrade from before #1377

A run's cost is now the sum of a spend ledger (a table in the run's session database, one row per model
response any agent of the run received, review calls included), so `cost_usd` and the run file's
`total_cost_usd` count what the run really paid. Old run files keep their main-only totals: totals before
and after this change are not comparable. Stop the API and workers before running the migration: it adds a
required column with no default, so an older process fails on every insert until it is upgraded. Run
migrations (revision `0010_cost_lower_limit`): the API's investigations gain `cost_is_lower_limit`, true
when `cost_usd` is "at least" that much (a spend write failed, or the run was killed before it sealed its
ledger). The mark is worked out when a record is read: a row that
ended after it started, with a cost and no final figure from its worker, reads "at least" (this includes such rows
already in the database); every other existing row reads exact.

## Upgrade from before #1363

The credential proxy's final frame gains a last field, `origin` (whose failure a refusal is:
`request`, `setup` or `access`). Upgrade the proxy and every run image together: a new run refuses
an old proxy's eight-field record whole and reads it as lost access (the run ends `proxy-access`,
exit 8), and an old run does not read the new field. A call cut for this request alone is now an
uncharged failed call with exit 3 in the queries table (its own error class, `request-cut`).

## Upgrade from before #1412

The credential proxy streams each upstream reply to the run in its own frame format (content
type `application/vnd.defender.proxy-reply`) instead of one JSON document, and no longer scrubs
credentials an upstream echoes. Upgrade the proxy and every run image together: an old run
refuses the new reply, and a new run refuses an old one, both as the proxy's own transport fault.
A reply over 8 MiB is still refused; the fault now tells the model to narrow the query. That
limit is no longer configurable: remove `max_response_bytes` from the proxy's config file before
upgrading, or the proxy refuses to start.

## Upgrade from before the Docker removal (#1391 O1, O2, O5)

Every system with network access is reached only through the credential proxy: a system is
proxied because its folder holds an `access.yaml`, and there is no access-method key. The settings
check now judges each system's whole folder against the keys its adapter reads, so a tenant on
old settings has every such system down at once until this is done. In one tenant commit, make
every folder under `settings/systems/` (elastic, cmdb, identity, change-mgmt, threat-intel, <!-- lint-shippable: ok — the vendor-specific product integration. -->
host-state, the case system — ticket, jira or servicenow — and any other) meet this rule:

1. `config.env` holds only the keys the adapter reads, and none is `CHANGE-ME` or blank. Every
   other key is refused by name. That removes, wherever they appear, `<PREFIX>_TRANSPORT`
   (including `JIRA_TRANSPORT` and `SERVICENOW_TRANSPORT`), `<PREFIX>_DOCKER_CONTEXT`,
   `<PREFIX>_BASTION_HOST`, `<PREFIX>_URL_BASE` and `<PREFIX>_HOST`, and for elastic  <!-- lint-shippable: ok — the vendor-specific product integration. -->
   `ELASTIC_TRANSPORT` and `ELASTIC_RETENTION_DAYS`. The stubs read `<PREFIX>_TIMEOUT_SEC`, ticket <!-- lint-shippable: ok — the vendor-specific product integration. -->
   also `TICKET_KEY_PATTERN`. host-state reads no key: delete its `config.env`. A key a system
   puts in a URL path (elastic's index patterns) must be one path segment: no `/ \ ? # % ;`. <!-- lint-shippable: ok — the vendor-specific product integration. -->
2. `access.yaml` is always required, with the system's `base` and `auth` (bearer, field
   `api_key`), and holds no `CHANGE-ME`. Any request other than a GET is declared: the case
   system's comment write under `writes`, and threat-intel's lookup under `reads` as
   `{method: POST, path: "/lookup"}` (the value now travels in the body). Copy the template's
   folders. host-state's base is an endpoint-query service (an endpoint-security product's query
   API) that answers `GET /hosts`, `/hosts/{host}/processes`, `/hosts/{host}/accounts`,
   `/hosts/{host}/accounts/{user}/authorized-keys`, `/hosts/{host}/files/sha256?path=…`,
   `/hosts/{host}/packages` and `/containers/{id}`.
3. A stored `bearer` credential per system, and a published export carrying the declarations
   (the proxy reads only `exports/current`).
4. Remove a leftover folder of the case system retired by #1359 (the case system is named by
   `settings/case-record.yaml` since then; `tenant check` names the folder).

A host, record id or other value the agent names that is not one path segment is now refused
before it is sent, and the proxy refuses a path holding an escaped `/` or `\`.

host-state's `health-check` no longer reports a docker context, and a host the service does not
enroll is now the agent's to fix (`UpstreamFault`, from the service's 404) rather than refused
before any call.

## Upgrade from before #1391

Elastic is reached only through the credential proxy; its Docker access is gone. <!-- lint-shippable: ok — the vendor-specific product integration. -->
A tenant's `systems/elastic/` needs, in one commit: <!-- lint-shippable: ok — the vendor-specific product integration. -->

1. `config.env` with the two index keys (`ELASTIC_EVENTS_INDEX`, `ELASTIC_ALERTS_INDEX`) and no
   other key: since the Docker removal above, any other key — `ELASTIC_TRANSPORT`,
   `ELASTICSEARCH_URL`, `KIBANA_URL`, `ELASTIC_DOCKER_CONTEXT`, `ELASTIC_ES_CONTAINER`,
   `ELASTIC_KIBANA_CONTAINER`, `ELASTIC_SSL_VERIFY` — is refused by name.
2. `access.yaml`: `base` (the cluster URL, a path allowed), basic `auth`, `reads` of
   `POST /*/_search` and `POST /_query`, and `ca:` (inline PEM certificates, nothing else) when the
   cluster's certificate comes from a private CA. `ca` is then the only trust for that system, the
   OAuth token URL included, and refuses an `http://` base or token URL.
3. A stored `basic` credential for a read-only user: `read` on the events and alerts indexes plus
   the cluster `monitor` privilege (without it `health-check` answers a settings fault naming it).

`health-check` no longer reports Kibana. Fault classes now follow the proxy's: 401 settings, 403
the agent's, 5xx transport. The exceptions: a 403 on `health-check`, `query`, `alerts` or `esql` is a
settings fault naming the missing privilege (`monitor`, or `read` on the configured indexes). `esql`
names its sources in the query, so each must fall within the configured patterns (FROM, TS, LOOKUP
JOIN) or the call is refused before the proxy. Commands are allow-listed: a query starts with FROM, TS,
ROW or SHOW (ROW and SHOW read nothing), and later commands are WHERE, EVAL, STATS, KEEP, DROP, RENAME,
SORT, LIMIT, DISSECT, GROK, MV_EXPAND and LOOKUP JOIN; any other command (ENRICH, FORK, RERANK, ...),
a subquery, a remote `cluster:index`, any triple-quoted string or run of three `"` outside a backtick
name, and unparsable text are refused (#1347 O2a, r6.4.4).

## Upgrade from before #1382

Record ids (tenant, user, membership, alert, investigation) are PostgreSQL `uuid`. Run migrations
(revision `0005_uuid_ids`); it stops, changing nothing, on any row whose id is not UUID text: recreate
such a development database. A membership's `invited_by`/`ended_by` hold a user id, or NULL for the
system (they held `'system'`).

## Upgrade from before #1163

Runs reach `http-proxy` systems through the credential proxy with a request token the run signs
as the tenant's own sign-only AppRole, and publish now also refuses a repository whose bot can
**merge** `main`. On a #1214 deployment, once:

1. Run migrations (revision `0003_sign_login` adds the generation's sign-login columns; every
   entry point refuses a database still at `0002_tenancy`). Mount transit at `transit/`.
2. Extend the lifecycle's management policy with create, read, update and delete on
   `transit/keys/request-token-*`. If that policy names AppRoles by prefix (for example
   `auth/approle/role/delivery-*`), give the new sign-only AppRoles `auth/approle/role/sign-*`
   the same capabilities; their entities, `tenant-<T>-<salt>-sign`, already match `tenant-*`.
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
