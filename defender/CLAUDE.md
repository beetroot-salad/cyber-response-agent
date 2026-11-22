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

## Upgrading

Every upgrade that runs migrations stops the old code first: each entry point (the API, the workers and every run
they start, the learning drains, the lifecycle service) refuses a database whose revision is not exactly its own, and a
migration may lock the tables it changes until it commits. So: stop the API, the workers, the learning drains and the
lifecycle service; run migrations; start the new code. The notes below say only what an upgrade needs beyond that.

## Upgrade from before #1620

No migration. The API now refuses to start when the sign-in realm does not accept its sign-in client and redirect
URI (the rest of the sign-in request, such as its PKCE method, is still met only at first sign-in): before
upgrading, check that the realm's sign-in client lists `<frontend origin>/api/auth/callback` among its valid redirect
URIs (a realm imported from an older realm file may still list only the old callback). A refused start names the
client and the redirect URI. Each start leaves one unfinished login session in the realm until its login timeout.

## Upgrade from before #1565

No migration. The learning store now refuses an item that arrives at a key it already holds with other content
(findings, pitfalls, curation requests), where it used to drop it silently; the same content is still a no-op. A run's
pitfalls are filed in one call, refused whole on a clash. From this upgrade on, a curation request retried across an
upgrade that changes how a run's pitfall rows are built refiles them with other content at their held ids, and is
refused at every try until it is dead: before such an upgrade, let the lead-author lane finish the requests it holds
(none `in_batch`).

## Upgrade from before #1504

A catalog system record's non-GET reads must now be exactly the routes its adapter sends (`READ_ROUTES` in the adapter
module; `GET /adapters` carries them as `reads`, null beside a `reads_unusable` reason for an adapter with no usable
list, and the adapter's reference as `reference`): Elastic's `POST /*/_search` <!-- lint-shippable: ok — the vendor-specific product integration. -->
and `POST /_query`, threat-intel's `POST /lookup`, none for the others. A record with a missing route, an extra one
(`DELETE /*` listed as a read, or a search narrowed to `POST /logs-*/_search`) is refused by `PUT /systems/<id>`, and
at run start the system is down with that reason (no read pass names it, so a case system among them cannot take the
comment), which the readiness check reports. Stop the API and the workers and start the new code together, request the
readiness check (`POST /api/tenants/<tenant-id>/readiness`, then its GET) for each tenant, and re-save each system it
reports down for its reads with `PUT /systems/<id>` and the reads `GET /adapters` shows. Until then those
systems are down, and a tenant whose only query system is one of them has its runs refused. Elastic's in-process <!-- lint-shippable: ok — the vendor-specific product integration. -->
endpoint check now judges only GET and HEAD; the proxy alone refuses any other undeclared route.

## Upgrade from before #1581

Stop the API and the workers first, as in "Upgrading" above: an old worker would complete investigations without
keeping the alert's stored outcome. Run migrations (revision `0025_alert_outcome`). It gives `jobs.alerts` its stored
outcome (filled from each alert's newest completed investigation) and the index the alert list's outcome filter reads,
and refuses a completed investigation with no disposition, or any disposition outside the five codes. It stops,
changing nothing, while any such row exists, naming how many of each; no production investigation has run, so no
remediation is written for them. A list cursor issued before the upgrade is refused once (422, "the filters changed"):
its client starts again from page 1.

## Upgrade from before #1589

Run migrations (revision `0024_drop_findings_count`): it drops `jobs.learning_jobs.findings_count`, which nothing
decided on. A job's stored findings carry its id (`source_run`): that is the lasting record of what its end stored.
The finish audit event of a completed job whose findings were stored also names how many rows its end added
(`added=N`; a refused one names none), but an audit event can be lost in a crash just after the commit.

A job's entry runs from its worker's code copy, not from the job image, so an upgraded worker's jobs write the
new end record. An end record written before the upgrade and read after it keeps its `findings_count`: the new
worker ignores it.

## Upgrade from before #1557

A learning job's oracle boxes no longer keep their scratch in the tenant's folder: it lives under the claim's folder
(`<data root>/.job-scratch/<claim>/shared/`), which the job container mounts, and the box binds it read-only. The worker
now removes a job's `.job-scratch/<claim>/` and `.job-sockets/<claim>/` once its child is gone, and at its start
(serving or draining) whatever is under both, each only once the claim's helper no longer runs: a helper records itself
in `<data root>/.job-owners/<claim>/` first and removes that record last. A helper from before this upgrade writes
no record, so stop the old worker and let its helpers end (about 30 seconds) before the new one starts. A folder it cannot remove is logged as an error and tried again at the next start. Once, after
upgrading: remove every `<data root>/<T>/episodes/*/.oracle-scratch` (nothing reaches them any more). Those an oracle
box wrote are owned by root and need root to remove; until they are gone the tenant's offboarding fails on them.

## Upgrade from before #1487

Stop the API, the workers, the learning drains and the lifecycle service, then run migrations (revision
`0023_findings_at_job_end`). A learning job's findings are now stored by the worker in the transaction that records the
job `completed`, and the post-step only runs the author's tick. The migration moves every learning job still marked
`pending` (its findings possibly never published, since #1170 a post-step in a job container could not reach the
database) to `refused`, and logs how many per tenant: these jobs' findings are not recovered. Rebuild the job image and
upgrade the worker and the job host together. Delete the old `<job>.post-step.json` and `<job>.post-step-pending.json` files from each
tenant's runs folder (`<data root>/<tenant>/runs/`), and any half-written copy a crash left beside them
(`<job>.post-step.json.staged-<hex>`), before starting the new code: the runs listing refuses them, and the migration
cannot reach the data root. For example `find <data root>/*/runs -maxdepth 1 \( -name '*.post-step.json' -o -name
'*.post-step-pending.json' -o -name '*.post-step.json.staged-*' -o -name '*.post-step-pending.json.staged-*' \)
-delete`.

## Upgrade from before #1534

A run's disposition is its closing record, a row of the `closing_record` table in the run's session database; nothing
writes or reads `report.md` any more. There is no jobs-database migration: the disposition column and `no_report` are
unchanged. Once:

1. Stop the workers, the learning drains and every running job, then rebuild the job image on every execution host
   (`docker build -f .devcontainer/Dockerfile.job -t defender-job:latest .` from the repository root, or the image
   `DEFENDER_JOB_IMAGE` names). An old job image writes `report.md` and no record, and its session pointer carries no
   closing-record mark: a new worker reading such a run (its job end says the close committed) fails it `unparseable`,
   worded as recorded before closing records were kept.
2. Drain or abandon queued learning jobs and in-flight episodes first: their source runs and arms were recorded before
   #1534, so the questioner and the judge refuse them.

Afterwards every run made before #1534 reads as a fault wherever it is read, including after a later run of the same case
adds the table to its database: a run's own pointer, not its database, says whether it keeps a closing record. Its run
page will not re-render, the trace CLI and held-out scoring show a fault row for it, and an old episode's judge pass
refuses. Nothing is converted.

## Upgrade from before #1161

Every API route is under `/api` (`/api/me`, `/api/admin/tenants/<T>/resume`, `/api/openapi.json`); nothing answers at
the old paths, and the notes below name the new ones. Once:

1. Run migrations (revision `0020_signin_attempts`): it adds `identity.signin_attempts`, where a sign-in in flight
   keeps its record until the callback.
2. In the sign-in realm, replace the client's redirect URI with `<DEFENDER_API_FRONTEND_ORIGIN>/api/auth/callback`;
   until then every sign-in fails at the identity provider (invalid redirect URI). `DEFENDER_KEYCLOAK_REDIRECT_URI` is no longer
   read: the URI is derived from the origin. Remove it.
3. Serve the app through the ingress (`python -m defender.api_server.ingress`, Caddy on PATH, the frontend built to
   `defender/frontend/dist`): it serves the frontend and sends `/api` to the API, in plain HTTP on
   `DEFENDER_INGRESS_LISTEN`. TLS ends in front of it: put the TLS terminator before it. See
   `docs/development-operations.md`.
4. Point every API-key or OAuth program client at the `/api` paths.
5. The interactive docs pages (`/docs`, `/redoc`) are gone and `DEFENDER_API_DOCS` is not read: remove it. Load
   `/api/openapi.json` in a viewer served from another origin instead.

## Upgrade from before #1471

Stop the API, the workers and the credential proxy first, then run migrations (revision `0021_ticket_write`). Rebuild the
job image, and upgrade the helper and the credential proxy together: a proxy that does not know the new write-pass claim
refuses the token. The worker now requires `DEFENDER_API_FRONTEND_ORIGIN` (the API's own name and origin rule) and
exits with status 2 without it.

Removed: the case record's `comment:` key (a record that still has it is refused, naming the key: delete it; the
comment's wording is fixed; `PUT /api/tenants/<tenant-id>/case-record` likewise takes only `replaces` and `system_id` and
refuses a `comment_body` with 422, and `GET` no longer answers it: update any client that sends or reads it) and the
operator's `run.py --update-ticket` (an operator run never comments and never mints a
write-back token). A ticket comment is now the start-investigation request's `update_ticket` flag. The run page's own
`--update-ticket` flag is gone too: its ticket line shows whenever a receipt exists, as the job's own report.

A case system's stored access declaration must now declare exactly one write, its adapter's comment route spelled as
the adapter spells it (the same method and segments, `*` only where the route has `*`), and only GET reads; the route
must hold exactly one `*`, where the ticket goes, so an adapter whose comment route has none or several cannot be a
case system (the credential proxy writes under no other shape). A wider
write that used to cover the route (a `*` in place of a literal), a second write route, or any non-GET read is refused:
by `PUT /systems/<id>` and the readiness check, and at run start, where a flagged investigation then ends with an `error`
receipt and no comment (the request is still accepted). After upgrading, request the readiness check (`POST /api/tenants/<tenant-id>/readiness`) for each tenant with a case
record and re-save any case system it names with `PUT /systems/<id>`.

The credential proxy now forwards only an allowed list of an adapter's request headers (`Content-Type`, `Accept`,
`User-Agent`, `Idempotency-Key`, in any case) and drops every other one, the request still going; a credential header
is still refused. A tenant adapter that relied on another header reaching its system loses it.

Removed (#1471): `tenant.py check <tenant-id>`, `tenant.py update` and `tenant.py propose` (`tenant.py check --folder
<path>` stays; `check <id>` is now a usage error, exit 2). Use the requests instead: the readiness check
(`POST /api/tenants/<tenant-id>/readiness`, then its GET) judges a tenant's repo and stored records; the adoption request
(`POST /api/tenants/<tenant-id>/systems/<system-id>/adoptions`) carries a carried adapter's base files to the tenant's
repo as a pull request, and any other connect output is left in the handoff folder for a person to commit. A merged
`main` is published by the next launch-time publish (a run or a drain start). `cli/learning/revert_lesson.py` stays.

A tenant's `<data root>/<T>/runs` is now made by the lifecycle's `prepare` step, and the job lane no longer makes it (a
missing one fails the worker's claim `worker_error`). Once, with `DEFENDER_DATABASE_DSN` and `DEFENDER_DATA_ROOT` set, make
it for the tenants created before: `python -m defender.lifecycle make-runs-folders`. It covers each `active` tenant, is
idempotent, and prints the ids it made. A tenant whose `<T>` folder is missing or whose `runs` is a link is refused: the
sweep finishes the others, then exits non-zero naming every refused tenant. Fix those and run it again.

## Upgrade from before #1083

Stop the API, the workers and the lifecycle service, then run migrations (revision `0016_list_indexes`). It builds one
index each on `jobs.alerts`, `jobs.investigations` and `jobs.learning_jobs`, and each build blocks writes to its table
until it finishes: on a large alerts table, a running intake or worker would stall or time out meanwhile.

## Upgrade from before #1366

A tenant's systems and its case record are versioned records in the database, and a tenant's
systems are exactly those its records name, from its creation; nothing reads a tenant's
`settings/systems/` or `settings/case-record.yaml` any more. A tenant admin writes them through the
API under `/api/tenants/<tenant-id>` (#1470): `PUT /systems/<id>` (settings, access declaration, enabled), `PUT
/systems/<id>/credentials` and `PUT /case-record`; `GET /adapters` lists the adapters a record may
name. Credentials live at a per-generation path `<tenant>/<system>/g<N>`. Once:

1. Stop the API, the credential proxy and the workers (an old process reads a table this upgrade
   drops), then run migrations (revisions `0015_system_records` and `0019_drop_records_mark`). They
   create the NOLOGIN role `defender_proxy_reader`, which reads `tenancy.system_versions` and the
   `id` and `state` columns of `tenancy.tenants`, nothing else: create a login that is a member of
   it and set the proxy config's `records_dsn` to that login's DSN in place of `data_root` (an old
   config refuses to start). The second of those migrations stops, changing nothing, while any tenant
   that is not offboarded predates #1366's records (its systems never moved onto them): without
   them it would read as a tenant with no systems. Recreate such a development database.
2. Rebuild the job image on every execution host (`docker build -f .devcontainer/Dockerfile.job -t
   defender-job:latest .` from the repository root, or the image `DEFENDER_JOB_IMAGE` names): an
   old job image refuses the new records wire.
3. Delete `settings/systems/` and `settings/case-record.yaml` from the tenant's repository:
   `tenant check` reports them as retired until they are gone.

From then on the tenant admin changes a system with `PUT /systems/<id>`, naming the version it
replaces (`GET /systems` shows it) and whether it is enabled; a change of its base, CA or auth block
raises its credential generation, and its credentials are set again (`PUT
/systems/<id>/credentials`). Connect hands its result to the tenant admin as a folder: its
validator takes `--handoff <folder>` and no longer `--tenant`.

## Upgrade from before #1532

The API's start check asks OpenBao who its token is (lookup-self) before its metadata read, and the writer policy
`store_policies()` writes now grants that lookup. A token minted with OpenBao's default policy already holds it; one
minted without it (`-no-default-policy`) refuses start, naming `DEFENDER_OPENBAO_ADDR` and
`DEFENDER_API_OPENBAO_TOKEN_FILE`, until the writer policy is re-applied. Once, before starting the new API: render
the policy for the API's mount, `python -c 'from defender.credential_proxy import store_policies;
print(store_policies(kv_mount="<mount>")["writer"])' > writer.hcl` from the repository root, then
`bao policy write <the writer policy's name> writer.hcl`.

## Upgrade from before #1485

Migrations `0017_retire_learning_cutover` and `0018_learning_set_aside_indexes`, as in "Upgrading" above. `0017`
stops, changing nothing, while any tenant still has a learning cutover pending: finish or resume it with the code at
revision `0016_list_indexes` first.

The #1278 learning-state cutover is retired: cut over on a revision before #1485 first; a deployment that never did will lose its old learning folder.

## Upgrade from before #1454

Programs (#1307) now have their own table, `identity.programs`; users and memberships are people only. Run migrations
(revision `0012_programs_table`). It stops, changing nothing, while any program row exists (a `users` row of kind
`program`) or any membership's role is not `admin`: no deployment created a program through the #1307 API, so
remove any left in a development database first. Stop the API and the
lifecycle service before migrating; an older process fails on every program read once the columns are gone.

## Upgrade from before #1469

A box can no longer reach a host unix socket, and the code proves it. #1170 gave every gVisor container host-socket
access through one daemon-wide `--host-uds=open`, boxes included; the box runtime and the job runtime are now two
registrations of the same gVisor binary, and the helper's caller check (`SO_PEERCRED`, the container's process list and
the `peer` refusal) is gone: the job socket is 0600 in a 0700 folder, and the filesystem alone decides who may use it.
On every execution host, once:

1. Re-register `runsc`, the box runtime, without host-socket access: `runsc install -- --oci-seccomp`.
2. Register the job runtime next to it: `runsc install --runtime runsc-job -- --oci-seccomp --host-uds=open`.
3. Restart Docker. `DEFENDER_BOX_RUNTIME` stays the only setting: `runsc` boxes get `runsc-job` job containers, `runc`
   boxes get `runc` job containers (no sandbox, as before). `runsc-job` cannot be named as a box runtime.
4. Before a process's first box under `runsc`, the code runs a box that tries to connect to a host socket in its own bind
   and refuses the start (naming this section) unless the runtime refuses it. A host not migrated refuses boxes and the
   operator's `run.py <alert>` at that check, and a job container is refused for the missing `runsc-job` (`box:
   start_failed`, with the remedy). A pass is kept in memory per docker daemon and registration, so a registration
   changed under a running worker is checked again at its next box; a runtime binary upgraded without a re-registration,
   or a shim edited without the registration changing, is seen at the next process start.
5. A job whose container cannot reach its socket (`runsc-job` registered without `--host-uds=open`) fails its row through
   its own refusal; the helper logs "the job never reached its socket" with this cause. The check's folder is
   `<data root>/.box-checks/`; a crash can leave an inert socket there, and nothing sweeps it.

## Upgrade from before #1170

The worker no longer runs a job as its own child process. For each claim it starts a per-job host helper
(`python -m defender.job_host`), which runs the job in a container of its own, scoped to the job's tenant. Before
upgrading a worker:

1. Build the job image on every execution host: `docker build -f .devcontainer/Dockerfile.job -t defender-job:latest .`
   from the repository root, or set `DEFENDER_JOB_IMAGE` to an image you built from it. The helper never pulls. Without
   the image every job fails its row (an investigation `worker_error`, a learning job `failed: entry_error`), and no
   job runs outside a container.
2. Register gVisor with `--host-uds=open` on every execution host, as the job runtime `runsc-job` (see "Upgrade from
   before #1469": the box runtime `runsc` is registered without it). The job's socket is a host unix socket mounted
   into the job's gVisor guest, and gVisor refuses the guest's connection to it without this. Run the worker natively
   on the execution host: the helper must share the docker daemon's mount paths
   (`docs/decisions/vps-compose-deployment.md`, brain confinement). A worker in a container beside the daemon fails
   every job.
3. Job containers start under the job runtime derived from the box runtime (`DEFENDER_BOX_RUNTIME`; #1469). Set `DEFENDER_JOB_NETWORK` to the Docker network
   from which the job reaches the credential proxy and the model provider. Leave OpenBao and the database off that network.
   It is required on every deployment, and must be a bridge network created for the jobs (`docker network create
   <name>`), not one docker compose made: unset, docker's default network, `host`, `container:<name>` or a compose
   project's network, the worker refuses to start (exit 2) naming it. It also refuses while docker cannot answer.
4. The job container runs as the uid that owns the data root, and its socket lives under
   `<data root>/.job-sockets/<claim>/`. A data root whose socket path would exceed 107 bytes fails every job as a start
   failure: keep the data root's path short.

`run.py --job` is now only a job container's entry. From a host shell it does nothing and exits non-zero. Queue the
investigation for the worker instead, or run it by hand with `run.py <alert> --tenant <id>`, which is unchanged.

## Upgrade from before #1414

Feedback issues on the tenant's Forgejo repository need the bot to write issues, labels and comments. Run
migrations (revision `0011_merge_eligibility`), then rotate each existing tenant's forge credential once
(`POST /api/admin/tenants/<T>/rotate-forge-credential`): only an integration created or rotated by this code is granted
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
2. A tenant admin saves the mapping with `PUT /api/tenants/<tenant-id>/alert-mapping` (the six entries, as `GET` on the same
   route answers them).
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
   (`POST /api/admin/tenants/<T>/rotate-forge-credential`). Rotation gives it the sign
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
4. With the lifecycle's settings in place and `serve` running, `POST /api/admin/tenants/<T>/resume`
   and wait for `active` (`GET /api/admin/tenants/<T>`).
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
