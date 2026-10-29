# Development operations

Read only when bootstrapping a development environment, running an investigation, or diagnosing tenant setup.
Tenants are created, rotated and offboarded through the platform API and the tenant lifecycle
(#1214); the commands below are the host's side of that. Check the current command's help before
using a procedure below.

In this devcontainer use `DEFENDER_DATA_ROOT=/workspace/.defender-data` (gitignored), so the
remote Docker daemon can resolve bind sources. There is no default data root; name the tenant.

## Existing commands and setup

```bash
cd defender && uv venv .venv && uv pip install --python .venv/bin/python -e '.[dev]'   # bootstrap (entrypoints re-exec into .venv themselves)
export DEFENDER_DATA_ROOT=/path/outside/the/checkout   # every run names its tenant; there is no default (#1078)
export DEFENDER_DATABASE_DSN=<the tenant database>   # host processes read the tenant records from it (see below)
export TENANT_ID=<the id POST /admin/tenants answered>   # an `active` tenant: see "Creating a tenant"
python3 defender/cli/tenant.py check "$TENANT_ID"    # admitted and its folder accepted; every finding reported
python3 defender/run.py <alert.json> --tenant "$TENANT_ID"   # one investigation → run dir under $DEFENDER_DATA_ROOT/$TENANT_ID/runs/; --no-learn skips curation enqueue
python3 defender/cli/learning/branch.py --tenant "$TENANT_ID" <run_id> <branch_message_id>   # fork a finished run (by id, under the tenant's runs) into a family of worlds and grade it
python3 defender/learning/loop.py --tenant "$TENANT_ID" --author-drain     # fold the findings queue into lessons; --lead-author-drain is the sibling stage
python3 defender/api/serve.py --tenant <id>           # the stub platform API on 127.0.0.1:8000, seeded for the named tenant(s) (needs the `api` extra: `uv sync --extra dev --extra runtime --extra api`, as CI does — a bare `uv sync --extra api` uninstalls the others); tokens `<id>-analyst`
```

### Creating a tenant (#1214)

An administrator posts `POST /admin/tenants` (202; `Location` is the tenant's URL). The record is
`creating` until the lifecycle has done its steps, which `python -m defender.lifecycle serve` runs
(dev: the management service and the host actor in one process; hosted: one process each): the
repository `tenants/<id>` from the committed template, a bot with write access to it alone, the
credentials and the forge integration, the host secret file under the secrets directory, and
`$DEFENDER_DATA_ROOT/<id>/` with the clone in `knowledge/`, an empty `learning/` and a first
publish. Then the tenant is `active`. Nothing is cloned or set up by hand, and there is no
`tenant.json` or other on-disk tenant row.

- `GET /admin/tenants/<id>` shows the state, the pending action, the step and the actor, and the
  failure of a failed step; `POST /admin/tenants/<id>/resume` retries it (a failure at `adopt` is
  cleared only by `python -m defender.lifecycle adopt`).
- `POST /admin/tenants/<id>/invitations` invites the first member (an `active` tenant with no
  members); `POST /admin/tenants/<id>/rotate-forge-credential` replaces the credential generation;
  `POST /admin/tenants/<id>/offboard` removes the tenant's folder, secrets, credentials and
  repository (the repository is deleted 30 days later).
- The lifecycle's settings are the files and variables `defender/lifecycle/config.py` names
  (the forge admin token and OpenBao management login are read from files, never the environment).
  OpenBao's address is `https`; the config refuses cleartext.
- The tenant's knowledge repository lives on the forge. Edit it through its pull requests; humans
  merge, and `python3 defender/cli/tenant.py update <id>` publishes the merged `main`.

The drains, standalone author commands, frontend, trace and revert commands require
`--tenant <T>`. Run-associated writers derive the tenant from the accepted run or episode.

## Host process settings (#1214)

Host processes (`run.py`, the drains, `tenant.py`, `python -m defender.lifecycle`, the launch-time
publish child) read the tenant records from the PostgreSQL that `DEFENDER_DATABASE_DSN` names
(dev, on the compose network: `postgresql://defender:dev-only-change-me@postgres:5432/defender`);
unset, each refuses, naming the variable. The base environment scrub drops it from every box,
model lane and host child, and only the publish child's launcher adds it back.

OpenBao and its OIDC issuer are fixed service names, not settings: `https://openbao:8200` and
`https://openbao:8200/v1/identity/oidc`, defined once in `defender/configuration/issuer.py`. The
infrastructure routes the name (DNS, the compose network) and makes OpenBao's certificate trusted
where the process's TLS client looks (`SSL_CERT_FILE`/`SSL_CERT_DIR`, as the compose file does for
Forgejo with the dev CA).

## Tenant version control credentials (PR #1253)

Since #1108 P4 every corpus write goes through `defender.learning.author.version_control.TenantDelivery`:
the drains, `tenant.py update`/`propose` and the launch-time publish child mint the tenant's token
themselves (`forge_credential`, #1214): the AppRole of the tenant's live credential generation in
the tenant records, its secret from the host secret file that generation records, and the
deployment's issuer (the fixed service names above). The run process never imports it:
a run reads its own copy of one published export. Production deployment is not defined yet.
`delivery.py` owns publish → draft/batch → commit → push/PR and revert. `repository.py`
owns git semantics, `forgejo.py` the concrete Forgejo API, `auth.py` Vault identities, and
`credentials.py` git's credential channel. `transport.py` owns the isolated transfer context. Export, batch and durable-record helpers live
in that same package. The legacy GitHub author path stays separate until P4.

Use Forgejo 17.0.0 or newer with [Authorized Integrations](https://forgejo.org/docs/v17.0/user/api/authorized-integrations/)
and [Vault Identity tokens](https://developer.hashicorp.com/vault/api-docs/secret/identity/tokens).
For each tenant:

1. Create a dedicated non-admin bot with write access only to that tenant's knowledge
   repository. Protect `main` against bot pushes; humans merge the bot's pull requests.
2. Create a Generic JWT Authorized Integration for that bot. Bind its issuer to Vault's
   HTTPS identity issuer, require `tenant_id=<tenant>`, restrict it to the exact repository,
   and grant `write:repository` and `write:issue`. Record the generated audience (not secret).
   Add Vault's hostname to `[authorized_integration] ALLOWED_DOMAINS`; Forgejo must reach
   its HTTPS discovery and JWKS endpoints and trust their CA.
3. Configure a Vault Identity OIDC role whose `client_id` is that audience, whose template
   signs the tenant claim, and whose TTL is at most 600 seconds. Restrict the workload's
   Vault policy to reading `identity/oidc/token/<that-role>`. Vault entity metadata and role
   bindings are operator-owned, never model-controlled input.
4. The trusted orchestrator authenticates to Vault using its deployment's workload identity
   and supplies an authenticated `httpx.Client` to `ForgejoIdentity(tenant_id=..., issuer=...,
   role=..., audience=..., client=...)`. The issuer is normally
   `https://vault.example/v1/identity/oidc`. Supply that identity explicitly to
   `TenantDelivery.open(..., origin=<Forgejo clone URL>, identity=..., client=<Forgejo HTTP client>)`. Vault login,
   renewal, CA trust and workload isolation belong to deployment wiring; this module does
   not discover credentials from a clone, command line, environment or home directory.

The identity fetches signed JWTs from Vault, checks tenant/issuer/audience/lifetime locally,
and refreshes before a bounded operation would outlive the cached token. Forgejo verifies
signatures and enforces repository and claim restrictions. API calls use Bearer headers;
git receives a URL-scoped Bearer header through a sealed anonymous memory descriptor. JWTs
are absent from process arguments, environment variables and disk files. Every transfer
creates a temporary bare repository with a private home, empty template, and owned git
configuration. Only the tenant object database and its hash format are shared; clone refs,
hooks, remotes, includes, system/user config, config environment injection, proxies and
tracing settings are excluded. The destination is supplied explicitly to the factory,
never selected through `origin`, `pushurl` or URL rewrite rules in the clone.

Fetch writes objects into the tenant database and atomically imports only the explicit
`refs/remotes/origin/*` branch mappings after the authenticated process has ended. Push
supplies one commit-to-review-branch refspec, with tag following and submodule recursion
disabled. Credentials, no-prompt/no-hook/redirect policy, maintenance settings and the wall
timeout are owned by the transfer context. Git's complete process group is killed on exit;
the credential descriptor is closed before local ref hooks can run. Agent boxes receive
exported files, never either authenticated client. HTTPS trust for git comes from the host
trust store; inherited CA/proxy environment overrides are intentionally excluded. Use HTTPS
for Forgejo in deployment; HTTP is for isolated local fixtures only.

The default dev-container image is 17.0.0. Existing volumes are not migrated automatically;
back them up and follow Forgejo's upgrade procedure before restarting an older installation.
No production migration or deployment is implied by the image bump.

### The dev issuer (#1108 P4)

The devcontainer compose file runs OpenBao 2.4.1 as the `openbao` service: file storage, a
static seal from a 32-byte key file and a TLS listener signed by a dev CA, reachable only on the
compose network at `https://openbao:8200` (no host port). Its storage, seal key, CA, recovery
keys and the AppRole client config live under `<repo>/playground-issuer/` (gitignored and
excluded from docker build contexts). This is a dev posture: the seal key sits beside the data
it seals, and any same-uid process in the dev container can read the client config. Forgejo's
`/data` is the host folder `<repo>/playground-knowledge/`, so `docker compose down -v` keeps it;
Forgejo allows only `openbao` as an integration issuer and trusts the dev CA through
`SSL_CERT_DIR`.

Provision from the dev container, after the stack is up, with the lab tenant's id, its bot and
its repository:

```bash
.devcontainer/provision-dev-issuer.sh provision <tenant-id> --bot <bot login> --repo <owner/name>
```

It is idempotent. It prepares `playground-issuer/` (and restarts `openbao` on it), initialises
OpenBao, creates the signing key, the tenant's OIDC role (TTL 600 s, `tenant_id` from entity
metadata), an AppRole whose policy reads only that role's token and the entity binding them,
creates the bot's Generic JWT Authorized Integration in Forgejo (the issuer, `tenant_id` equal to
the tenant, restricted to the repository, `write:repository` and `write:issue`) and sets the
role's `client_id` to the audience Forgejo generated, writes `client/<tenant-id>/issuer.json` and
the tenant row's forge binding naming it, warns if the bot can push `main`, and revokes the root token it used (a
later run regenerates one from the recovery keys inside the issuer container). Forgejo 17 has no
API for Authorized Integrations: the script fills the web form as the bot, after resetting the
bot's unused password. The signing role is created before the integration because Forgejo caches
the issuer's JWKS: an integration attempted against an empty JWKS keeps failing until Forgejo
restarts. Pass `--rotate-secret` to mint a new AppRole `secret_id`.

Moving an existing Forgejo off the old `forgejo-data` named volume, once: stop `forgejo`, run
`.devcontainer/provision-dev-issuer.sh migrate-forgejo-data` (it copies the volume into
`playground-knowledge/` and keeps the volume), then `docker compose up -d`. A 15.x installation
becomes 17.0.0 at the same time; back up first and follow Forgejo's upgrade notes. The old
volume is no longer declared, so `down -v` does not remove it; delete it yourself once the lab
repository, its bot and its history are confirmed on the new Forgejo
(`test_live_dev_issuer.py`, run with `-m live`, checks them).

Live JWT verification is separate from the fast fake-backed suite. Provision a disposable
Forgejo 17 service and an HTTPS OIDC fixture issuer with a matching RSA key and JWKS.
Create private `fixture-admin/blue` and `fixture-admin/other`, give `tenant-bot` write access
to both (so integration restrictions are actually exercised), protect blue's `main`, and
create a bot integration restricted to blue with `tenant_id=blue` and the two scopes above.
Set `FORGEJO_TEST_CONFIG` to a test-only JSON file containing `origin` (blue's clone URL),
`issuer`, `audience`, `key_file` (fixture RSA private PEM), and `other_origin`. Then run
`flock /tmp/defender-pytest.lock pytest defender/tests/tenancy/tenant_1108_delivery/test_live_forgejo.py -m live`.
The issuer's JWKS key id must be `fixture`; these signing keys are fixture data only.

## Migrating named tenants to UUIDs (#1187)

Tenant IDs are canonical lowercase UUIDs. Names such as `acme` are refused by every normal
admission path; there is no alias or automatic conversion. The replacement is a new tenant:
`POST /admin/tenants` mints its UUID (save it).

If a pre-#1120 installation has no knowledge repository, recover it with the old checkout
before this migration; `tenant.py migrate` is retired and no longer exists here.

Before upgrading, stop every run, fork and drain, and drain or clear the curation queue using
the old code. Upgrade every checkout using the data root together. With all writers stopped:

1. Move the entire old named tenant directory to an archive **outside** `DEFENDER_DATA_ROOT`.
   Preserve that archive, including its row, runs, episodes, sessions and learning state.
   Do not change tenant IDs inside historical records or reuse their state for the new tenant.
   A sibling archive inside the data root is refused by its single-tenant guard.
2. Create the new tenant (`POST /admin/tenants`, then wait for it to be `active`; see "Creating a
   tenant"). Its repository starts from the template: push the archived `knowledge/` history
   into it by hand as a pull request, keeping `agent/.tenant-id` as the lifecycle wrote it (the
   new UUID followed by one newline). Review and update any external credentials or identity
   claims bound to the old tenant ID.
3. Run `python3 defender/cli/tenant.py update <new-uuid>` once the pull request is merged, then
   `python3 defender/cli/tenant.py check <new-uuid>`. The new tenant never imports the archived
   runtime state. Use the UUID in every CLI, API token and integration configuration thereafter.

This is an explicit identity migration. The archive retains the old identity and bytes;
normal UUID lookups cannot reach it. The retired `tenant.py migrate` subcommand recovered
pre-#1120 knowledge from checkout history and never converted tenant IDs.
