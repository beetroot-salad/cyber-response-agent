# Development operations

Read only when bootstrapping a development environment, running an investigation, or diagnosing tenant setup.
These are existing CLI procedures, not the desired user onboarding API. Tenant registration belongs
in the product API and its register-tenant command; this cleanup does not implement that interface.
Check the current command's help before using a procedure below.

In this devcontainer use `DEFENDER_DATA_ROOT=/workspace/.defender-data` (gitignored), so the
remote Docker daemon can resolve bind sources. There is no default data root; name the tenant.

## Existing commands and setup

```bash
cd defender && uv venv .venv && uv pip install --python .venv/bin/python -e '.[dev]'   # bootstrap (entrypoints re-exec into .venv themselves)
export DEFENDER_DATA_ROOT=/path/outside/the/checkout   # every run names its tenant; there is no default (#1078)
export TENANT_ID=<uuid-committed-in-the-tenant-repo>  # new tenants: mint with tenant.py new-id before scaffold
git clone <tenant repo> "$DEFENDER_DATA_ROOT/$TENANT_ID/knowledge"   # the tenant's settings + agent knowledge, on the host
python3 defender/cli/tenant.py setup "$TENANT_ID"    # once, after the clone exits 0, before the first run
python3 defender/run.py <alert.json> --tenant "$TENANT_ID"   # one investigation → run dir under $DEFENDER_DATA_ROOT/$TENANT_ID/runs/; --no-learn skips curation enqueue
python3 defender/learning/branch/cli.py --tenant "$TENANT_ID" <run_id> <branch_message_id>   # fork a finished run (by id, under the tenant's runs) into a family of worlds and grade it
python3 defender/learning/loop.py --tenant "$TENANT_ID" --author-drain     # fold the findings queue into lessons; --lead-author-drain is the sibling stage
python3 defender/api/serve.py --tenant <id>           # the stub platform API on 127.0.0.1:8000, seeded for the named tenant(s) (needs the `api` extra: `uv sync --extra dev --extra runtime --extra api`, as CI does — a bare `uv sync --extra api` uninstalls the others); tokens `<id>-analyst`
```

Run `tenant.py setup` with `DEFENDER_DATA_ROOT` set after the clone into
`<root>/<id>/knowledge` has exited successfully. Setup validates that folder and provisions
`<root>/<id>/learning/` as a real directory. It has no default tenant or learning-state
source. `DEFENDER_LEARNING_STATE_DIR` no longer selects runtime state.

To move an existing learning-state directory, stop all runs, forks and drains on every
checkout using it, then name the source explicitly:

```bash
python3 defender/cli/tenant.py setup "$TENANT_ID" --learning-state-from /path/to/old/learning
```

Setup moves only the known queues, markers, locks, deliveries and legacy `runs/` bundles;
Python source and unrelated entries stay at the source. It never merges into occupied
learning state. The source must be disjoint from the data root, except an already-in-place
source equal to the destination. Re-run the same command to complete an interrupted move.
Modes and timestamps are preserved; running as root also preserves owners and groups.
Root-owned legacy state may require migration as root. An unexpected writer that recreates
source records is reported and those records remain for the operator to reconcile.

The drains, standalone author commands, frontend, trace and revert commands require
`--tenant <T>`. Run-associated writers derive the tenant from the accepted run or episode.


## Tenant version control credentials (PR #1253)

Since #1108 P4 every corpus write goes through `defender.learning.author.version_control.TenantDelivery`:
the drains, `tenant.py update`/`propose`/`setup` and the launch-time publish child log in to the
issuer themselves with the AppRole pair in the issuer client config file (`--issuer-config`,
default `<repo>/playground-issuer/client/issuer.json` in dev) and the tenant row's forge binding
(`<T>/tenant.json` `forge: {origin, audience, issuer_role}`). The run process never imports it:
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
role's `client_id` to the audience Forgejo generated, writes `client/issuer.json` and the tenant
row's forge binding, warns if the bot can push `main`, and revokes the root token it used (a
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
admission path; there is no alias or automatic conversion. Choose and save the replacement
with `python3 defender/cli/tenant.py new-id`. The command only prints a UUID.

If a pre-#1120 installation has no knowledge repository, recover it with the old checkout
before this migration. The current `migrate` command does not accept a legacy name.

Before upgrading, stop every run, fork and drain, and drain or clear the curation queue using
the old code. Upgrade every checkout using the data root together. With all writers stopped:

1. Move the entire old named tenant directory to an archive **outside** `DEFENDER_DATA_ROOT`.
   Preserve that archive, including its row, runs, episodes, sessions and learning state.
   Do not change tenant IDs inside historical records or reuse their state for the new tenant.
   A sibling archive inside the data root is refused by its single-tenant guard.
2. Copy the archived `knowledge/` repository to
   `$DEFENDER_DATA_ROOT/<new-uuid>/knowledge`. Change `agent/.tenant-id` to the chosen UUID
   followed by one newline, and commit that change in the knowledge repository. Review and
   update any external credentials or identity claims bound to the old tenant ID.
3. Run `python3 defender/cli/tenant.py setup <new-uuid>`, then
   `python3 defender/cli/tenant.py check <new-uuid>`. Setup creates a fresh UUID tenant row;
   it never imports the archived runtime state. Use the UUID in every CLI, API token and
   integration configuration thereafter.

This is an explicit identity migration. The archive retains the old identity and bytes;
normal UUID lookups cannot reach it. The older `tenant.py migrate` subcommand recovers
pre-#1120 knowledge from checkout history and does not convert tenant IDs.
