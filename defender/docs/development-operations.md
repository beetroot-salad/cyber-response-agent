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
python3 defender/learning/loop.py --author-drain     # fold the findings queue into lessons; --lead-author-drain is the sibling stage
python3 defender/api/serve.py --tenant <id>           # the stub platform API on 127.0.0.1:8000, seeded for the named tenant(s) (needs the `api` extra: `uv sync --extra dev --extra runtime --extra api`, as CI does — a bare `uv sync --extra api` uninstalls the others); tokens `<id>-analyst`
```

Run `tenant.py setup` once, from the main checkout, with `DEFENDER_DATA_ROOT` set (there is no
default data root), after the clone into `<root>/<id>/knowledge` has exited 0 (clone with a
credential helper or an ssh agent, never a credential in the URL; setup adopts the folder and
copies nothing), and no run, fork or drain in flight on any checkout of the host, as the same
user that runs defender; a destination already occupied makes setup refuse, naming it in the
message. (Adopting an existing (B)/(C) installation whose old entries are root-owned may need
setup run as root — that adoption case only.)


## Tenant version control credentials (PR #1253)

Production deployment and drain wiring are not defined yet; delivery remains dormant until
P4. The host-side API is `defender.learning.author.version_control.TenantDelivery`.
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
