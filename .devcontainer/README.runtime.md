# Dev container vs. runtime container

Two images, on purpose:

| | Dev container (`Dockerfile.dev`) | Runtime container (`Dockerfile.runtime`) |
|---|---|---|
| Role | the "coding machine" — editing, this session, infra tooling | where an investigation actually executes (`defender/run.py`) |
| Carries | terraform, hcloud, codex, docker CLI, ssh, uv, node | **only** python 3.11 + the defender `.[runtime]` deps + defender code — never tenant data (mounted at run time) |
| Privilege | privileged, for its own jobs daemon (#1475); already root-equivalent through the host docker socket | gets the privilege runsc needs |
| Maps to the sandbox design | the trusted orchestration/dev host | (superseded — see "The box image" below) |

The dev container now mounts the host Docker socket (Docker-outside-of-Docker), so
it can build and run the runtime image as a **sibling** container on the host —
which is how the two stay separate. This makes the dev container root-equivalent on
the host daemon; that's acceptable because it's the trusted coding machine and it's
the seam that spawns the isolated runtime.

## Build & run

Context is the repo root; a `.dockerignore` keeps it lean.

```bash
# build (from the dev container via the socket, or from the host)
docker build -f .devcontainer/Dockerfile.runtime -t defender-runtime .

# hermetic replay smoke test — no key, no egress; replays run as the test fixture tenant
# (baked in under defender/tests/fixtures/), and some tests read the starter tenant
# (knowledge/tenant-template), so the repo's knowledge/ is mounted
docker run --rm -v "<HOST_REPO_PATH>/knowledge":/workspace/knowledge:ro \
    defender-runtime defender/.venv/bin/python -m pytest defender -m e2e
```

Every run names its tenant, and there is no default (#1078). A tenant is created through the
lifecycle service's admin API (`python -m defender.lifecycle serve`; see "Creating a tenant" in
`defender/docs/development-operations.md`): the service makes the tenant's repository, bot and
credentials and records the tenant in PostgreSQL, and a run works only for an `active` tenant. The
runtime container needs `DEFENDER_DATABASE_DSN` and the same `DEFENDER_DATA_ROOT` mount the
lifecycle's host side prepares; nothing is cloned or set up by hand. A tenant from before #1214 is
moved once by hand (see "Upgrade from before #1214" in `defender/CLAUDE.md`).

```bash
# live investigation — needs the LLM key, the same data root (the tenant's knowledge is in it),
# the compose network (the tenant records are in the `postgres` service, and the token issuer is the
# `openbao` service) and the dev issuer's CA, which `SSL_CERT_DIR` must name (a folder `prepare`
# has run `openssl rehash` on, mounted read-only like the dev container's)
docker run --rm --env-file .env \
    --network cyber-response-agent_devcontainer_default \
    -e DEFENDER_DATA_ROOT=/data -v "<HOST_DATA_ROOT>":/data \
    -e DEFENDER_DATABASE_DSN=postgresql://defender:dev-only-change-me@postgres:5432/defender \
    -e SSL_CERT_DIR=/etc/ssl/certs:/etc/ssl/dev-issuer-ca \
    -v "<HOST_REPO_PATH>/playground-issuer/trust":/etc/ssl/dev-issuer-ca:ro \
    defender-runtime python3 defender/run.py <alert.json> --tenant <tenant-uuid>
```

`<tenant-uuid>` is the id the lifecycle's `POST /admin/tenants` answered, an `active` tenant (a
tenant id is an opaque UUID, not a name like `playground`). The network is the compose project's
default one: `name:` in `docker-compose.yml` plus `_default` (`docker network ls` shows it). The DSN
and the trust folder are the dev stack's (`defender/docs/development-operations.md`, "Host process
settings" and "The dev issuer"); the trust folder is a HOST path, as below.

**Tenant knowledge is mounted, never baked (#1106, #1120).** A tenant's knowledge folder holds
its settings (endpoints, later credentials) and its model-facing knowledge — deployment data,
not code. The image carries none of it; `run.py` reads it from the tenant's folder under the
mounted data root, `$DEFENDER_DATA_ROOT/<tenant>/knowledge`, and `.dockerignore` keeps
`knowledge/` and `.defender-data` out of the build context. From the dev container, `<HOST_…>` is a HOST path (see the caveat below).

## The box image (the sandbox itself)

The untrusted **"hands"** — the per-run sandbox `start_box` creates (#1092) — is a THIRD
image, `defender/box.Dockerfile`, distinct from both of the above: it is what `defender-sql`
and the other granted shims actually run inside, and it is what the "hands" row used to
describe. Its name is derived from the tree (`defender/box/_image.py::image_tag`), so
there is nothing to tag by hand — only to build:

```bash
# build (from the dev container, over the socket onto the HOST daemon — the daemon a box
# actually starts on — with no pull: the image is built locally, never fetched)
python3 defender/box/image_cli.py build
```

Build it once; it persists on the host daemon until one of these changes (#1097):
`box.Dockerfile`; the lock's entries for the core dependencies plus the `box` extra;
`pyproject.toml`'s core or `box` requirements; or its `[tool.uv]`. A `[tool.ruff]`-style edit,
or a relock that only moves dev-only or runtime-only packages, keeps the same image. A relock
that moves a package the runtime stack SHARES with the image (`idna`, reached through
pydantic's `email` extra), or changes which extras of such a package the runtime asks for,
renames it too — the name deliberately errs toward an extra rebuild, never a stale image. The
next `start_box` after a change that renames it faults with a missing-image error naming this
same command — `start_box` itself never builds.

## Two caveats

- **Egress is not baked in.** Live gather shells out to `docker --context
  soc-playground exec … curl` (mode-2 in the design). Credentialed egress belongs
  behind the broker, not in the untrusted runtime surface, so until the broker
  exists, mount it at run time instead of baking it:
  `-v /var/run/docker.sock:/var/run/docker.sock -v "$HOME/.ssh":/root/.ssh:ro`.
- **DooD bind paths are host paths.** When the dev container spawns a sibling with
  `-v <src>:/workspace`, the daemon resolves `<src>` on the **host**, not inside the
  dev container. Use the host repo path, not the dev container's `/workspace`.
