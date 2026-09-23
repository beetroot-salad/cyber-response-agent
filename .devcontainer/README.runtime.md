# Dev container vs. runtime container

Two images, on purpose:

| | Dev container (`Dockerfile.dev`) | Runtime container (`Dockerfile.runtime`) |
|---|---|---|
| Role | the "coding machine" — editing, this session, infra tooling | where an investigation actually executes (`defender/run.py`) |
| Carries | terraform, hcloud, codex, docker CLI, ssh, uv, node | **only** python 3.11 + the defender `.[runtime]` deps + defender code |
| Privilege | none special | gets the privilege runsc needs later (the dev container never does) |
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

# hermetic replay smoke test — no key, no egress
docker run --rm defender-runtime defender/.venv/bin/python -m pytest defender -m e2e

# live investigation — needs the LLM key
docker run --rm --env-file .env defender-runtime python3 defender/run.py <alert.json>
```

## The box image (the sandbox itself)

The untrusted **"hands"** — the per-run sandbox `start_box` creates (#1092) — is a THIRD
image, `defender/box.Dockerfile`, distinct from both of the above: it is what `defender-sql`
and the other granted shims actually run inside, and it is what the "hands" row used to
describe. Its name is derived from the tree (`defender/runtime/box/_image.py::image_tag`), so
there is nothing to tag by hand — only to build:

```bash
# build (from the dev container, over the socket onto the HOST daemon — the daemon a box
# actually starts on — with no pull: the image is built locally, never fetched)
python3 defender/scripts/box_image.py build
```

Build it once; it persists on the host daemon until `box.Dockerfile` or
`defender/box-requirements.txt` changes. That list is `uv export` of the core dependencies plus
the `box` extra — regenerate it with `python3 defender/scripts/box_image.py export` after a
relock (a test fails CI while it disagrees with `uv.lock`). A relock that leaves the list alone
(a dev-tool bump, say) keeps the same image. The next `start_box` after a change to either file
faults with a missing-image error naming the build command — `start_box` itself never builds.

## Two caveats

- **Egress is not baked in.** Live gather shells out to `docker --context
  soc-playground exec … curl` (mode-2 in the design). Credentialed egress belongs
  behind the broker, not in the untrusted runtime surface, so until the broker
  exists, mount it at run time instead of baking it:
  `-v /var/run/docker.sock:/var/run/docker.sock -v "$HOME/.ssh":/root/.ssh:ro`.
- **DooD bind paths are host paths.** When the dev container spawns a sibling with
  `-v <src>:/workspace`, the daemon resolves `<src>` on the **host**, not inside the
  dev container. Use the host repo path, not the dev container's `/workspace`.
