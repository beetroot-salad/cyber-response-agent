# `connect` — pre-merge checklist

Walk this before calling a connection done. Anything unchecked goes in
the user-facing summary as an open item.

## Adapter CLI

- [ ] Written to `defender/scripts/tools/{system}_cli.py`, nowhere else.
- [ ] Copies the closest reference shape — a `_stub_transport.py`-based
      stub (`cmdb_cli.py`) for an HTTP-over-`docker exec` read source, or
      `elastic_cli.py` for a credentialed direct source.
- [ ] `argparse` with `health-check` plus one subcommand per verb.
- [ ] `--raw` emits a stable JSON envelope matching the sibling adapters
      (per `docs/state-surface-adapters.md`). Default output is short
      formatted text.
- [ ] Exit codes: `0` success (zero hits included), `1` query error,
      `2` connectivity/auth failure, `64` usage error (free via the
      shared `AdapterArgumentParser` — don't reinvent it).
- [ ] Native query language passed through unmodified (query source), or
      keyed on an identifier (lookup source) — no translation, no field
      renaming.
- [ ] Non-secret config loaded from
      `knowledge/environment/systems/{system}/config.env` via the
      `DEFENDER_DIR` pattern; secrets from env vars only.
- [ ] Missing-config / missing-secret errors print an actionable hint and
      exit `2`. Import failures print the `uv pip install -e '.[dev]'`
      bootstrap and exit `2`.
- [ ] No `--run-dir` salt wrapping in the adapter (the runtime hook does
      that).
- [ ] `--help` examples use real, maintainer-confirmed field names and
      values — not generic placeholders.

## Shim & registration

- [ ] `bin/defender-{system}` exists, is executable, and matches a
      sibling shim (`bin/defender-cmdb`) with only the CLI filename
      changed.
- [ ] The shim name is **not** in `NON_ADAPTER_SHIMS`
      (`hooks/_cmd_segments.py`) — so it auto-gates as a data-source
      adapter everywhere. No per-hook edit was made.
- [ ] `run-settings.json` was checked: the `Bash(defender-* *)` glob
      already covers the shim. An explicit per-CLI entry was added **only
      if** the repo lists tools individually (rare) — and any such change
      is flagged in the summary.

## Dependencies

- [ ] Stdlib-only when feasible. A vendor SDK only when the API genuinely
      needs one.
- [ ] If a dep was added: a named extra in `defender/pyproject.toml`,
      mirrored into `[dev]`, and `uv pip install --python .venv/bin/python
      -e '.[dev]'` re-run so `uv.lock` is updated and committed.

## Tests (Phase 3)

- [ ] `defender/.venv/bin/python3 scripts/tools/{system}_cli.py
      health-check` exits `0` and reports connected.
- [ ] A sample query / lookup with `--raw` returns output.
- [ ] The maintainer has eyeballed the sample output and confirmed the
      fields look right.
- [ ] (Optional, when surfaces are thin or the vendor is unfamiliar)
      Field-model probe: a fresh-context **Haiku** subagent, handed only
      the adapter `--help` + draft `execution.md` + the draft SKILL's
      `gaps`/`read_guidance` + a realistic task, surfaced no field name,
      enum, or index it had to guess at — or the obvious gaps it found
      were filled.

## Per-system knowledge

The bar is **lean**, not comprehensive — everything here grows
post-merge via the offline lead-author and the learning loop. Mirror an
existing sibling for exact shape; `docs/system-skill-shape.md` is the
contract.

- [ ] `skills/{system}/SKILL.md` exists — Visibility surface only,
      frontmatter `name: defender-{system}` + `description`. Covers the
      Visibility fields (match the sibling's field names) and keeps a
      one-line `## Execution` pointer.
- [ ] `gaps` is declared loudly — what the system **cannot** answer here,
      including silent-failure shapes (e.g. a `verdict: unknown` miss).
- [ ] No connectivity, credential, or CLI-flag detail leaked into
      `SKILL.md` (that belongs in `execution.md` — issue #261).
- [ ] `skills/{system}/execution.md` exists — CLI invocation, flags,
      query syntax, exit codes, connectivity — and carries the "do not
      Read the CLI source to discover flags" line.
- [ ] `knowledge/environment/systems/{system}/config.env` has the
      deployment's non-secret values; tracked in git if it holds no
      secrets, gitignored if it would encode a sensitive deployment.
- [ ] A couple of `skills/gather/queries/{system}/{id}.md` seed templates
      follow `queries/SCHEMA.md` (`id: {system}.{template-id}`, Goal,
      What to summarize, Query with `${param}`, Common pitfalls). Only
      the ones you're certain of — **not** a catalog from API docs.

## Credential boundary

- [ ] No tokens, passwords, API keys, or basic-auth strings anywhere in
      the adapter, config.env, docs, or commit.
- [ ] The maintainer was told which env var names to set and confirmed
      them (or explicitly deferred, noted in the commit).
- [ ] No `curl` with `-H "Authorization: ..."` in docstrings or examples.

## Scope discipline

- [ ] Only these were written: `scripts/tools/{system}_cli.py`,
      `bin/defender-{system}`, `skills/{system}/`,
      `knowledge/environment/systems/{system}/config.env`,
      `skills/gather/queries/{system}/` seeds, and — only if needed —
      `pyproject.toml` / `uv.lock` / `run-settings.json`.
- [ ] No touches to `hooks/`, `learning/`, `lessons/`, the runtime
      `defender/SKILL.md`, the invlang skill, or another system's files.
- [ ] No lessons authored and no bulk query catalog pre-built — those
      grow post-merge.
- [ ] The reference adapters (`elastic_cli.py`, the stubs) were not
      rewritten.
- [ ] Any legitimate divergence from the default flow (unusual upstream,
      weird access topology) is surfaced in the summary for human review —
      not silently patched over, not blocked outright.

## Commit

- [ ] A branch was created (`connect/{system}` or
      `connect/{system}-update`).
- [ ] Commit message is clear about what was added and which system.
- [ ] The maintainer has a summary: files touched, health-check result,
      sample-query outcome, env vars to set, open TODOs.
- [ ] **Nothing was merged or pushed without explicit direction.** The
      human review gate is non-negotiable. (`/ship` can open the PR.)

## Enough to build on

The query catalog and the lessons corpus fill in post-merge — from real
runs via the offline lead-author, and from the learning loop. Your
scaffold exists so those flows have something to build on, and so the
first runs can find and route to the system. Ask:

- [ ] Does `SKILL.md` let the defender decide *when* to route here
      (`when_to_use` / `gaps`) without reading anything credentialed?
- [ ] Does `execution.md` let the gather subagent dispatch a query
      without reading the CLI source?
- [ ] Do the seed templates plus `--help` give a fresh-context Haiku
      enough to compose a valid first query?
- [ ] Is anything missing that the lead-author would need to start
      extracting templates from a real run?

A judgment call, not a completeness bar. If you're writing things you
aren't sure will matter, stop — post-merge will catch them.
