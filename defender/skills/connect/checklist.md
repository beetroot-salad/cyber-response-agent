# `connect` — pre-merge checklist

The mechanical bar is automated. Run:

```bash
python3 defender/skills/connect/validate_scaffold.py {system}
```

and fix every FAIL before going further. It verifies the structural
contract a script can check:

- adapter at `scripts/adapters/{system}_cli.py`, with the shared
  `_adapter.py` installed;
- the CLI `--help` runs and exposes `health-check`, and a bad invocation
  exits `64`;
- the `bin/defender-{system}` shim exists, is executable, and auto-gates
  as an adapter (not in `NON_ADAPTER_SHIMS`);
- `config.env` carries no inline secrets;
- `skills/{system}/SKILL.md` has `name: defender-{system}` and a
  `## Execution` pointer, and `execution.md` exists;
- any seed templates have valid `id: {system}.<name>` frontmatter.

(For the MCP path there is no adapter/shim to check — `validate_scaffold.py`
is CLI-specific. Run the judgment list below either way.)

This file covers the rest — the calls a script can't make.

## Judgment checks

- [ ] **Sample results look right.** The maintainer eyeballed real output
      and confirmed the fields match what they expect.
- [ ] **`gaps` are honest.** `SKILL.md` declares what the system *cannot*
      answer here, including silent-failure shapes — enough that a reader
      who'd never touched this system wouldn't fall in blind.
- [ ] **The CLI conforms to the client.** The Haiku alignment loop was
      run (`cli-adapter.md`): cosmetic divergences became CLI changes, and
      only irreducible vendor constraints were documented. You are not
      teaching Haiku your aesthetics.
- [ ] **Native query passes through unmodified** (or the source keys on an
      identifier) — no translation, no field renaming.
- [ ] **Aggregation happens in the source where it can.** If the source
      has a query language that aggregates server-side, the adapter
      exposes it and returns the answer — not a payload the agent must
      reduce. The download-and-reduce fallback (native filter +
      `defender-sql`, recipe in `execution.md`) was used only because the
      source can't aggregate.
- [ ] **The scaffold is lean, not a catalog.** A couple of seed templates
      you're sure of, not a speculative set mined from API docs.
- [ ] **Credential boundary held by eye, too.** No tokens, passwords, or
      auth-bearing cURL anywhere in the adapter, docs, examples, or commit
      — not just in `config.env` (which the script scans).
- [ ] **Env vars communicated.** The maintainer was told which env var
      names to set and confirmed them (or explicitly deferred, noted in
      the commit).
- [ ] **One system.** If others came up in the interview, they were noted
      for a separate re-run, not folded in here.
- [ ] **Divergences surfaced.** Any legitimate departure from the default
      flow (odd upstream, unusual access topology, a vendor auth scheme
      `_adapter.py` doesn't cover) is called out in the summary for human
      review — not silently patched, not blocked.
- [ ] **Human review checkpoint cleared (CLI path).** The maintainer read
      the generated adapter and approved it *before* it ran against the
      live system — not only at the final diff (`cli-adapter.md`).
- [ ] **Nothing merged or pushed** without explicit direction. The human
      review gate is non-negotiable. (`/ship` opens the PR.)

## Enough to build on

The query catalog and the lessons corpus fill in post-merge. Your
scaffold exists so those flows have a foundation and the first runs can
find and route to the system. Ask:

- [ ] Does `SKILL.md` let the defender decide *when* to route here
      (`when_to_use` / `gaps`) without reading anything credentialed?
- [ ] Does `execution.md` let the gather subagent dispatch without reading
      the CLI source?
- [ ] Do the seed templates plus `--help` give a fresh-context Haiku
      enough to compose a valid first query?
- [ ] Is anything missing that the offline lead-author would need to start
      extracting templates from a real run?

A judgment call, not a completeness bar. If you're writing things you
aren't sure will matter, stop — post-merge will catch them.
