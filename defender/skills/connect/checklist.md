# `connect` — pre-merge checklist

The mechanical bar is automated. Run:

```bash
python3 defender/skills/connect/validate_scaffold.py {system}
```

and fix every FAIL before going further. What it checks, and at which
severity — a WARN is a judgment call left to you, not a cleared bar:

**FAIL** (exit 1 — the merge bar):

- adapter module at `scripts/adapters/{system}_adapter.py`, importable and
  exposing a non-empty `VERBS` mapping;
- `VERBS` includes `health-check`;
- every verb is dispatchable as `fn(ctx, **params)`: a leading param
  annotated `VerbContext`, no other positional param, no `**kwargs`, and
  every model-supplied param keyword-only AND annotated (`*, host: str`) — a
  param that binds positionally is one the model can never supply, so the
  verb is dead on arrival (`adapter.md` §"The keyword-only params ARE the
  param contract");
- `config.env` carries no inline secrets;
- `skills/{system}/SKILL.md` frontmatter says `name: defender-{system}`;
- every seed template with readable frontmatter names a declared verb; and
  for a **param-only** verb (one with no `@verb(engine=…)`), every
  `${placeholder}` in its body is a declared param of that verb or listed in
  the template's `body_substitutions:`. An **engine** verb's body IS the
  query language, so its placeholders are body text and are NOT checked —
  the rule is per-verb, not per-system (`adapter.md`, `queries/SCHEMA.md`).

**WARN** (exit 0 — surfaced, not enforced):

- no `config.env`, or a value that merely looks high-entropy;
- no `execution.md` (or one still inlined as a `## Execution` section in
  `SKILL.md` — split it, per `docs/system-skill-shape.md`);
- no seed query templates at all. They grow post-merge, so this is not a
  bar — but note that a tree with none also skips the template checks above.

Two silent gaps to know about, neither of them a FAIL:

- a template whose frontmatter will not parse, or that carries no `id:`, is
  dropped from the corpus by `iter_query_templates` with a `warn:` on stderr
  and is never checked at all. A tree whose ONLY template is malformed
  reports the "no seed query templates" WARN and exits 0.
- template `id:` frontmatter is not checked here. That invariant
  (`id` == `{system}.{filename}`) is real and is enforced in CI over the
  whole committed catalog by `test_d24_every_template_id_matches_its_system_dir_and_filename`
  and by `test_verb_roster_632.py`'s census (which also fails a template
  that declares no `id:` at all) — just not by this script.

(For the MCP path there is no adapter module to check —
`validate_scaffold.py` is adapter-specific. Run the judgment list below
either way.)

This file covers the rest — the calls a script can't make.

## Judgment checks

- [ ] **Sample results look right.** The maintainer eyeballed real output
      and confirmed the fields match what they expect.
- [ ] **`gaps` are honest.** `SKILL.md` declares what the system *cannot*
      answer here, including silent-failure shapes — enough that a reader
      who'd never touched this system wouldn't fall in blind.
- [ ] **The adapter conforms to the client.** The Haiku alignment loop was
      run (`adapter.md`): cosmetic divergences became verb/param
      changes, and only irreducible vendor constraints were documented. You
      are not teaching Haiku your aesthetics.
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
      flow (odd upstream, unusual access topology, a vendor auth scheme the
      shared transport doesn't cover) is called out in the summary for human
      review — not silently patched, not blocked.
- [ ] **Human review checkpoint cleared (adapter path).** The maintainer read
      the generated adapter and approved it *before* it ran against the
      live system — not only at the final diff (`adapter.md`).
- [ ] **Nothing merged or pushed** without explicit direction. The human
      review gate is non-negotiable. (`/ship` opens the PR.)

## Enough to build on

The query catalog and the lessons corpus fill in post-merge. Your
scaffold exists so those flows have a foundation and the first runs can
find and route to the system. Ask:

- [ ] Does `SKILL.md` let the defender decide *when* to route here
      (`when_to_use` / `gaps`) without reading anything credentialed?
- [ ] Does `execution.md` let the gather subagent dispatch without reading
      the adapter source?
- [ ] Do the seed templates plus the verb roster give a fresh-context Haiku
      enough to compose a valid first query?
- [ ] Is anything missing that the offline lead-author would need to start
      extracting templates from a real run?

A judgment call, not a completeness bar. If you're writing things you
aren't sure will matter, stop — post-merge will catch them.
