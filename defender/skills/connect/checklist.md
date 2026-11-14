# `connect` — pre-merge checklist

The mechanical bar is automated. Run the validator as `SKILL.md` step 6 gives it — with
`--staged` for a system with investigator tools, with `--case` for a case system that has none:

```bash
python3 defender/skills/connect/validate_scaffold.py {system} --handoff {handoff}/{system} --staged {staged}
python3 defender/skills/connect/validate_scaffold.py {system} --handoff {handoff}/{system} --case {handoff}/case-record.yaml
```

and fix every FAIL before going further. What it checks, and at which
severity — a WARN is a judgment call left to you, not a cleared bar:

**FAIL** (exit 1 — the merge bar):

- adapter module at `integrations/{system}_adapter.py`, importable and
  exposing a `VERBS` mapping;
- `VERBS` includes `health-check`, unless it is empty and the adapter exports the host's comment
  action (a case adapter that offers the investigator nothing);
- every verb is dispatchable as `fn(ctx, **params)`: a leading param
  annotated `VerbContext`, no other positional param, no `**kwargs`, and
  every model-supplied param keyword-only AND annotated (`*, host: str`) — a
  param that binds positionally is one the model can never supply, so the
  verb is dead on arrival (`adapter.md` §"The keyword-only params ARE the
  param contract");
- the handoff's `config.env` and `access.yaml` are a record the store accepts: the
  store's own judgement (every key the adapter declares and no other, no blank or
  `CHANGE-ME` value, the adapter's settings check, an access declaration that parses),
  each failure the sentence the operator would be refused with, naming the file;
- with `--case`: the case record is one the store accepts beside the handoff's system — its body
  template renders, it names that system, and the system's `access.yaml` declares a write route
  covering the adapter's comment route (printed as `the comment the host sends: ...`);
- `skills/{system}/SKILL.md` frontmatter says `name: defender-{system}` — asked only for an
  adapter with a tool beyond `health-check`, and judged whenever `--staged` is given;
- every seed template with readable frontmatter names a declared verb; and
  for a **param-only** verb (one with no `@verb(engine=…)`), every
  `${placeholder}` in its body is a declared param of that verb or listed in
  the template's `body_substitutions:`. An **engine** verb's body IS the
  query language, so its placeholders are body text and are NOT checked —
  the rule is per-verb, not per-system (`adapter.md`, `defender/skills/gather/query-schema.md`).

**WARN** (exit 0 — surfaced, not enforced):

- no `--handoff` given;
- no `execution.md` (or one still inlined as a `## Execution` section in
  `SKILL.md` — split it, per `docs/system-skill-shape.md`);
- no seed query templates at all. They grow post-merge, so this is not a
  bar — but note that a tree with none also skips the template checks above.

Two silent gaps to know about, neither of them a FAIL:

- a template whose frontmatter will not parse, or that carries no `id:`, is
  dropped from the corpus by `iter_query_templates` with a `warn:` on stderr
  and is never checked at all. A tree whose ONLY template is malformed
  reports the "no seed query templates" WARN and exits 0.
- template `id:` frontmatter is not checked here. CI enforces
  `id` == `{system}.{filename}` for templates yielded by `iter_query_templates`
  in `test_d24_every_template_id_matches_its_system_dir_and_filename`.
  An id-less template is dropped with the stderr warning described above.

This file covers the rest — the calls a script can't make.

## Judgment checks

- [ ] **The check was agreed first, and is falsifiable.** `check.md` names the question, the
      tool and inputs, an answer a wrong credential, base or mapping would not give, and a
      negative control. A write targets an object the maintainer named as disposable.
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
      — not just in `config.env` (whose keys the store holds to the adapter's
      declared ones; CI refuses a declared key named like a secret).
- [ ] **Declared for the proxy.** `access.yaml` names the base, the auth
      scheme and field name (never a value), and every route the adapter
      calls with a method other than `GET`/`HEAD` (the proxy admits those as reads); `config.env` holds exactly the adapter's `REQUIRED_CONFIG_KEYS`. A
      credential is the operator's to store with the proxy (noted in the
      summary).
- [ ] **One system.** If others came up in the interview, they were noted
      for a separate re-run, not folded in here.
- [ ] **Divergences surfaced.** Any legitimate departure from the default
      flow (odd upstream, unusual access topology, a vendor auth scheme the
      shared transport doesn't cover) is called out in the summary for human
      review — not silently patched, not blocked.
- [ ] **Human review checkpoint cleared (generate path).** The maintainer read
      the generated adapter and approved it, and the tool that answers the check, *before*
      the handoff — not only at the final diff (`adapter.md`).
- [ ] **The operator's steps are in order** (`SKILL.md` step 7), and the summary says the final
      check cannot run from the conversation yet.
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
- [ ] Do the seed templates plus the adapter declarations give a fresh-context Haiku
      enough to compose a valid first query?
- [ ] Is anything missing that the offline lead-author would need to start
      extracting templates from a real run?

A judgment call, not a completeness bar. If you're writing things you
aren't sure will matter, stop — post-merge will catch them.
