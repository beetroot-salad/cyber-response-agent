# `/connect` — Pre-merge checklist

Walk through this before calling a connection done. Anything unchecked goes in the user-facing summary as an open item.

## Adapter script

- [ ] Written to `scripts/tools/{system}_cli.py`, not anywhere else.
- [ ] Implements `health-check` and `query` as argparse **subcommands** (not flags like legacy `wazuh_cli.py`).
- [ ] `query` accepts `<native_query>` as a positional argument plus `--start`, `--end`, `--limit`, `--raw`, `--run-dir`.
- [ ] Exit codes match the contract: health-check {0, 1}; query {0, 1, 2}.
- [ ] Native query language is passed through unmodified — no translation, no DSL, no field renaming.
- [ ] Non-secret config loaded from `knowledge/environment/systems/{system}/config.env`, with environment variable overrides.
- [ ] Secrets loaded from environment variables only. No pasted tokens anywhere in the script, config, or docstrings.
- [ ] Missing-config and missing-secret errors print an actionable hint pointing to the fix, and exit 2.
- [ ] Missing-dependency errors (import failures) print `bash scripts/tools/{system}/setup.sh` and exit 2.
- [ ] `--run-dir` reads the salt from `meta.json` and wraps output in `<run-{salt}-{system}-data>…</run-{salt}-{system}-data>`.
- [ ] `--raw` outputs JSON (wrapped in salt delimiters if `--run-dir` is set).

## Dependencies

- [ ] Stdlib-only when feasible. Vendor SDKs only when the API genuinely needs them.
- [ ] If deps are required: `scripts/tools/{system}/requirements.txt` has pinned versions, `scripts/tools/{system}/setup.sh` creates a venv and installs them.
- [ ] `setup.sh` is idempotent — safe to re-run.
- [ ] The setup.sh pattern matches `scripts/siem/setup.sh` (uv-preferred, venv fallback).

## Tests (Phase 3)

- [ ] `python3 scripts/tools/{system}_cli.py health-check` exits 0 and prints `connected`.
- [ ] A sample query with `--limit 5` returns output.
- [ ] The user has eyeballed the sample output and confirmed the fields look right.
- [ ] (Optional, recommended when field-notes are thin) Field-model Haiku probe. Hand a fresh-context Haiku the output of `query --help` plus `field-notes.md`, give it a realistic task ("find 5 failed SSH logins on web-01 in the last hour"), and inspect the ambiguities it surfaces. Any field name, sourcetype, or enum value Haiku has to guess about is a gap in `field-notes.md` — fill it in before committing. (Don't probe CLI shape; that's been measured and all common shapes pass. See `design.md` §5.)

## Environment knowledge

- [ ] `knowledge/environment/systems/{system}/config.env.template` exists, is tracked in git, and contains only non-secret keys with comments.
- [ ] `knowledge/environment/systems/{system}/config.env` exists locally with actual deployment values, is gitignored (verify via `git check-ignore`), and does not contain any secrets.
- [ ] Secrets live in env vars (or a gitignored `.env` at the repo root), never in either config file.
- [ ] `field-notes.md` exists with a concrete "fields you'll reach for" section and at least one "known quirks" note (or an honest `TODO` if none were discovered yet). This is the load-bearing file for runtime agent quality — don't ship it empty.
- [ ] `SKILL.md` for the system names it, describes how to invoke the CLI with a real complete example, and points at the field notes.
- [ ] `knowledge/environment/data-sources/{data-type}.md` has been updated (or created) to name this system as a source, with access method, query language, retention, and coverage notes.

## Credential boundary

- [ ] No tokens, passwords, API keys, or basic-auth strings anywhere in the adapter, config.env, docs, or commit.
- [ ] The user has been told which env var names to set and confirmed they're set (or explicitly deferred, in which case the commit message notes it).
- [ ] No `curl` commands with `-H "Authorization: ..."` in docstrings or examples.

## Scope discipline

- [ ] Only `scripts/tools/` and `knowledge/environment/` have been edited. Hard limit: no touches to `hooks/`, `schemas/`, `skills/`, `knowledge/signatures/`, or `config/signatures/`.
- [ ] No signature knowledge was created or modified. If the user wants starter signatures for this system, that's a follow-up `/author` run.
- [ ] No lead templates were created. Lead templates come from investigation experience, not API docs.
- [ ] `scripts/siem/wazuh_cli.py` (the reference example) was not touched. Its eventual migration is a separate PR.
- [ ] If the user's request legitimately falls outside the default flow (unusual upstream, weird access topology, bespoke integration), that divergence is surfaced in the summary to the user for human review — not silently patched over, and not blocked outright.

## Preflight

- [ ] `python3 scripts/preflight.py` exits 0 (or 1 only because of pre-existing unrelated gaps — not because of this connection).
- [ ] The new system appears in the preflight systems list as connected.
- [ ] No knowledge gaps reported for the new system.

## Commit

- [ ] A branch was created (`connect/{system}` or `connect/{system}-update`).
- [ ] Commit message is clear about what was added/modified and which system.
- [ ] The user has a summary: files touched, health-check result, sample query outcome, env vars to set, open TODOs.
- [ ] **Nothing was merged or pushed without explicit user direction.** The human review gate is non-negotiable.

## Friction-free agent use

Harder to mechanically check. Ask yourself:

- [ ] If a fresh investigate run picked up only the env knowledge you just wrote, could it form a query in this system's native language? (Fields named? Query syntax flagged? Pagination quirks noted?)
- [ ] Does the SKILL.md for this system point at every supporting doc (field notes, query examples), so the investigate agent can find them without grep-ing?
- [ ] Is there at least one example CLI invocation in the SKILL.md the agent can copy from?

If any of the above is "no," the adapter will run but the agent will waste context re-discovering the system on every run. Fix the gap before declaring done.
