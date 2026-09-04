# `connect` — recording a tacit-knowledge sanction

Read this when a human wants to record that **someone has signed off on a
particular actor doing a particular thing on particular hosts**, and the
tacit-knowledge system is already connected.

This is **not** the onboarding workflow. `SKILL.md`'s six steps connect a
new system of record; this adds *data* to one that is already connected.
Two different jobs in the same skill because the shape of the work is the
same — interview a maintainer, write files, validate, leave a branch — and
because a maintainer who has run `/connect` once already knows where to
look. Nothing here touches an adapter, a config, or a query template.

## Why the skill does this at all

The registry is a version-controlled file, `skills/tacit-knowledge/registry.yaml`.
There is no service, no API, and no admin UI — a human edits YAML and
commits it, and **the commit is the sign-off**. That is the entire safety
argument for the system, and it is deliberate: nothing an investigation
reaches can write this file, so the registry can never be populated from
the agent's own conclusions.

What you add is a **transcription** step, not an approval one. The human
still decides that the pattern is sanctioned; you turn what they say into
eight well-formed fields, check it, and hand them a branch. Every property
that makes the file trustworthy survives, because the thing that makes it
trustworthy is the reviewed commit, not the keystrokes.

Two consequences, and neither is negotiable:

- **`added_by` names the human, never you.** An entry authored under the
  agent's name is the system vouching for itself, which is the one shape
  this design exists to prevent. Ask who is sanctioning it and write that.
- **You never decide that something should be sanctioned.** If the human
  cannot state the actor, the hosts, the exact action, or why — stop and
  ask. `SKILL.md`'s "fail loud on ambiguity" applies here with full force:
  a guessed scope is a sanction nobody granted.

## What to ask

Six things, one at a time, conversationally. Every one is required and
none has a sensible default.

1. **What exact action is being sanctioned?** This is matched
   **literally** at lookup time, so it has to be the action as the
   telemetry names it — not a description of it. "rewrites the CA bundle"
   is a summary; `rewrite /etc/ssl/certs/ca-bundle.crt` is a pattern. If
   they have the alert or the investigation that prompted this, read the
   action off it rather than off their sentence.
2. **Which actor?** A glob against the actor as telemetry names it
   (`uid-0`, `svc-backup`, `build-runner-*`). A blank, `*`, `all`/`any`,
   or a mostly-wildcard scope is refused at load — and so is a negated
   character class like `[!x]*`, which matches everything in a spelling
   that looks specific.
3. **Which hosts?** The same, for the host (`build-runner-*.prod`).
4. **Who is sanctioning it?** A person or a team address. Not a service
   account, not you, not "the platform team" without an address anyone
   can reach.
5. **Why?** One sentence a reviewer can act on months from now. This is
   the field a human reads when deciding whether the sanction still
   holds, so "approved" is not an answer — say what makes the pattern
   legitimate.
6. **How long?** At most 180 days from today, and offer that as the
   default. Past the review date the entry simply stops answering, so the
   date is a re-attestation deadline, not an expiry warning.

Derive the `id` yourself from the pattern and scope
(`tk-ca-bundle-build-runner`), confirm it with them, and check it is not
already claimed — a re-used id is dropped at load, and worse, an id kept
across an edited `pattern` silently re-points every existing citation.

## What you do

1. **Check the current file first.**

   ```bash
   defender/.venv/bin/python -m defender.scripts.tacit_cli check
   ```

   If it is already failing, say so before you add anything — an entry
   appended to a broken file inherits the confusion.

2. **Append the entry.** Eight fields, in the order the file's own header
   lists them, matching the commented example there. Append; never
   reorder or reformat entries you did not write, so the diff shows one
   addition.

3. **Check it again, and show them the output.** The check names every
   entry the runtime will drop and why. A drop here is the failure mode
   worth explaining out loud: a dropped entry is not refused, it just
   stops answering, which is indistinguishable from a sanction nobody
   wrote. Fix and re-run until clean.

4. **Show what is now in force.**

   ```bash
   defender/.venv/bin/python -m defender.scripts.tacit_cli show
   ```

   Read the new entry back to them in their own terms — "uid-0 may
   rewrite the CA bundle on build-runner-*.prod until 2026-08-01, on
   [name]'s sign-off" — and get a yes. This is the last point at which a
   misheard scope is cheap to fix.

5. **Branch and stage. Do not merge or push.**

   ```bash
   git checkout -b tacit/{id}
   git add defender/skills/tacit-knowledge/registry.yaml
   ```

   Present: the entry, the check output, and who must review it. The
   review of that commit is the sign-off — say so, so nobody treats the
   branch as the end of the process. `/ship` can open the PR.

## Refreshing or removing one

**Refreshing** is the same flow with a smaller interview: confirm the
sanction still holds and who is re-attesting it, then move `added_at` and
`review_by` forward in a fresh commit. That commit is the re-attestation,
which is the step a file cannot perform for itself. Do not edit `pattern`
or the scopes under a kept `id` — that is a different sanction and needs a
different id.

**Removing** is deleting the entry. Prefer it to letting one lapse: an
expired entry still sits in the file reading like coverage, and `check`
flags it for exactly that reason.

## What this route never does

- Write any file but `registry.yaml`.
- Author an entry the human did not state in full.
- Merge, push, or treat its own branch as approval.
- Add an entry because an investigation concluded something. A run's own
  finding is not a sanction, and a registry populated from closes is the
  system authorizing itself — the failure this whole design is shaped
  around.
