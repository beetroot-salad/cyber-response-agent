---
name: symbol-refs
description: "Resolve a Python symbol's cross-file references or definitions — who calls or imports it, where it is defined — as a resolved answer, not grep's lexical guess. Use to settle a census or referential claim (\"these are all the callers\", \"the rename is safe\"), to run the 'same pattern elsewhere' sweep over a symbol, or for any who-references-X question a comment or a same-named unrelated symbol would fool grep on."
argument-hint: "[file:line symbol]"
effort: low
---

# Symbol refs

The resolved sibling of the Explore agent. Explore locates code lexically and reads it narratively; this **resolves** it — it links every importer to the actual definition, so "who references `X`" and "where is `X` defined" are answered by the type checker, not approximated by a name match.

grep is the **lexical floor**: every real reference contains the name, so grep never misses one — but it also matches the name in comments, strings, and unrelated same-named symbols, and cannot tell which. This turns that floor into a resolved set.

## When to reach for it

- A **census** a decision rests on — "these are all the callers / writers / occurrences of `X`": the rename that must hit every site, the invariant every consumer must uphold. grep's hit list is the superset to check; this is the resolved one.
- The **same pattern elsewhere** sweep when "the same" is a *symbol* (a function, class, constant), not a text pattern.
- Any who-references / where-defined question where a comment mention or a homonym would inflate or mislead a grep.

## Run it

`pyrefly-refs <file>:<line> <symbol>` — resolved references. It ships with the plugin and is on your PATH. `<file>:<line>` is any line where the symbol appears — its definition or a usage.

- `--defs` — the symbol's definition(s) instead of references; follows imports across files.
- `--json` — machine-readable.

Read the result against the floor it prints. **Resolved fewer than grep** means grep had false positives the resolver dropped — the win. **Resolved collapsing to one file while grep found many** trips the resolution guard: the tool exits non-zero and says so, because that is pyrefly *silently failing to resolve* (a search-path problem, not a true empty) — never read a guard-tripped result as "no references."

## What it does not resolve

Static Python only — symbol and call edges. It does **not** see runtime dispatch (a `VERBS`-style registry the runtime imports and calls by data, a subprocess re-exec) or reachability matched on a string (a regex over a filename). Those are not call edges; read the dispatch site yourself. This is a sharper census for the code-symbol slice, not a reachability oracle.

Requires pyrefly (`uvx pyrefly`, fetched on first use) and a `codeGraph` block in `.claude/spec-flow.json` (`configDir` + `searchPath`). Without a pinned search path pyrefly silently under-resolves on namespace-package layouts — which is exactly why the guard exists.
