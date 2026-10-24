---
name: symbol-refs
description: "Resolve a symbol's cross-file references or definitions — who calls or imports it, where it is defined — as a resolved answer, not grep's lexical guess. Use to settle a census or referential claim (\"these are all the callers\", \"the rename is safe\"), to run the 'same pattern elsewhere' sweep over a symbol, or for any who-references-X question a comment or a same-named unrelated symbol would fool grep on."
argument-hint: "[file:line symbol]"
effort: low
---

# Symbol refs

grep is the **lexical floor**: every real reference contains the name, so grep never misses one, but it also matches the name in comments, strings and unrelated same-named symbols, and can't tell which. A language server **resolves** the name: it links each use to the actual definition, so "who references `X`" is answered by the type checker rather than a name match.

## When to reach for it

- A **census** a decision rests on: "these are all the callers / writers / occurrences of `X`", the rename that must hit every site, the invariant every consumer must uphold.
- The **same pattern elsewhere** sweep when "the same" is a symbol (a function, class, constant), not a text pattern.
- Any who-references or where-defined question where a comment or a homonym would inflate a grep.

## Run it

1. **The floor.** `grep -rlw <symbol>` over the source tree, excluding vendored and generated directories. Note the file count.
2. **The resolved set.** Use Claude Code's `LSP` tool at a line where the symbol appears: find references, or go to definition. It needs the language's code-intelligence plugin (for example `pyright-lsp` or `typescript-lsp`) and its language server installed. Without one, say so and fall back to the floor, reading each hit to separate real references from comments and homonyms.
3. **Compare.** Resolved fewer than grep means grep had false positives the server dropped, which is the point. **Resolved collapsing to one file while grep found the name in many** is the language server failing to resolve imports, not a true empty: a project layout it doesn't understand, usually a missing import root in its config. Fix the config or fall back to reading the grep hits; never report a collapsed result as "no references".

Record the search with its scope and both counts, so the census is reproducible.

## What it does not resolve

Static symbol and call edges only. A language server doesn't see runtime dispatch (a registry called by data, a subprocess re-exec, reflection) or reachability matched on a string (a regex over a filename). Read those dispatch sites yourself. This sharpens the code-symbol slice of a census; it is not a reachability oracle.
