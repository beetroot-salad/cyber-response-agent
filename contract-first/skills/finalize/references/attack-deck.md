# The attack deck

A project's record of the exploit shapes that carried real bugs past its committed suites. It belongs to the project, not the plugin: it lives at `.claude/contract-first-attacks.md` in the project's repo, finalize appends to it, and write-code-from-tests' attackers replay it against every new contract. A project with no deck yet simply has nothing to replay.

Each entry is one shape, appended from a tracer attribution that is proven and deck-eligible. Phrase the shape so it transfers to other contracts ("assert shape, not substance, on serialization demands"), never only this bug's specifics, and never as doctrine. Entries are append-only; a later finding that weakens one gets a dated note under it, not an edit.

If the file doesn't exist, create it with a `# Attack deck` heading and one line saying what it records, then the entry:

```
## <date> · PR #<n> — <exploit shape, one line>
- **violated**: <design-doc clause, quoted, and the test meant to enforce it>
- **exploit**: <how it greened — enough to re-attempt>
- **killed by**: <what the fix asserts, or "open">
```
