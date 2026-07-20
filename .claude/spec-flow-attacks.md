# Attack deck

Append-only. One entry per exploit shape that carried a real bug past a committed suite in this repo — appended by `finalize` from an artifact-proven tracer attribution, replayed by `write-code-from-spec`'s adversarial implementer against every future spec. Entries record *shapes*, phrased to transfer across specs ("assert shape, not substance, on serialization demands"), never this-bug specifics alone and never doctrine.

Entry format:

```
## <date> · PR #<n> — <exploit shape, one line>
- **violated**: <demand id or design-doc clause, quoted>
- **exploit**: <how it greened — enough to re-attempt>
- **killed by**: <what the fix asserts, or "open">
```

No entries yet.
