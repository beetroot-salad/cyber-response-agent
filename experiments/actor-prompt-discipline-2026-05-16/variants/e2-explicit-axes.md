# E2 — explicit axes

Append to the first paragraph of `actor.md` (after the current
"Concrete and specific..." sentence):

```
Operational parameters (count, cadence, fan-out, target breadth, dwell time) must be committed at **magnitude-tier resolution only**: count as one/few/many; cadence as seconds/minutes/hours/days; fan-out as single/few/many. Specific values (e.g., "every 70 seconds", "3 hosts") are forbidden — they invite refutation on cosmetic detail rather than load-bearing axes.
```

Harness patch: append the paragraph in-place inside the existing
first paragraph (one paragraph, not two — keeps the preamble visually
unified).
