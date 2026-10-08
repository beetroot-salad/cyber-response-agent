# The frontier file

Every write-tests leaf exits by writing one of these. It is read by the next phase's leaves, the cold reconciler, and a human peeking mid-run — write prose and fenced data blocks for them. Only the frontmatter is machine-read, by `spec-graph frontiers` (resume and shape), and it checks exactly what is below; you do not need its source.

```markdown
---
phase: C-judge
status: complete
inputs: [40-premises.md, 42-answers.py, 44-probes.md, 20-demands.md, 10-brief.md]
---

## Digest

- 212 premises judged: 151 settled, 48 forks in 31 clusters (12 material), 9 dropped (reasons below).
- 6 promotions (settled → fork): #14, #39, #95, #136, #150, #162.
- 2 answers overturned by 44-probes (P-03, P-07); 1 new probe obligation (route: re-ground).
- Top red flag: the design's O2 and O8 contradict on the outage reading — cluster M07.

## Red flags

- O2 vs O8: ... (omit this section when empty)

## <payload sections — whatever the charge asks for>
```

- **`phase`** — the phase letter plus your role (`A-ground`, `B-adversarial`, `C-judge`, `E-writer-<slice>` …).
- **`status`** — `complete`; `design-refuted` when you refuted the design's own ground (stop and say how in the digest); `blocked` when you could not finish (say why in the digest).
- **`inputs`** — the filenames of the frontiers you consumed, bare (`10-brief.md`). List only files that exist: a numbered name with no file behind it (a skipped phase's output) is a finding. A non-frontier input (the design doc, an issue thread) may be listed too; it is not checked. This list is what lets `--resume` see that your file is stale when an input changes.
- **Counts** — put them in the digest or the payload where a reader needs them, computed with `grep -c`/`wc` over your own file, never recalled. An optional `inventory: {premises: 212, ...}` mapping is allowed (integers only); nothing reconciles it against other files.
- **`## Digest`** — at most 15 non-blank lines; it is your inline return to the spine, verbatim. Put detail in the payload.
- **Sidecar** — when your payload is not markdown (a `.py` premise or answer file), write it beside a `.md` frontier of the same stem that carries the frontmatter and digest.

Before returning, run `spec-graph frontiers <frontiers-dir> --only <your-file.md>` on each frontier you wrote and fix what it names; return only on exit 0.
