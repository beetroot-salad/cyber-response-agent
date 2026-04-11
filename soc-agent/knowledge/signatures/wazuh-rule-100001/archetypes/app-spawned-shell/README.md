---
archetype: app-spawned-shell
signature_id: wazuh-rule-100001
required_anchors:
  - image-baseline
---

# Application-Spawned Shell

## Story

A long-running application binary shelled out as part of its normal
work. The shell appears as a child of a service process (web server,
language runtime, database, image-processing tool) — the same parent
shape as `post-exploit-interactive`, but **this image has done this
before, many times, without incident**. The cmdline can be
interactive-looking or scripted; what matters is that the pattern
matches the image's established baseline.

Real applications shell out for many legitimate reasons. Python code
calls `subprocess.run(..., shell=True)`. PHP calls `exec()` and
`system()`. Build tools wrap `git`, `make`, and compiler invocations
through a shell. Image-processing wrappers (ImageMagick, ffmpeg,
ghostscript) shell out to invoke other binaries. Log rotation scripts
run from cron-like supervisors inside the container. Init systems
spawn helper shells. None of this is suspicious *for an image that
routinely does it*.

The boundary between this archetype and `post-exploit-interactive` is
the image baseline, and only the image baseline. If this image has
spawned shells from this parent with this shape repeatedly across
normal operation, the activity is boring and this archetype matches.
If this is a first-seen pattern — new parent, new cmdline shape, new
image, or a sudden change in frequency from an established baseline
— it is `post-exploit-interactive`, not this. The boundary is also
behavioral: an application shelling out to its normal helpers stays
in this archetype; an application shelling out to read mounted
secrets or enumerate the filesystem outside its working set leaves
this archetype regardless of baseline.

This is benign **only when the image baseline confirms the pattern
is established**. The baseline is the only thing distinguishing
routine shell-out from compromise.

## Trust Anchors

### `image-baseline`

**Question:** for this `container.image`, does the historical record
show 100001 events firing from the same `proc.pname` with a similar
`proc.cmdline` shape, with sufficient frequency and over a long
enough window to be considered routine?

**Confirmation:** the anchor returns a baseline showing this
parent/cmdline shape recurring across many prior events for this
image, with sample size large enough to be representative and a
recency window that includes the current image version. A baseline
that shows only a few recent occurrences without a longer-term
pattern is *not* sufficient confirmation — it could be the early
stages of a compromise that the agent is now treating as the new
normal.

## Precedents

None yet.
