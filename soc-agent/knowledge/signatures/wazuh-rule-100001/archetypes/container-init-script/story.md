---
archetype: container-init-script
signature_id: wazuh-rule-100001
required_anchors:
  - image-baseline
---

# Container Init Script — Story

The container's own entrypoint or init script invoked a shell as part
of normal startup. This happens when an image's `ENTRYPOINT` or `CMD`
is itself a shell script (or wraps the application in one), or when
an init system inside the container shells out before exec'ing the
main process. The shell appears as a child of an **in-container**
process — the image's entrypoint binary, an init wrapper like `tini`
or `dumb-init`, or a custom launcher — not a runtime exec primitive.
This is the key difference from `operator-runtime-debug` and
`ci-pipeline-exec`: the shell came from inside the container's own
process tree, not from a `docker exec`-style injection.

The event fires within seconds of container creation. It happens
**once per container start** and not in between — a fresh container
fires this event during its boot sequence, then never fires it again
until the next restart. The pattern is reproducible: every time this
image starts, the same parent and the same cmdline appear.

What takes an alert *out* of this archetype is a shell from the same
parent at any time *other* than container start, or a shell from a
parent the image's startup sequence doesn't normally use. A
long-lived container suddenly producing a "startup-shaped" shell
hours or days after boot is not this archetype — that is either a
runtime restart that should be visible elsewhere, or something
masquerading as init.

This is benign **only when the image has a recorded baseline of doing
exactly this on every prior start**. Without that baseline, an
init-script-shaped event could be a tampered image or a startup hook
that was never authorized.
