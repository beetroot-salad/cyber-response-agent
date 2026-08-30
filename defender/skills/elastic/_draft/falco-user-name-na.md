---
id: elastic.falco-user-name-na
status: draft
scope: system-wide
affects: all-falco-templates
discovered_in: verify-debug-flow-prior-alert-105543Z
---

# Falco `user.name` emitted as `<NA>` for non-root container UIDs

## Pattern

Falco events in `logs-falco.alerts-*` carry:

```
falco.output_fields.user.name: "<NA>"
falco.output_fields.user.uid: 1001   (or any non-zero UID)
```

The sentinel appears verbatim in `falco.output` / raw `message` as
`user=<NA> user_uid=1001`. `user.uid` is always resolved.

## Root cause

Falco resolves `user.name` by looking up the UID in the **Docker host's**
`/etc/passwd` (via its container plugin), not the container's own user
namespace. UIDs that exist only inside the container (non-root service
accounts, app users) are unknown to the host and produce `<NA>`.
`user.uid` comes from the kernel's credential struct directly and is
unaffected.

## Workaround

**In-document substitute**: Use `falco.output_fields.user.uid` as the user
identifier in place of `user.name`. It is always resolved when a Falco event
names a user at all.

**Cross-source resolution** (recovers the username if the container is still
running): The `host-state` skill can run a live exec against the container:

```bash
docker exec <container_id> id <uid>
```

This is a runtime query — if the container has been stopped or removed, the
username cannot be recovered via any log source. ES has no stored mapping
between container UIDs and names.

## Relationship to the `container.name` sentinel

Both sentinels (`user.name` here and `falco.output_fields.container.name`,
documented in `elastic/SKILL.md` §Gaps) surface as the same `<NA>` value, but
they are independent failures with different causes: `container.name` is
`<NA>` on every Falco alert unconditionally (the sensor never populates it,
per SKILL.md — not a timing-dependent Docker-socket race); `user.name` fails
structurally for any non-zero UID because the host `/etc/passwd` does not
carry container-internal accounts. The latter will always be `<NA>` for
non-root container users unless the same UID happens to exist on the host.

## Notes

- `user.loginuid = -1` in this event means no PAM login session set the
  loginuid — consistent with a service account or a shell spawned inside the
  container without a login session. It is not a substitute for `user.name`.
- Fold this draft as a second entry in the SKILL.md Gaps section alongside
  the existing container attribution note.
