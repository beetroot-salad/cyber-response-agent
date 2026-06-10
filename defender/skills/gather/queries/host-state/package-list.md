---
id: host-state.package-list
status: established
---

## Goal

List installed packages on a host by hostname. Used to verify whether specific tools
(e.g., nc, netcat, nmap) are available at the host level — typically after a Falco
container alert, to determine whether the tool was installed as a host-level package
on the Docker host rather than being bundled in the container image.

## What to summarize

- Count of installed packages on the host
- Whether specific tools appear in the package list (e.g., nc, netcat, nmap, curl, wget)
- Package names and versions for any tools relevant to the investigation

## Filter binding

- `${host}` — hostname to query (e.g., the Docker host running the container of interest)

## Query

```
# See defender/skills/host-state/SKILL.md for CLI invocation shape.
# Bound param: ${host}
```

## Common pitfalls

- **Host-level packages only.** This reflects the host OS package database for the
  queried hostname. Tools present only inside a container image layer (not installed
  via the OS package manager on the host) will not appear here.
