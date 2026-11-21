---
id: {system}.process-events
status: established
verb: query
params: [end, start, sort]
---

## Goal

Process execution events over a window: which processes ran, with what command line, under which account, on which
host, and spawned by what parent. One **capability** template for process questions: what ran around an alert, the
execution chain from a parent to its children, a baseline of a binary's use. Keyword recall: process, execve, exec,
command line, process.name, process.parent.name, process.command_line, user.name, host.name, spawn, ancestry.

This is a **wide/superset** query: it matches every process event and carries no entity predicate. **You narrow it to
the lead** by adding the predicates the lead constrains.

## Query

Lucene, the verb's default events index.

```
event.category: "process"
```

**Narrowing examples:**

- *One binary*: add `AND process.name: "<name>"`.
- *Children of a parent*: add `AND process.parent.name: "<name>"`; read each document's `process.command_line`.
- *One host's activity*: add `AND host.name: "<host>"`, with `sort: "asc"` for the order it started in.

## Pitfalls

- **Which fields exist depends on the sensor.** A sensor that records process events may fill `process.name` and leave
  `process.parent.name` or `process.command_line` null, or put them under its own namespace. Read one hit's fields
  before binding a predicate on a name from memory.
- **The host a sensor reports may not be the host the process ran on.** A sensor running beside a container host can
  name itself in `host.name`. If every hit carries one host name, attribute by the container or workload field the
  sensor records, and resolve it to a host through another system.
- **Parent only, no further.** The chain stops at the parent the event names.
- **Process events are high-volume.** Prefer `esql` aggregation for counts; use this query when the documents are the
  evidence.
