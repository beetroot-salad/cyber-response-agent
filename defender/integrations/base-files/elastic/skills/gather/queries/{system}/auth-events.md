---
id: {system}.auth-events
status: established
verb: query
params: [end, start, sort]
---

## Goal

Authentication events over a window: which accounts authenticated or failed to, from which source addresses, on which
hosts, by which method, and when. One **capability** template for every authentication-history question: the sequence
around an alert, a baseline over a longer window, whether a source has ever reached a host, per-user or per-host spread.
Keyword recall: login, logon, ssh, sshd, sudo, failed password, brute force, authentication, event.outcome, user.name,
source.ip, host.name.

This is a **wide/superset** query: it matches every authentication event and carries no entity predicate. **You narrow
it to the lead** by adding the predicates the lead constrains. Fork to a new template only for a different measurement,
never for a different entity.

## Query

Lucene, the verb's default events index. Bind `start` and `end`; bind `sort` to `"asc"` for what came first.

```
event.category: "authentication"
```

**Narrowing examples** (each is the query above with a clause added):

- *One account's history*: add `AND user.name: "<user>"`.
- *A source to a host*: add `AND source.ip: "<ip>" AND host.name: "<host>"`; the envelope's `total` answers
  zero-versus-nonzero without reading documents.
- *Failures only*: add `AND event.outcome: "failure"`.

For counts by method, source or host over a long window, aggregate with `esql` over the same index instead of reading
the capped documents.

## Pitfalls

- **`event.outcome` is null on lines that are not an authentication result** (session open and close, module
  chatter). A clause on it drops those lines; a total taken without one counts them.
- **Fields are filled only on the lines the ingest parsed.** A null `user.name` on a line is a parser gap, not an
  anonymous login. Do not report it as one.
- **A parser can land a value with stray whitespace.** An equality predicate on `user.name` then silently drops those
  rows, a confidently wrong zero on exactly the failures you were sent for. If a failure count looks too low, drop the
  user predicate and read the values off the hits, or match a wildcard form.
- **The cap keeps one end of the window.** The default is the newest 20; a window that brackets an alert can return only
  its tail. Use `sort: "asc"` for what happened first.
