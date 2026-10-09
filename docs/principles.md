# Engineering principles

The standing rules every design in this repo is judged against. A design doc can add to them or override them for its own issue; it says so in its principles section. The spec-flow workflow reads this file (the profile's `conventions.principles` points here) and judges every fork against it — a fork that exists only to serve something these principles reject is proposed for dropping, and forks sharing one cause get one design call that dissolves them.

Stated by the owner during the #1105 and #1135 spec runs (October 2026); quotes are theirs.

## 1. Threat model

Files on disk are not necessarily trusted — the filesystem can be corrupt, and anything a sandbox can write is attacker-influenced. The host itself is not assumed malicious.

> "the files in the file system are not necessarily trusted, and the FS could be corrupted, it is just we don't assume the host is malicious"

## 2. Fail closed, loud, and fast

On a condition the code was not built to handle, refuse: stop, say what was wrong, and do it at the first point the condition is visible. Do not continue in a degraded mode, guess a default, or defer the failure to somewhere less obvious.

## 3. No apologetic programming

Do not write over-defensive code: per-case recovery, quarantine, tolerance, retries, and compatibility shims for conditions that should simply be refused (principle 2) or that the threat model (principle 1) does not call for. Each such branch is code that apologizes for a condition instead of ruling it out, and it multiplies edge cases, forks, and tests. When a design accumulates edge cases, look for the design call that makes them impossible — one owner, one location, one shape — rather than patching each one.

> "over-adjusting to edge cases instead of being simple, loud, and fast"
>
> "It's not about hard-to-produce failures, it is about us apologizing for these conditions."
