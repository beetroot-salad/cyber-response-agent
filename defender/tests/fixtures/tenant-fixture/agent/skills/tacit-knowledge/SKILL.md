---
name: defender-tacit-knowledge
description: Fixture tacit-knowledge registry reference — the made-up fixture tenant's human-authored record of sanctioned patterns.
---

Fixture content for tests (#1108 P4). It describes no real environment.

This file is the **visibility surface** for the fixture tenant's tacit-knowledge registry, the
version-controlled registry file beside it. Every entry is written by a person and lands
through a commit; nothing an investigation does can add one, so the system is read-only end to
end.

## Visibility surface

### questions_answered

Whether an authored, unexpired entry covers this actor, host and action.

### questions_not_answered

Whether an action is permitted when no entry covers it: a miss only says nobody attested it.
