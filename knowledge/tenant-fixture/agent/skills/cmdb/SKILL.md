---
name: defender-cmdb
description: Fixture CMDB reference — host inventory (owner, role, change window) for the made-up fixture tenant.
---

Fixture content for tests (#1108 P4). It describes no real environment.

This file is the **visibility surface** for the fixture tenant's inventory system. Execution
details live in `execution.md`, read only by gather; the verbs and their params come from the
`list_verbs` tool.

## Visibility surface

### questions_answered

Who owns a host, what role the inventory gives it, and when its change window is.

### questions_not_answered

What ran on the host, or who logged in to it: the inventory records intent, not activity.
