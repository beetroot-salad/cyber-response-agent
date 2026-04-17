---
name: user-analysis
data_tags: [identity-state, auth-events]
baseline: not-applicable   # Account classification is binary — account exists or doesn't; name matches a known pattern or doesn't. Diversity counts across events in the current alert window are observations on that alert, not rate claims against history.
---

## Goal

Classify the user account(s) involved in an alert against known
patterns and determine what the account choice reveals about the
actor's intent.

## What to Characterize

- **Pattern matching**: Does the username match known service account
  patterns, admin patterns, monitoring accounts, or attack wordlists?
  See environment/context/identity-patterns.md.
- **Account existence**: Does the account actually exist in the
  identity system? Non-existent vs existing accounts are different signals.
- **Account properties**: If the account exists, what are its
  privileges, group memberships, last login, creation date?
- **Username diversity across events**: Single username repeated, a
  small set, or many distinct names? Diversity patterns distinguish
  attack types.
- **Username source**: Do the names appear in known breach databases,
  common wordlists, or are they org-specific?

## Common Pitfalls

- A "real-looking" username doesn't mean the account exists. Always
  verify against the identity system.
- Service accounts may not follow naming conventions if they predate
  the convention. Check creation date.
- An attacker can use a legitimate username — matching a known pattern
  doesn't prove benign intent. Cross-reference with other evidence.
