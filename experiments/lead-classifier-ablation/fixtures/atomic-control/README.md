# Scenario: atomic-control (clone of underfold-sshd-narrowing)

A single coined query, no multi-query pattern → `composite_kind = atomic`,
`co_dispatched_with = []`. The classifier metadata is INERT here. Removing it
MUST NOT change the verdict; if the two arms diverge on this fixture, the
harness/variant is confounded, not the metadata.
