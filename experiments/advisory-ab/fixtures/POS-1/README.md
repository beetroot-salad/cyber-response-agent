# POS-1 — synthetic 5710, advisory plausibly helps

## Story

A new automation host (`172.22.0.42`) appears running `apt-mirror`, hitting
`target-endpoint` SSH with `srcuser=apt-mirror`. The hostname/IP isn't in
CMDB; the account isn't in IAM. Two competing explanations are equally
plausible without precedent — *legacy ops automation missing a CMDB
entry* vs *internal scanner mimicking a real tool name*.

## Construction

Modeled on the recurring 5710 corpus pattern (e.g.
`/tmp/defender-runs/20260519T065544Z-live-5710`) where CMDB + IAM + a
Wazuh cadence check together discriminate misconfig from scanner. The
entity names are net-new so the case is not in the corpus, but the alert
*shape* mirrors what the corpus has seen often enough to surface
high-discrimination leads via Class-8.

## Why this is "positive" (advisory should help)

The minimum lead set is CMDB + IAM (both miss → enough for `escalate`).
A baseline agent will likely pick those. But the *quality* of escalation
turns on the cadence check (`wazuh-auth-pattern`) — without it the
investigation lands at inconclusive with thin support; with it, the
agent has structured evidence either way.

Advisory should surface `wazuh-auth-pattern` from the recurring 5710
corpus as a high-discrimination lead.
