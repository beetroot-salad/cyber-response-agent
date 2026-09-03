# Validation (t0), hand-scored 2026-09-02 before the grader ran

Well-formed on all four cells: every reply parsed as YAML in the requested shape; prompt sizes
current 13–18K tokens, proposed 51–80K tokens (K3 accepted both); replies 0.5–7K tokens.

| cell | R1/A1 | R2/A2 (db-1) | R3/A3 | unmatched (hand read) |
|---|---|---|---|---|
| current / fresh-alert-input | miss | miss | miss | 2 — both restate the run's own reasoning (authz override; "answers the discriminator") |
| proposed / fresh-alert-input | hit (auth index never queried, lesson loaded 3×, siblings found SSH) | miss | hit (empty error payloads; summary asserts 404 with no bytes) | 1 true (l-005 summary dropped curl→/tmp and restart-nginx rows that r1 names), 1 near-duplicate of R1 (no scheduler lead) |
| current / A-F1-t3 | miss | miss | partial (closed high-confidence on weak trace; no l-007 link) | 3 false — reads sibling worlds' counterfactual injects as world-A facts; calls the db-1 host-state pivot a defect (it was the right asset); identity-404 category error is arguable |
| proposed / A-F1-t3 | miss (7-day window not named) | miss | hit (SSH→sudo link unestablished; own summary read scripted) | 2 true (ticket store never queried, 15/24 siblings did; l-007's 19 payloads never synthesized), 1 true (commands re-narrated as reconnaissance against the summary) |

Observation that survives to the write-up regardless of scale-up: NO cell made the db-1 join
(container named db-1 in host-state ↔ db-1 in the CMDB inventory ↔ db-1 in identity role maps),
even with all three payloads in view. The per-lead chain keeps entities inside their lead; nothing
in the four views indexes an entity across leads. Candidate fifth view for the follow-up: an
entity index (host / user / ip / container → every lead, payload, summary and document row that
names it). The 7-day-window finding (A1) also needs the coverage view to carry time windows,
which it does not.
