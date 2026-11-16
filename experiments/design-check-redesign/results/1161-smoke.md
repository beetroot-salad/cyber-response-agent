# #1161 smoke: current vs proposed design check (1 run each, Opus high)

Contamination: neither transcript ran `gh`, read the live #1161 worktree, or read issue records.

| | current | proposed |
|---|---|---|
| Opening | "not ready"; DC-1, DC-2 block | "the shape holds", with two owner changes |
| Findings | 8 (DC-1..8), grouped by decision | 15 (T-1..15), grouped into 6 tension groups by cause |
| Redesign attempted | no | 4 candidates for the sign-in attempt, 3 rejected with costs, 1 adopted |
| Test/harness upkeep | "noise set aside" section | separate author list |
| Readiness for thorough authoring | stated | **not stated** |

Coverage: every current finding has a proposed counterpart. DC-1→T-10, DC-2→T-7/T-8, DC-3→T-4,
DC-4→T-1/T-2/T-3, DC-5→T-5/T-6, DC-6→T-11, DC-7→T-9/T-14/T-15, DC-8→T-12. Proposed adds T-13
(B9's artifact domain belongs to piece 2). No catch lost.

What only proposed did:
- Rejected "the frontend completes the sign-in": an XSS could take the code and verifier and
  redeem them outside the browser. Today an HttpOnly cookie rules that out.
- Rejected one shared binding cookie: tabs restored together race, and the last write wins.
  That argument is the reason D6's per-attempt cookies are the minimal correct shape.
- Rejected moving the attempt into the tab: it narrows S3 and pushes P2's tests into browser
  tests CI can't run.
- Corrected the spike's premise: the fakes stand in for the port, not the service, so moving the
  attempt into the identity service costs one test helper, not the spike's assumed fan-out.

Regression found: the new return order (verdict on shape, leftover tensions, author list) drops
the "ready for thorough authoring?" answer. Current states it; proposed never does, though T-10
(B6's false premise) blocks authoring B6.
