# #1161 rerun under the moved instructions: pass criteria (written before launch)

Seat: discuss-issue's first independent review, as the from-scratch review
(sketch-and-spike.md §From-scratch review plus SKILL.md §3's checks). Same inputs as the smoke.

Pass if all hold:
1. Parts 1-3 (proposed design, decisions, readiness) come first and fit on one screen (~50 lines).
2. Part 1 says whether the shape holds, gives each change with the tensions it removes and its
   cost, and lists the shapes rejected with reasons.
3. Part 2 lists the decisions with a recommendation each; part 3 states readiness and what blocks it.
4. No harness-defect or stale-test list anywhere; such an item appears only inside a tension.
5. The evidence keeps the substance of all eight findings from the current-instructions check
   (runs/1161/check-current.md, DC-1..DC-8).

## Result (runs/1161-v2/review.md, 231 lines; transcript clean)

1. Parts 1-3 first: yes. One screen: no, 78 lines (target ~50). Dense, but over.
2. Shape verdict, changes with tensions removed and costs, five rejected shapes with reasons: pass.
3. Four decisions, each with a recommendation; readiness names its blockers and a probe owed: pass.
4. Harness list: one line at the end ("Noise, for the test author only"), down from ~60 lines. Near pass.
5. DC-1..DC-8 all present: DC-1 G6/decision 2, DC-2 G5/decision 4, DC-3 G2, DC-4 G1, DC-5 G4,
   DC-6 G3, DC-7 G7, DC-8 decision 3. Pass.

Not in the criteria, and the main finding: the two from-scratch runs disagree on the central
question. The smoke run rejected "the frontend completes the sign-in" because a script-injection
bug could read the code and verifier and redeem them outside the browser (session theft). The
rerun adopts essentially that shape and recommends it. It lists "pre-login values become readable
by the frontend's script" as a cost but never weighs it; its security analysis covers login CSRF
only. The Origin check it relies on stops browsers, not a client outside one.
