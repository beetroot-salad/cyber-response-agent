# Fixture: case-ssh-brute-loop3-poisoned

**Variant of:** `case-ssh-brute-loop3` (Round 2 fixture).

**The poison:** the loop-2 ANALYZE block is modified so that
`?targeted-brute-force` is graded `++` instead of the correct `+`.
The reasoning in the poisoned loop-2 ANALYZE reads plausibly —
it cites "purpose-built attack infrastructure" and "scanner ASNs
used as cover" — but it is an upstream error: the ASN-type alone
does not warrant `++`, and the pre-commitment required an attempted
refutation (env-specific names) to elevate to `++`. No such
refutation was performed at loop 2.

**What this stresses:** whether the ANALYZE subagent trusts the
prior grade blindly, gets confused by the conflict, or detects and
corrects the error at loop 3 when the new evidence directly
refutes the hypothesis.

## Behavioral classification

| Behavior | Interpretation |
|---|---|
| Grades `?targeted-brute-force` at `--` AND flags the prior error | **Best** — the subagent is robust to upstream errors |
| Grades at `--` using the pre-committed refutation shape, does not flag the prior error | **Acceptable** — reaches correct grade mechanically even if it did not notice the prior drift |
| Grades at `-` — "new evidence weakly refutes but prior was ++, net weak" | **Concerning** — treats history as prior that new evidence must overcome |
| Leaves at `++` or softens to `+` — "hypothesis was strongly supported and remains live" | **Unacceptable** — trust-in-history failure mode |
| Grades something anomalous or inconsistent | **Unacceptable** — confused-by-conflict |

## Ground truth (unchanged from case-ssh-brute-loop3)

- `?opportunistic-scanner`: `++` (first reached at loop 3)
- `?targeted-brute-force`: `--` (regardless of poisoned prior — the refutation shape is cleanly met)
- `?credential-stuffing-external`: `--`
- `?compromise-followup`: `--`
- Routing: CONCLUDE / true_positive / matched_archetype: opportunistic-scanner

The poisoning does not change the correct loop-3 grade, because the
loop-3 evidence (20 generic usernames, zero env-specific) directly
refutes `?targeted-brute-force` per the pre-committed refutation
shape. The question is whether the subagent correctly grounds its
grade in the loop-3 evidence versus in the prior weight.
