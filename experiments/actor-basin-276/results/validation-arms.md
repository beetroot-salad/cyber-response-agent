# Validation pass — outcomes & read (1 run per arm, falco benign fixture)

Direction-signal pass over `fixtures/falco-net-tool-live/` (frozen **benign/high**). Seed pinned →
identical archetype (`internal`) + MITRE menu across arms. Setup + design decisions in
`validation-setup.md`. Raw artifacts under `runs/<arm>/`.

## Outcomes (all three SURVIVED)

| arm | actor.md | outcome | findings | story | techniques |
|---|---|---|---|---|---|
| arm0-baseline | current | **survived** | 5 | 4836 B | 5 (T1190,1059.004,1563.001,1098.004,1548.003) |
| armA-reframe | reframed | **survived** | 5 | 4318 B | 4 (drops sudo) |
| armB-whitebox | reframed + gather_summary | **survived** | 5 | 7584 B | 7 (adds 1560.001 archive, 1048.003 exfil) |

"survived" = the actor's FN story was **not refutable** by the frozen lead set — the desired output on
a benign fixture (a real missed-attack the defender's analysis would have closed benign).

## The one structural gap all three found (independently)

Every arm landed the same basin-and-pivot shape: **the `nc -z -w1 jump-box-1 22` probe *is* the
svc.monitoring baseline** (byte-identical to the 9,189-event/7-day cadence → lands in the benign basin),
and the **malice is exiled to jump-box-1** — the SSH-pivot target the defender's lead set never queried.
The benign disposition rests on "no co-occurring signals in scanner-1's Falco window," which is
dual-consistent with the malicious pivot. That the frozen defender genuinely has this coverage gap is
the #276 dynamic firing for real.

## Direction signals (what differed — quality, not caught/survived)

1. **Reframe (arm0→armA) sharpened the dual-consistency, on BOTH sides.**
   - Actor: armA's bypass leans explicitly on *baseline-matching* ("operationally identical to the
     connectivity heartbeat … the malice lives in the out-of-band sequence") — the contextual
     automation-basin framing the reframe intends. Story is tighter (4 techniques, shortest).
   - Judge: armA produced the **cleanest likelihood-ratio finding** —
     `analyze-discipline: "baseline volume used as discriminating benign signal when it is
     dual-consistent"`. That is precisely the judge-FN-naming the experiment is after (the 9,189-event
     baseline treated as evidence *for* benign when the malicious mechanism mimics it). arm0's
     analyze-discipline finding was vaguer ("Falco window absence as benign discriminator").
   - Cost: armA is slightly **less grounded** (hand-waves the agent-hijack source: "a different
     container or internal host").

2. **White-box (armA→armB) bought grounding + depth — the "ceiling oracle" value.**
   armB used the real actuals throughout: cited the 9,189 / 6-prior-occurrences / 8–10-min interval,
   timed the probe *inside* the real inter-probe window, grounded `sre-ops sudo:true on jump-box-1`,
   the `host-plain:24.04` image, the `host-entrypoint.sh`, `tty=0` non-interactive. It extended the
   kill chain two steps further (archive + nc exfil) and **applied tradecraft** (timed the
   authorized_keys write to coincide with a key rotation — the `authorized-keys-artifact-state-bypass`
   lesson). Clear monotonic grounding/depth: arm0 < armA(framing) < armB(grounding+depth).

3. **Shared weakness (all three): the entry vector is ungrounded.** Every story uses T1190 against a
   *postulated* scanner-1 HTTP management API/stub that the actuals do not show (scanner-1's `ps`
   shows only sshd + the baseline loop). The judge flagged it directly (armA "management API existence
   not established"; armB "internal HTTP stub … no defender query surface predicted"). Partly an
   artifact of the **pinned menu** forcing T1190 as the sole Initial-Access option — a different menu
   draw would likely move the entry vector. Worth varying the seed to see if the basin-landing core
   survives a different initial-access technique.

## Reading for the call (prompts untuned — provisional)

- The **reframe is not inert** even where I expected it might be: it measurably tightened the actor's
  basin-framing and produced the sharpest judge dual-consistency finding. But it did **not** change the
  outcome (all survive) and slightly traded grounding for framing.
- **White-box is the strongest single lever here** — markedly more grounded, realizable, deeper stories.
  Per the plan's decision criteria, the open question is *realizability*: armB's wins (real cadence
  numbers, the sudo fact, the rotation-timing) lean on having read the actuals — a **blind** actor
  could only reach them if those facts live in `lessons-environment`. So armB reads more as a
  **ceiling oracle exposing env-lessons substrate gaps** than as a production change. (The cadence,
  the sre-ops sudo fact, the image/entrypoint are exactly the env-facts to encode.)
- Caveat: N=1/arm, one fixture, falco anchor (where the basin is *winnable* by design, so arm0 already
  does well). The reframe's bigger test is a **sshd-anchored** run where the old corpus actively
  steers to the human-mimicry dead-end (retired-corpus copy is staged for that).

## Harness note
The runner's `yaml.safe_load` post-step flagged arm0/armA as "error" — a parsing glitch only: the
low-effort judge prepended reasoning text (arm0) / dropped the `outcome:` key (armA). All stages ran;
outcomes recovered by lenient re-parse. If this harness is reused, tighten judge output discipline or
parse leniently (the production `validate_judge_doc` path may already handle it).
