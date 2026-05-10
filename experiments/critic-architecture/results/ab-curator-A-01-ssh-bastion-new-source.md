# Arm A training: 01-ssh-bastion-new-source

### Defender

- cost: $0.0932
- tokens: in=2 out=1265 cache_read=11896 cache_create=18583

```
### TRIAGE

**Claim:** This is jsmith on Building 7 wifi following up on their own bastion config rotation, not a compromise.

- The key fingerprint is established — same key, four other corp IPs, 90-day history. Not a new credential; the only novelty is the source subnet.
- INC-8821 ("rotated bastion sshd config") closed at 03:31Z — 16 minutes before this login. Login to verify config behavior after a late-night change is the expected next action.
- Source geolocates to corp-internal Building 7 wifi. Subnet shift (from 10.42.5.0/24 to .7.x) is explained by being on wifi rather than the usual wired network — not lateral movement.
- No concurrent sessions rules out parallel key abuse; off-hours timing is explained by the active maintenance window.

**Disposition:** `benign`

**Load-bearing assumption:** INC-8821 is a legitimate ticket authored and closed by jsmith — not pre-staged cover created or manipulated by an attacker holding jsmith's key. If the ticket was fabricated or its close timestamp was spoofed, the coherent narrative collapses and this becomes a key-compromise with planted alibi.

---

### DIRECTIVE-TO-CRITIC

When an alert arrives with strong surface legitimacy — known key, corp-internal source, role-consistent user, and a recent ticket that narratively explains the anomaly — prioritize attacking the integrity of that ticket as a whole artifact over auditing individual evidence items independently. A matching ticket is the most dangerous form of cover because it converts a single suspicious data point (new source) into an apparently coherent operational story. The critic should ask: was the ticket created before or after the anomalous action? Is the ticket content specific enough to be predictive rather than post-hoc? Who else can confirm the work order? Treat the ticket not as corroboration but as the highest-value falsification target in the investigation.
```
### Critic

- cost: $0.1090
- tokens: in=2 out=2123 cache_read=11896 cache_create=19201

```
### VERDICT

**CRITIQUE**

**Assumption attacked:** "Login to verify config behavior after a late-night change is the expected next action."

**Mechanism:** An attacker holding jsmith's key who performed the sshd config rotation could have embedded a persistence mechanism in the rotation itself — a second `AuthorizedKeysFile`, a relaxed `PermitRootLogin` directive, an added `Match` block, or `AllowTcpForwarding yes`. The post-rotation login is then not verification of a defensive change; it is functional testing of a backdoor. INC-8821 provides standing for the actor, not evidence that the change was defensive.

**Observable consequence:** The sshd_config diff on bastion-01 for the 03:31Z window is a concrete artifact. A legitimate key rotation or policy tightening produces a targeted, narrow delta (one algorithm removed, one key replaced). A backdoor insertion produces an unexpected structural addition.

**Lead:** Retrieve `sshd_config` before/after state — config management repo diff, backup file, or `auditd` records on bastion-01 around 03:31Z.

**Prediction:** Legitimate rotation → diff shows one targeted change with no new `Match` blocks, no `PermitRootLogin yes`, no additional `AuthorizedKeysFile`. Backdoor → diff contains at least one of those indicators.

---

### DIRECTIVE-TO-DEFENDER

For alerts where the anomalous action is itself a configuration write — not just an authenticated session but a change to an infrastructure surface — extend provenance checks to the *content* of the change, not only the actor's standing to make it. A credentialed actor with a plausible ticket satisfies "who"; it does not satisfy "what did they actually do." For credentialed-config-write alert classes, the investigation sequence should be: (1) actor standing check, (2) diff the changed artifact against the pre-change state, (3) confirm the observed delta matches the stated purpose. Cover narratives are constructed to pass step 1 and collapse at step 2; skipping the diff leaves the highest-value falsification target unexamined.
```
