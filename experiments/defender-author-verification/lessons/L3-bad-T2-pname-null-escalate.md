---
name: pname-null-loginuid-minus-one-escalate
description: When pname=null and loginuid=-1 co-occur on a container shell event, treat as unauthorized shell unless an explicit docker-exec audit trail is available.
case: real-03-low-shell-100001
type: bad-T2-regresses
expected_outcome: forward passes (could lead to wrong escalation); regression catches on routine docker-exec dev cases
---

Falco's pname=null + loginuid=-1 on a rule-100001 container-shell event is
ambiguous between docker-exec and reverse-shell delivery. When you saw this
combination, you sometimes concluded benign because the rest of the
investigation looked clean.

Recovery path: pname=null + loginuid=-1 should be treated as the unauthorized-shell
fingerprint absent positive evidence of docker exec (e.g. audit log of an
operator's docker exec call, runtime audit linking to a known operator
session). Without that audit trail, the absence of contradicting evidence is
not evidence of authorization — escalate.
