---
name: container-shell-baseline-before-isolation-conclusion
description: On rule-100001 with pname=null + loginuid=-1, gather the container's shell-spawn baseline before treating "no surrounding alerts" as authorization evidence.
case: real-03-low-shell-100001
type: good
expected_outcome: all checks should pass (verdict GOOD)
---

When you saw rule-100001 with `pname=null` + `loginuid=-1` (Falco container
shell, ambiguous between docker-exec and reverse-shell delivery), you
sometimes concluded benign because the surrounding-alerts query returned
clean. Absence of surrounding alerts is not by itself authorization
evidence — it's necessary but not sufficient.

Recovery path: when pname=null + loginuid=-1 co-occur on a rule-100001
event, gather the container's shell-spawn baseline (rule-100001 history
on this container over 7d) as a co-equal lead alongside the
surrounding-alerts check. A documented dev/ops baseline of similar
one-shot commands (`whoami`, `ls`, `env`) is positive authorization
evidence; an empty or sparse history with a single shell event in
isolation is not — that combination warrants a runtime audit lead before
disposition.
