"""Chaos control plane for the SOC playground (issue #401).

Devcontainer-side fault injection: stale CMDB records, renamed/dropped log
fields. Every mutation travels over `docker --context soc-playground exec` —
see `ctl.DockerExecSeam` — so the fault lives in the stack, not in a
long-lived controller process the agent-under-test could ever observe.

Never shipped with the soc-agent plugin; same boundary as attacks/runner.py.
"""
