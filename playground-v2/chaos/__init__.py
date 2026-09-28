"""Chaos control plane for the SOC playground.

Devcontainer-side fault injection: stale CMDB records, renamed/dropped log
fields. Every mutation travels over `docker exec` (`ctl.DockerExecSeam`), so
the fault lives in the stack, not in a controller process the
agent-under-test could observe.


Never shipped with the soc-agent plugin; same boundary as attacks/runner.py.
"""
