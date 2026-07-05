"""Per-agent Bash policy files — one module per runtime agent.

Each module answers "what can this agent run?" from one place: it builds the
agent's `AgentPolicy`, whose `bash_allow` is a flat list of anchored regexes over
the tokenized argv (see `..policy.AgentPolicy`). Runtime agents (main/gather) live
here; learning-loop agents (judge, actor) build their own `AgentPolicy` in their
own pipeline module, co-located with the rest of their agent-specific wiring.
"""
