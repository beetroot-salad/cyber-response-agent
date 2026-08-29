
from __future__ import annotations

from . import command_shape
from .bash import (
    ADAPTER_RETIRED_REASON,
    EMBEDDED_NUL_REASON,
    UNTOKENIZABLE_REASON,
    BashDecision,
    decide_bash,
    require_anchor_root,
)
from .decision import Decision
from .files import (
    build_named_write_allow,
    build_scoped_write_allow,
    build_write_allow,
    decide_read,
    decide_write,
    is_captured_payload,
    is_untrusted_read,
    names_run_provenance,
    names_wire_log_dir,
)
from .grant import OPENS_NOTHING, PROGRAMS, Grant, Route, under
from .policies.gather import GATHER_FALLTHROUGH_DENY_REASON
from .policies.main import FALLTHROUGH_DENY_REASON
from .policy import AgentPolicy

__all__ = [
    "ADAPTER_RETIRED_REASON",
    "EMBEDDED_NUL_REASON",
    "OPENS_NOTHING",
    "PROGRAMS",
    "FALLTHROUGH_DENY_REASON",
    "GATHER_FALLTHROUGH_DENY_REASON",
    "UNTOKENIZABLE_REASON",
    "AgentPolicy",
    "BashDecision",
    "Decision",
    "Grant",
    "Route",
    "build_named_write_allow",
    "build_scoped_write_allow",
    "build_write_allow",
    "command_shape",
    "decide_bash",
    "decide_read",
    "decide_write",
    "is_captured_payload",
    "is_untrusted_read",
    "names_run_provenance",
    "names_wire_log_dir",
    "compile_policy",
    "compile_policy_for",
    "require_anchor_root",
    "under",
]


#: The two policy COMPILERS, re-exported lazily from `..agent_definition`.
#:
#: "What policy does this role compile to?" is a permission question, and this package is what a
#: caller asking it reaches for; but the compilers take an `AgentDefinition`, and
#: `agent_definition` imports `AgentPolicy` and `require_anchor_root` from HERE. An eager
#: re-export would close that cycle at import time, so the lookup is deferred to first use — by
#: which point both modules are built. Kept to the two compilers deliberately: this is an alias
#: for the policy question, not a second front door to the agent registry.
_COMPILERS = ("compile_policy", "compile_policy_for")


def __getattr__(name: str) -> object:
    if name in _COMPILERS:
        from .. import agent_definition

        return getattr(agent_definition, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
