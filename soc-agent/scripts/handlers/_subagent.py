"""Shared subagent invocation wrapper used by every phase handler.

Invokes a plugin-defined subagent by reading its `agents/{name}.md` definition,
splitting frontmatter from body, and passing the body as `--system-prompt-file`
to a `claude -p` one-shot call. Works around the CLI's lack of direct plugin
subagent dispatch (`--agent soc-agent:{name}` doesn't route to the subagent;
it just starts a generic main-agent session).

Also centralizes:
    - terminal YAML extraction
    - `inject_env_context.py` equivalent: env-gated subagents get their SIEM
      adapter SKILL.md appended to the user prompt before invocation
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import yaml

from scripts.orchestrate import OrchestrationError

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent

DEFAULT_TIMEOUT_SECONDS = int(
    os.environ.get("SOC_AGENT_SUBAGENT_TIMEOUT_SECONDS", "300")
)

# subagent name → env var naming the SIEM/ticketing adapter whose
# knowledge/environment/systems/{adapter}/SKILL.md gets appended to the prompt.
# Mirrors hooks/scripts/inject_env_context.py's ENV_GATED_SUBAGENTS.
ENV_GATED_SUBAGENTS: dict[str, str] = {
    "ticket-context": "SOC_AGENT_SIEM_ADAPTER",
    "gather": "SOC_AGENT_SIEM_ADAPTER",
}


# ---------------------------------------------------------------------------
# Agent definition loading
# ---------------------------------------------------------------------------


_FRONTMATTER_RE = re.compile(r"\A---\n(.*?)\n---\n(.*)\Z", re.DOTALL)


def _load_agent_definition(name: str) -> tuple[str, dict]:
    """Read `agents/{name}.md`, split frontmatter from body.

    Returns (body_text, frontmatter_dict). Body is the subagent's system prompt;
    frontmatter carries `model` and `tools`.
    """
    path = SOC_AGENT_ROOT / "agents" / f"{name}.md"
    if not path.exists():
        raise OrchestrationError(f"subagent definition not found: {path}")
    text = path.read_text()
    m = _FRONTMATTER_RE.match(text)
    if not m:
        raise OrchestrationError(
            f"subagent {path} missing YAML frontmatter"
        )
    try:
        frontmatter = yaml.safe_load(m.group(1)) or {}
    except yaml.YAMLError as exc:
        raise OrchestrationError(
            f"subagent {path} frontmatter did not parse: {exc}"
        ) from exc
    body = m.group(2).strip()
    if not body:
        raise OrchestrationError(f"subagent {path} has empty body")
    return body, frontmatter


def _tools_list(frontmatter: dict) -> list[str]:
    """Normalize the frontmatter `tools:` field into a comma-split list."""
    raw = frontmatter.get("tools", "")
    if isinstance(raw, list):
        return [t.strip() for t in raw if t.strip()]
    if isinstance(raw, str):
        return [t.strip() for t in raw.split(",") if t.strip()]
    return []


# ---------------------------------------------------------------------------
# Env-context injection (replaces the PreToolUse hook path)
# ---------------------------------------------------------------------------


def _inject_env_context(subagent_name: str, prompt: str) -> str:
    """If the subagent is env-gated, append the SIEM/ticketing adapter's
    SKILL.md to the prompt. Mirrors `inject_env_context.py`."""
    env_var = ENV_GATED_SUBAGENTS.get(subagent_name)
    if not env_var:
        return prompt
    adapter = os.environ.get(env_var)
    if not adapter:
        return prompt
    skill_path = (
        SOC_AGENT_ROOT / "knowledge" / "environment" / "systems"
        / adapter / "SKILL.md"
    )
    if not skill_path.exists():
        return prompt
    return (
        prompt
        + "\n\n## Environment adapter (injected from "
        + env_var
        + ")\n\n"
        + skill_path.read_text()
    )


# ---------------------------------------------------------------------------
# Subagent invocation
# ---------------------------------------------------------------------------


def invoke_subagent(
    agent: str,
    prompt: str,
    *,
    model: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> str:
    """Run a subagent by name (e.g. "archetype-scan") and return its stdout.

    The `agent` argument is the bare subagent name — **not** the
    `soc-agent:archetype-scan` prefixed form. The plugin prefix is a Task-tool
    convention, not a CLI one.

    Implementation: reads `agents/{agent}.md`, passes body as
    `--system-prompt-file`, passes the user prompt via stdin. Model defaults
    to the subagent's frontmatter `model:` if not overridden.
    """
    body, frontmatter = _load_agent_definition(agent)
    effective_model = model or frontmatter.get("model") or "haiku"
    tools = _tools_list(frontmatter)
    final_prompt = _inject_env_context(agent, prompt)

    # Write body to a temp file so `--system-prompt-file` can read it.
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".md", delete=False, prefix=f"subagent-{agent}-",
    ) as tmp:
        tmp.write(body)
        tmp_path = tmp.name

    argv = [
        "claude", "-p",
        "--model", effective_model,
        "--system-prompt-file", tmp_path,
        "--output-format", "text",
    ]
    if tools:
        argv.extend(["--allowed-tools", ",".join(tools)])

    # Ensure the subagent's Bash tool resolves `python3` to the same venv the
    # handler is running in — otherwise the subagent hits system python which
    # is missing the soc-agent extras (wazuh, elastic, etc.) and `ticket_context.py`
    # / `wazuh_cli.py` fail with import errors.
    env = dict(os.environ)
    venv_bin = SOC_AGENT_ROOT / ".venv" / "bin"
    if venv_bin.is_dir():
        env["PATH"] = f"{venv_bin}:{env.get('PATH', '')}"
        env["VIRTUAL_ENV"] = str(SOC_AGENT_ROOT / ".venv")

    try:
        result = subprocess.run(
            argv,
            input=final_prompt,
            capture_output=True, text=True,
            timeout=timeout,
            env=env,
        )
    except FileNotFoundError as exc:
        raise OrchestrationError(f"claude CLI not found: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        raise OrchestrationError(
            f"subagent {agent} timed out after {timeout}s"
        ) from exc
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    if result.returncode != 0:
        raise OrchestrationError(
            f"subagent {agent} exited {result.returncode}: {result.stderr.strip()}"
        )
    return result.stdout


# ---------------------------------------------------------------------------
# Terminal YAML extraction
# ---------------------------------------------------------------------------


def extract_terminal_yaml(raw: str) -> dict:
    """Return the last fenced ```yaml block from `raw` parsed as a mapping.

    Subagents are contracted to emit a single terminal YAML block as their
    final message. Taking the *last* such block tolerates any preamble a
    subagent might accidentally emit (their contracts forbid it — defense in
    depth).
    """
    block: Optional[str] = None
    fence = "```yaml"
    end = "```"
    i = 0
    while True:
        start = raw.find(fence, i)
        if start == -1:
            break
        start_body = start + len(fence)
        if start_body < len(raw) and raw[start_body] == "\n":
            start_body += 1
        stop = raw.find(end, start_body)
        if stop == -1:
            break
        block = raw[start_body:stop]
        i = stop + len(end)

    if block is None:
        raise OrchestrationError(
            "subagent produced no terminal YAML block:\n" + raw
        )

    try:
        parsed = yaml.safe_load(block)
    except yaml.YAMLError as exc:
        raise OrchestrationError(
            f"subagent terminal YAML did not parse: {exc}\n{block}"
        ) from exc

    if not isinstance(parsed, dict):
        raise OrchestrationError(
            f"subagent terminal YAML is not a mapping: {parsed!r}"
        )
    return parsed
