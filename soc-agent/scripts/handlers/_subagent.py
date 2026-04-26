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

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import yaml

from scripts.handlers._markdown import iter_yaml_fences
from scripts.orchestrate import OrchestrationError

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent.parent

# Make hooks/scripts/run_context importable without forcing callers to set up
# sys.path themselves — tests import this module directly.
if str(SOC_AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.run_context import write_session_mapping  # noqa: E402

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


def _resolve_run_context() -> tuple[Optional[Path], str]:
    """Read the current run_dir / signature_id from env.

    Set by `orchestrate.run()` at state-machine startup so every
    `invoke_subagent` call can write its session→run mapping and persist
    per-invocation artifacts without plumbing the Context through every
    handler.
    """
    run_dir_val = os.environ.get("SOC_AGENT_RUN_DIR", "")
    run_dir = Path(run_dir_val) if run_dir_val else None
    signature_id = os.environ.get("SOC_AGENT_SIGNATURE_ID", "")
    return run_dir, signature_id


def invoke_subagent(
    agent: str,
    prompt: str,
    *,
    model: Optional[str] = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    session_id: Optional[str] = None,
) -> str:
    """Run a subagent by name (e.g. "archetype-match") and return its stdout.

    The `agent` argument is the bare subagent name — **not** the
    `soc-agent:archetype-match` prefixed form. The plugin prefix is a Task-tool
    convention, not a CLI one.

    Implementation:
        - Reads `agents/{agent}.md`, passes body as `--system-prompt-file`,
          passes the user prompt via stdin.
        - Loads the soc-agent plugin via `--plugin-dir` so the subagent's
          PreToolUse/PostToolUse hooks (invlang_validate, tag_tool_results,
          audit_tool_calls, etc.) fire inside the child session.
        - Forces a UUID session id via `--session-id` and writes the
          session→run mapping before invocation so hooks resolve run_dir
          deterministically (no race with mtime fallback).
        - After invocation, persists the prompt+stdout and a JSONL audit
          record under the run dir. Advisory: these never block the handler.

    Model defaults to the subagent's frontmatter `model:` if not overridden.

    `session_id`: when provided, used as the child session id instead of
    generating a UUID. Required by callers that need to partition manifest
    entries across concurrent dispatches (each parallel call pre-mints its
    own UUID so the orchestrator can group hook-saved tool outputs by it).
    """
    body, frontmatter = _load_agent_definition(agent)
    effective_model = model or frontmatter.get("model") or "haiku"
    tools = _tools_list(frontmatter)
    final_prompt = _inject_env_context(agent, prompt)

    # Eagerly establish a session → run mapping so inner hooks resolve run_dir
    # via the fast path instead of the racy mtime-scan fallback.
    if session_id is None:
        session_id = str(uuid.uuid4())
    run_dir, signature_id = _resolve_run_context()
    if run_dir is not None and run_dir.exists():
        try:
            write_session_mapping(
                session_id, run_dir, signature_id, run_dir.parent
            )
        except Exception:
            pass  # advisory — mapping is best-effort

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
        "--session-id", session_id,
        "--plugin-dir", str(SOC_AGENT_ROOT),
        "--output-format", "text",
    ]
    if tools:
        argv.extend(["--allowed-tools", ",".join(tools)])

    # Optional per-agent effort override. Read from `effort:` frontmatter or
    # a per-agent env var `SOC_AGENT_{AGENT}_EFFORT`. CLI flag values:
    # low | medium | high | xhigh | max.
    effort = (
        frontmatter.get("effort")
        or os.environ.get(f"SOC_AGENT_{agent.upper().replace('-', '_')}_EFFORT")
    )
    if effort:
        argv.extend(["--effort", str(effort)])

    # Ensure the subagent's Bash tool resolves `python3` to the same venv the
    # handler is running in — otherwise the subagent hits system python which
    # is missing the soc-agent extras (wazuh, elastic, etc.) and `ticket_context.py`
    # / `wazuh_cli.py` fail with import errors.
    env = dict(os.environ)
    venv_bin = SOC_AGENT_ROOT / ".venv" / "bin"
    if venv_bin.is_dir():
        env["PATH"] = f"{venv_bin}:{env.get('PATH', '')}"
        env["VIRTUAL_ENV"] = str(SOC_AGENT_ROOT / ".venv")

    started = time.monotonic()
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
    duration_ms = int((time.monotonic() - started) * 1000)

    if run_dir is not None and run_dir.exists():
        try:
            _append_subagent_log(
                run_dir, agent, session_id,
                final_prompt, result.stdout, result.stderr,
            )
            _append_subagent_audit(
                run_dir, agent, session_id, effective_model,
                duration_ms, result.returncode,
                len(final_prompt), len(result.stdout),
            )
        except Exception:
            pass  # advisory — persistence must never crash a handler

    if result.returncode != 0:
        raise OrchestrationError(
            f"subagent {agent} exited {result.returncode}: {result.stderr.strip()}"
        )
    return result.stdout


# ---------------------------------------------------------------------------
# Outer-layer persistence helpers
# ---------------------------------------------------------------------------


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ts_filename() -> str:
    # Sortable UTC timestamp safe for filenames.
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def _append_subagent_log(
    run_dir: Path,
    agent: str,
    session_id: str,
    prompt: str,
    stdout: str,
    stderr: str,
) -> None:
    """Persist the full invocation under `{run_dir}/subagent_outputs/` for
    post-mortem. One file per call, named by timestamp + agent."""
    out_dir = run_dir / "subagent_outputs"
    out_dir.mkdir(parents=True, exist_ok=True)
    # session_id suffix disambiguates concurrent same-agent spawns (the
    # parallel-singletons orchestrator runs N gather subagents in the same
    # microsecond window).
    sid_suffix = session_id.split("-")[0] if session_id else "nosid"
    path = out_dir / f"{_ts_filename()}-{agent}-{sid_suffix}.txt"
    parts = [
        f"=== agent: {agent} ===",
        f"=== session_id: {session_id} ===",
        "",
        "=== PROMPT ===",
        prompt,
        "",
        "=== STDOUT ===",
        stdout,
    ]
    if stderr:
        parts.extend(["", "=== STDERR ===", stderr])
    path.write_text("\n".join(parts))


def _append_subagent_audit(
    run_dir: Path,
    agent: str,
    session_id: str,
    model: str,
    duration_ms: int,
    returncode: int,
    prompt_chars: int,
    stdout_chars: int,
) -> None:
    """Append a one-line JSONL record per invocation to `subagent_audit.jsonl`.
    Distinct from the plugin's `tool_audit.jsonl` — that log captures tools the
    subagent used; this log captures the *spawn* event itself, which the
    orchestrator shells out to via subprocess and is invisible to PostToolUse."""
    audit_path = run_dir / "subagent_audit.jsonl"
    entry = {
        "timestamp": _iso_now(),
        "agent": agent,
        "session_id": session_id,
        "model": model,
        "duration_ms": duration_ms,
        "returncode": returncode,
        "prompt_chars": prompt_chars,
        "stdout_chars": stdout_chars,
    }
    with open(audit_path, "a") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


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
    for body in iter_yaml_fences(raw):
        block = body

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
