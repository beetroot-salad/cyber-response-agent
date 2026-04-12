#!/usr/bin/env python3
"""Preload ticket-context and archetype-scan during skill expansion.

Called as a !command in SKILL.md after setup_run.py has created the run
directory. Forks a detached child that spawns two claude subprocesses in
parallel (ticket-context on Sonnet, archetype-scan on Haiku) and writes
their outputs to `{run_dir}/ticket_context.yaml` and `archetype_scan.yaml`.
The parent returns immediately so skill expansion is not blocked; the main
agent reads the files from disk during CONTEXTUALIZE.

Usage: python3 scripts/contextualize_preload.py <signature_id>

Finds the current run directory by scanning SOC_AGENT_RUNS_DIR for the
most recent subdirectory whose meta.json matches the given signature_id.

Exit codes:
    0 — Always. This script must never block skill expansion.
"""

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
SKILLS_DIR = SOC_AGENT_ROOT / "skills" / "investigate"

TICKET_CONTEXT_PROMPT = SKILLS_DIR / "ticket-context.md"
ARCHETYPE_SCAN_PROMPT = SKILLS_DIR / "archetype-scan.md"

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

SUBPROCESS_TIMEOUT = int(os.environ.get("SOC_AGENT_PRELOAD_TIMEOUT", "240"))

# ---------------------------------------------------------------------------
# Frontmatter parsing (reuse the zero-dep parser from hooks/scripts/)
# ---------------------------------------------------------------------------

sys.path.insert(0, str(SOC_AGENT_ROOT / "hooks" / "scripts"))
from frontmatter import parse_yaml_frontmatter  # noqa: E402


# ---------------------------------------------------------------------------
# Run directory discovery
# ---------------------------------------------------------------------------


def find_run_dir(signature_id: str) -> Path | None:
    """Find the current run directory from SOC_AGENT_RUNS_DIR.

    Scans for the most recently modified subdirectory whose meta.json
    matches the given signature_id and contains alert.json.
    """
    runs_base = Path(
        os.environ.get("SOC_AGENT_RUNS_DIR", str(SOC_AGENT_ROOT / "runs"))
    )
    if not runs_base.is_dir():
        return None

    candidates = []
    for d in runs_base.iterdir():
        if not d.is_dir() or d.name.startswith("."):
            continue
        alert = d / "alert.json"
        meta = d / "meta.json"
        if not alert.exists() or not meta.exists():
            continue
        try:
            meta_data = json.loads(meta.read_text())
            if meta_data.get("signature_id") == signature_id:
                candidates.append(d)
        except (json.JSONDecodeError, OSError):
            continue

    if not candidates:
        return None
    return max(candidates, key=lambda d: d.stat().st_mtime)


# ---------------------------------------------------------------------------
# Core logic
# ---------------------------------------------------------------------------


def build_subagent_prompt(template_path: Path, substitutions: dict[str, str]) -> tuple[str, str]:
    """Read a subagent prompt template and substitute variables.

    Returns (prompt_body, model) where model comes from frontmatter.
    Raises ValueError if the template has no model declared in frontmatter.
    """
    text = template_path.read_text()
    fm = parse_yaml_frontmatter(text)
    model = fm.get("model")
    if model is None:
        raise ValueError(f"{template_path.name}: frontmatter missing required 'model' field")

    # Strip frontmatter from the body — everything after the closing ---
    parts = text.split("---", 2)
    if len(parts) < 3:
        raise ValueError(f"{template_path.name}: missing frontmatter delimiters (expected --- ... ---)")
    body = parts[2]

    for key, value in substitutions.items():
        body = body.replace(f"{{{key}}}", value)

    return body.strip(), str(model)


def invoke_subagent(
    prompt: str,
    model: str,
    label: str,
    allowed_tools: list[str] | None = None,
    extra_dirs: list[str] | None = None,
) -> tuple[str, str | None]:
    """Invoke claude --print with the given prompt and model.

    Returns (output, error). Error is None on success.

    The subagent gets --add-dir for the soc-agent knowledge tree and
    acceptEdits permission mode so it can read files without interactive
    approval (not possible in --print mode). Pass allowed_tools for
    subagents that need Bash access (e.g. SIEM queries). Pass extra_dirs
    to grant read access to directories outside the soc-agent root
    (e.g. the eval run directory under /tmp/).
    """
    try:
        cmd = [
            "claude", "-p", prompt,
            "--model", model,
            "--output-format", "text",
            "--permission-mode", "acceptEdits",
            "--add-dir", str(SOC_AGENT_ROOT),
        ]
        for d in (extra_dirs or []):
            cmd.extend(["--add-dir", d])
        for tool in (allowed_tools or []):
            cmd.extend(["--allowedTools", tool])
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=SUBPROCESS_TIMEOUT,
            cwd=str(SOC_AGENT_ROOT),
        )
        if result.returncode != 0:
            return "", f"{label} exited with code {result.returncode}: {result.stderr[:200]}"
        return result.stdout.strip(), None
    except FileNotFoundError:
        return "", f"{label}: claude CLI not found"
    except subprocess.TimeoutExpired:
        return "", f"{label}: timed out after {SUBPROCESS_TIMEOUT}s"


def _run_subagents(
    run_path: Path,
    runs_dir: str,
    tc_prompt: str | None,
    tc_model: str | None,
    tc_build_error: str | None,
    as_prompt: str | None,
    as_model: str | None,
    as_build_error: str | None,
) -> None:
    """Run subagents and write output files. Called in a forked child process."""
    # Ticket-context needs Bash for SIEM queries; archetype-scan is read-only.
    # Allow both relative and absolute paths for the SIEM CLI.
    tc_tools = [
        "Bash(python3 scripts/tools/wazuh_cli.py *)",
        f"Bash(python3 {SOC_AGENT_ROOT}/scripts/tools/wazuh_cli.py *)",
    ]
    run_parent = [runs_dir]

    tc_output, tc_error = None, tc_build_error
    as_output, as_error = None, as_build_error

    futures = {}
    with ThreadPoolExecutor(max_workers=2) as executor:
        if tc_prompt is not None:
            futures["ticket-context"] = executor.submit(
                invoke_subagent, tc_prompt, tc_model, "ticket-context",
                tc_tools, run_parent,
            )
        if as_prompt is not None:
            futures["archetype-scan"] = executor.submit(
                invoke_subagent, as_prompt, as_model, "archetype-scan",
                None, run_parent,
            )

        for label, future in futures.items():
            try:
                output, error = future.result(timeout=SUBPROCESS_TIMEOUT + 10)
                if label == "ticket-context":
                    tc_output, tc_error = output, error
                else:
                    as_output, as_error = output, error
            except Exception as e:
                if label == "ticket-context":
                    tc_error = f"future error: {e}"
                else:
                    as_error = f"future error: {e}"

    # Save outputs to disk — the main agent checks for these files
    if tc_output:
        try:
            (run_path / "ticket_context.yaml").write_text(tc_output)
        except OSError:
            pass
    if as_output:
        try:
            (run_path / "archetype_scan.yaml").write_text(as_output)
        except OSError:
            pass


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <signature_id>", file=sys.stderr)
        return 0  # never block

    signature_id = sys.argv[1]

    # Find the run directory
    run_path = find_run_dir(signature_id)
    if run_path is None:
        print(f"contextualize_preload: no run directory found for {signature_id}", file=sys.stderr)
        return 0

    run_dir = str(run_path)
    runs_dir = str(run_path.parent)

    # Build subagent prompts
    substitutions = {
        "run_dir": run_dir,
        "signature_id": signature_id,
        "runs_dir": runs_dir,
    }

    tc_prompt = tc_model = tc_build_error = None
    as_prompt = as_model = as_build_error = None

    try:
        tc_prompt, tc_model = build_subagent_prompt(TICKET_CONTEXT_PROMPT, substitutions)
    except Exception as e:
        tc_build_error = str(e)

    try:
        as_prompt, as_model = build_subagent_prompt(ARCHETYPE_SCAN_PROMPT, substitutions)
    except Exception as e:
        as_build_error = str(e)

    if tc_prompt is None and as_prompt is None:
        return 0

    # Fork the subagent work into a background process so the !command
    # returns immediately and skill expansion is not blocked.
    pid = os.fork()
    if pid > 0:
        # Parent: print status message (embedded in prompt) and exit.
        print(f"Preload dispatched — ticket-context (Sonnet) and archetype-scan (Haiku) "
              f"are running in the background. Output files will appear at "
              f"`{run_dir}/ticket_context.yaml` and `{run_dir}/archetype_scan.yaml`.")
        return 0

    # Child: detach from parent session so we survive the !command returning.
    try:
        os.setsid()
        # Close inherited stdio to avoid interfering with the parent's pipes.
        sys.stdout = open(os.devnull, "w")
        sys.stderr = open(os.devnull, "w")
        sys.stdin = open(os.devnull, "r")

        _run_subagents(
            run_path, runs_dir,
            tc_prompt, tc_model, tc_build_error,
            as_prompt, as_model, as_build_error,
        )
    except Exception:
        pass
    finally:
        os._exit(0)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        print(f"contextualize_preload: unhandled error: {e}", file=sys.stderr)
        sys.exit(0)
