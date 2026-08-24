"""Opt-in deterministic and executable experiment adapters."""

from __future__ import annotations

import asyncio
import os
import sys
from abc import ABC, abstractmethod
from time import perf_counter
from typing import Any

from .adaptive_models import ExperimentAdapterInfo, ExperimentResult
from .journal import digest
from .models import SourceMaterial
from .recursive_models import RecursivePolicy
from .workspace import WorkspaceSnapshot, normalize_relative_path


class ExperimentAdapter(ABC):
    info: ExperimentAdapterInfo

    @abstractmethod
    async def run(
        self,
        arguments: dict[str, Any],
        *,
        snapshot: WorkspaceSnapshot | None,
        source_materials: dict[str, SourceMaterial],
        timeout_seconds: int,
    ) -> ExperimentResult:
        """Execute one bounded experiment and return an auditable result."""


class TextStatisticsAdapter(ExperimentAdapter):
    info = ExperimentAdapterInfo(
        name="text_statistics",
        description=(
            "Deterministically count lines, words, characters, and unique lexical "
            "tokens in one source material or snapshotted workspace file."
        ),
        argument_schema={"source_id": "string"},
    )

    async def run(
        self,
        arguments: dict[str, Any],
        *,
        snapshot: WorkspaceSnapshot | None,
        source_materials: dict[str, SourceMaterial],
        timeout_seconds: int,
    ) -> ExperimentResult:
        del timeout_seconds
        source_id = str(arguments.get("source_id", ""))
        if source_id in source_materials:
            content = source_materials[source_id].content
        elif snapshot is not None and source_id in snapshot.paths:
            content = snapshot.documents([source_id])[0].content
        else:
            raise ValueError(f"Unknown source_id for text_statistics: {source_id!r}")
        started = perf_counter()
        words = content.split()
        punctuation = '.,:;!?()[]{}"'
        lexical = {word.casefold().strip(punctuation) for word in words}
        data = {
            "source_id": source_id,
            "lines": len(content.splitlines()),
            "words": len(words),
            "characters": len(content),
            "unique_lexical_tokens": len({word for word in lexical if word}),
        }
        summary = ", ".join(f"{key}={value}" for key, value in data.items())
        payload = {
            "adapter": self.info.name,
            "arguments": arguments,
            "status": "completed",
            "summary": summary,
            "stdout": "",
            "stderr": "",
            "exit_code": 0,
            "elapsed_ms": round((perf_counter() - started) * 1000),
        }
        return ExperimentResult(**payload, content_sha256=digest(payload))


class PytestAdapter(ExperimentAdapter):
    info = ExperimentAdapterInfo(
        name="pytest",
        description=(
            "Run pytest in the snapshotted workspace with bounded, validated target "
            "paths. This executes workspace code and must be explicitly enabled."
        ),
        argument_schema={"targets": "list[string], optional"},
        executes_workspace_code=True,
    )

    async def run(
        self,
        arguments: dict[str, Any],
        *,
        snapshot: WorkspaceSnapshot | None,
        source_materials: dict[str, SourceMaterial],
        timeout_seconds: int,
    ) -> ExperimentResult:
        del source_materials
        if snapshot is None:
            raise ValueError("pytest requires a workspace snapshot")
        raw_targets = arguments.get("targets", [])
        if not isinstance(raw_targets, list) or len(raw_targets) > 12:
            raise ValueError("pytest targets must be a list of at most 12 paths")
        targets: list[str] = []
        for raw_target in raw_targets:
            target = normalize_relative_path(str(raw_target))
            resolved = (snapshot.root / target).resolve()
            if snapshot.root not in resolved.parents and resolved != snapshot.root:
                raise ValueError(f"pytest target escapes workspace: {target}")
            if not resolved.exists():
                raise ValueError(f"pytest target does not exist: {target}")
            targets.append(target)
        command = [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "--disable-warnings",
            *targets,
        ]
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        started = perf_counter()
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=snapshot.root,
            env=environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(), timeout=timeout_seconds
            )
            status = "completed" if process.returncode == 0 else "failed"
            exit_code = process.returncode
        except TimeoutError:
            process.kill()
            stdout_bytes, stderr_bytes = await process.communicate()
            status = "timed_out"
            exit_code = None
        stdout = stdout_bytes.decode("utf-8", errors="replace")[-12000:]
        stderr = stderr_bytes.decode("utf-8", errors="replace")[-12000:]
        display_targets = targets or ["."]
        payload = {
            "adapter": self.info.name,
            "arguments": {"targets": targets},
            "status": status,
            "summary": (
                f"pytest {status}; exit_code={exit_code}; targets={display_targets}"
            ),
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "elapsed_ms": round((perf_counter() - started) * 1000),
        }
        return ExperimentResult(**payload, content_sha256=digest(payload))


class ModelAuthoredPythonAdapter(ExperimentAdapter):
    info = ExperimentAdapterInfo(
        name="python_checker",
        description=(
            "Execute one bounded model-authored Python checker. This is opt-in, "
            "receives no inherited environment secrets, and is auditable, but it "
            "is not a security sandbox."
        ),
        argument_schema={"code": "string (max 50000 chars)", "argv": "list[string]"},
        executes_workspace_code=True,
        executes_model_authored_code=True,
    )

    async def run(
        self,
        arguments: dict[str, Any],
        *,
        snapshot: WorkspaceSnapshot | None,
        source_materials: dict[str, SourceMaterial],
        timeout_seconds: int,
    ) -> ExperimentResult:
        del source_materials
        code = arguments.get("code")
        argv = arguments.get("argv", [])
        if not isinstance(code, str) or not code.strip() or len(code) > 50_000:
            raise ValueError(
                "python_checker code must be a non-empty string of at most 50000 chars"
            )
        if (
            not isinstance(argv, list)
            or len(argv) > 20
            or any(not isinstance(item, str) or len(item) > 1000 for item in argv)
        ):
            raise ValueError(
                "python_checker argv must contain at most 20 bounded strings"
            )
        command = [sys.executable, "-I", "-S", "-c", code, *argv]
        cwd = snapshot.root if snapshot is not None else None
        environment = {
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONIOENCODING": "utf-8",
        }
        started = perf_counter()
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=cwd,
            env=environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout_bytes, stderr_bytes = await asyncio.wait_for(
                process.communicate(), timeout=timeout_seconds
            )
            status = "completed" if process.returncode == 0 else "failed"
            exit_code = process.returncode
        except TimeoutError:
            process.kill()
            stdout_bytes, stderr_bytes = await process.communicate()
            status = "timed_out"
            exit_code = None
        stdout = stdout_bytes.decode("utf-8", errors="replace")[-12000:]
        stderr = stderr_bytes.decode("utf-8", errors="replace")[-12000:]
        payload = {
            "adapter": self.info.name,
            "arguments": {"code": code, "argv": argv},
            "status": status,
            "summary": (
                f"python_checker {status}; exit_code={exit_code}; "
                f"code_sha256={digest(code)}"
            ),
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": exit_code,
            "elapsed_ms": round((perf_counter() - started) * 1000),
        }
        return ExperimentResult(**payload, content_sha256=digest(payload))


def experiment_adapters(policy: RecursivePolicy) -> dict[str, ExperimentAdapter]:
    available: dict[str, ExperimentAdapter] = {
        "text_statistics": TextStatisticsAdapter(),
        "pytest": PytestAdapter(),
        "python_checker": ModelAuthoredPythonAdapter(),
    }
    unknown = set(policy.enabled_experiment_adapters) - set(available)
    if unknown:
        raise ValueError(f"Unknown experiment adapters: {sorted(unknown)}")
    return {name: available[name] for name in policy.enabled_experiment_adapters}
