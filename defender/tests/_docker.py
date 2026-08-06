"""Is there a docker daemon this process can actually use — and the ambient engine keys.

Two facts several suites need before they can decide whether to run at all, and which had
been hand-copied four times (the daemon probes) and twice (the key seeding) across the e2e
tree and the top-level tree. Neutral home rather than either harness's, because the
callers straddle both: `e2e/_box665`, `e2e/_spec771`, `e2e/test_540_box_boundary` and
`tests/test_store_boundary_705` all ask the same question.

What deliberately does NOT live here: the pytest MARKERS built on these predicates. Those
differ genuinely between suites — one skips on no-daemon-or-DooD, one on no-daemon alone,
one adds a shared-mount coverage condition — and each reason string names the specific
capability its own tests need. A shared marker would flatten three different reasons into
one wrong one.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import subprocess
from pathlib import Path


def daemon_reachable() -> bool:
    """A docker daemon answers `version`. Never raises — an absent binary is a `False`."""
    try:
        return subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, timeout=30,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def is_dood() -> bool:
    """Docker-outside-of-Docker: a reachable daemon whose root dir is not OUR root dir.

    This is the case that matters and the one a bare `daemon_reachable()` misses. Inside a
    container talking to the host's daemon, `docker run -v` binds resolve against the
    HOST's filesystem, so a bind source that exists here is invisible there — the container
    starts and the test then fails on missing files rather than skipping. The probe is
    exactly that: the daemon reports a root directory this process cannot see.
    """
    if not Path("/.dockerenv").exists():
        return False
    probe = subprocess.run(
        ["docker", "info", "--format", "{{.DockerRootDir}}"],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    root = probe.stdout.strip()
    return probe.returncode == 0 and bool(root) and not Path(root).exists()


def satisfy_engine_keys(monkeypatch, disposition: str = "inconclusive") -> None:
    """An ambient provider key per model the run cycle will touch.

    Without it `run_one`'s `_prepare_engines_for` raises `FatalConfigError` during key
    sourcing, before the seam any of these tests is actually about. `setenv`, never
    `setattr` — the env is the sanctioned seam and the monkeypatch gate enforces it.
    """
    from defender.learning.core.config import oracle_model
    from defender.learning.core.directions import BY_NAME
    from defender.learning.core.run_cycle import _directions_for
    from defender.runtime import providers

    models = {oracle_model()}
    for name in _directions_for(disposition):
        d = BY_NAME[name]
        models.add(d.judge_wiring.model)
        models.add(d.actor_model)
    for model in models:
        try:
            var = providers.provider_for(model).api_key_var
        except Exception:  # noqa: BLE001 — best-effort; a red test does not depend on it
            continue
        monkeypatch.setenv(var, "spec-test-key")
