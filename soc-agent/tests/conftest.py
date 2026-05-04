"""Shared pytest configuration and fixtures for soc-agent tests."""

import os
import sys
import sysconfig
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

FIXTURES = SOC_AGENT_ROOT / "tests" / "fixtures"


def _enable_subprocess_coverage() -> None:
    # Many tests subprocess-spawn hook scripts and CLI entrypoints. Without
    # this shim, pytest-cov only measures the parent process and the child
    # paths look uncovered. The .pth file is honored by Python at startup
    # for any interpreter using this venv's site-packages.
    cov_active = (
        "coverage" in sys.modules
        or os.environ.get("COV_CORE_SOURCE")
        or os.environ.get("COVERAGE_PROCESS_START")
        or any(arg.startswith("--cov") for arg in sys.argv)
    )
    if not cov_active:
        return
    site_packages = Path(sysconfig.get_paths()["purelib"])
    pth = site_packages / "coverage_subprocess.pth"
    if not pth.exists():
        try:
            pth.write_text("import coverage; coverage.process_startup()\n")
        except OSError:
            return
    os.environ.setdefault("COVERAGE_PROCESS_START", str(SOC_AGENT_ROOT / "pyproject.toml"))


_enable_subprocess_coverage()


def pytest_configure(config):
    config.addinivalue_line("markers", "llm: tests requiring LLM (Claude CLI + API)")
    config.addinivalue_line("markers", "live: tests requiring live SIEM (Wazuh playground)")
