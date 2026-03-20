"""Shared pytest configuration and fixtures for soc-agent tests."""

import sys
from pathlib import Path

# Add soc-agent root to sys.path so schemas can be imported
SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))
