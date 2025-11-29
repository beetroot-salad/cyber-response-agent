"""
Configuration module for Cyber Response Agent.

Contains:
- logging_config: Structured JSON logging
- signatures/: Per-signature permissions and settings
"""

from .logging_config import JSONFormatter, log_event, setup_logging

__all__ = [
    "JSONFormatter",
    "log_event",
    "setup_logging",
]
