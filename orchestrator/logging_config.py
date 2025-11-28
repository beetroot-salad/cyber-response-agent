"""
Logging configuration for the orchestrator.

Provides structured JSON logging for audit trail.
"""

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class JSONFormatter(logging.Formatter):
    """Format log records as JSON for structured logging."""

    def format(self, record: logging.LogRecord) -> str:
        log_data = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }

        # Add extra fields if present
        if hasattr(record, "ticket_id"):
            log_data["ticket_id"] = record.ticket_id
        if hasattr(record, "signature_id"):
            log_data["signature_id"] = record.signature_id
        if hasattr(record, "event"):
            log_data["event"] = record.event
        if hasattr(record, "data"):
            log_data["data"] = record.data

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_data)


def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """
    Set up structured JSON logging.

    Args:
        level: Logging level (default INFO)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger("orchestrator")
    logger.setLevel(level)

    # Remove existing handlers
    logger.handlers.clear()

    # Console handler with JSON formatting
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JSONFormatter())
    logger.addHandler(handler)

    return logger


def log_event(
    logger: logging.Logger,
    event: str,
    message: str,
    ticket_id: str = None,
    signature_id: str = None,
    data: dict[str, Any] = None,
    level: int = logging.INFO,
) -> None:
    """
    Log a structured event.

    Args:
        logger: Logger instance
        event: Event type (e.g., "investigation_started", "agent_invoked")
        message: Human-readable message
        ticket_id: Optional ticket ID
        signature_id: Optional signature ID
        data: Optional additional data
        level: Log level
    """
    extra = {"event": event}
    if ticket_id:
        extra["ticket_id"] = ticket_id
    if signature_id:
        extra["signature_id"] = signature_id
    if data:
        extra["data"] = data

    logger.log(level, message, extra=extra)
