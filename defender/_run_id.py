from __future__ import annotations


RUN_ID_ALLOWED = "ASCII alphanumerics, '_', '.', '-', starting alphanumeric"


def is_valid_run_id(run_id: str) -> bool:
    return (
        bool(run_id)
        and run_id.isascii()
        and run_id[0].isalnum()
        and all(c.isalnum() or c in "_.-" for c in run_id)
    )
