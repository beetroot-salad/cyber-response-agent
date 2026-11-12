"""The proxy's own audit (#1163 O9, A4, A13): one JSON object per line per proxied request,
appended to a file and never truncated or rewritten. Credential writes are audited by OpenBao's
audit device, not here."""
from __future__ import annotations

import json
import os
import stat
import threading
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Protocol

#: The keys every proxy audit record carries (A4): `outcome` is `sent <status>` or the fault
#: class; `path` is relative to the declared base; `version` is the system record's version applied.
#: A field the request never reached (a token refused before its tenant is trusted) is null.
AUDIT_KEYS = ("tenant", "system", "investigation", "version", "method", "path", "outcome")

_APPEND = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC


class AuditSink(Protocol):
    """Where the proxy records each request; a record that cannot be written raises."""

    def record(self, entry: Mapping[str, Any]) -> None: ...


class FileAuditSink:
    """Appends each record to `path` as one JSON line, opened for append on every record (so a
    rotated file is followed by the next record) and written in one `write`. The path is used as
    the operator spells it. A file that cannot be opened for append fails at construction; a
    write that fails or falls short raises `OSError` from `record`."""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        os.close(os.open(self.path, _APPEND, 0o600))

    def __repr__(self) -> str:
        return f"{type(self).__name__}({str(self.path)!r})"

    def record(self, entry: Mapping[str, Any]) -> None:
        line = (json.dumps(dict(entry), sort_keys=True) + "\n").encode("utf-8")
        with self._lock:
            fd = os.open(self.path, _APPEND, 0o600)
            try:
                written = os.write(fd, line)
                if written != len(line):
                    raise OSError(f"the audit file {self.path} took {written} of {len(line)} "
                                  "bytes")
                if stat.S_ISREG(os.fstat(fd).st_mode):  # a device or pipe has nothing to sync
                    os.fsync(fd)
            finally:
                os.close(fd)


__all__ = ["AUDIT_KEYS", "AuditSink", "FileAuditSink"]
