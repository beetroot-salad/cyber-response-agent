"""Append-only run records with a hash-linked manifest."""

from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel


class JournalError(RuntimeError):
    pass


def _jsonable(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        _jsonable(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]+", "-", value).strip("-.")
    return cleaned[:96] or "record"


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


class RunJournal:
    """Writes each stage record once and maintains a tamper-evident event chain."""

    def __init__(self, root: Path, manifest: dict[str, Any]):
        self.root = root
        self.manifest = manifest

    @classmethod
    def create(cls, runs_dir: Path, title: str) -> RunJournal:
        runs_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        run_id = f"{stamp}-{_safe_name(title).lower()}-{uuid4().hex[:8]}"
        root = runs_dir / run_id
        root.mkdir(parents=False, exist_ok=False)
        manifest = {
            "schema_version": 1,
            "run_id": run_id,
            "created_at": _utc_now(),
            "status": "running",
            "events": [],
        }
        journal = cls(root, manifest)
        journal._write_manifest()
        return journal

    @classmethod
    def open(cls, root: Path) -> RunJournal:
        manifest_path = root / "manifest.json"
        if not manifest_path.is_file():
            raise JournalError(f"No manifest found at {manifest_path}")
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        return cls(root, manifest)

    @property
    def run_id(self) -> str:
        return str(self.manifest["run_id"])

    def write_record(
        self,
        stage: str,
        name: str,
        value: Any,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> Path:
        relative = Path(_safe_name(stage)) / f"{_safe_name(name)}.json"
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            raise JournalError(f"Refusing to overwrite immutable record {target}")

        payload = _jsonable(value)
        pretty = (
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        )
        with target.open("x", encoding="utf-8") as handle:
            handle.write(pretty)

        event = {
            "index": len(self.manifest["events"]),
            "timestamp": _utc_now(),
            "stage": stage,
            "name": name,
            "path": relative.as_posix(),
            "record_sha256": hashlib.sha256(pretty.encode("utf-8")).hexdigest(),
            "previous_event_hash": (
                self.manifest["events"][-1]["event_hash"]
                if self.manifest["events"]
                else None
            ),
            "metadata": _jsonable(metadata or {}),
        }
        event["event_hash"] = digest(event)
        self.manifest["events"].append(event)
        self._write_manifest()
        return target

    def finish(self, status: str = "completed") -> None:
        self.manifest["status"] = status
        self.manifest["finished_at"] = _utc_now()
        self._write_manifest()

    def verify(self) -> list[str]:
        errors: list[str] = []
        previous: str | None = None
        for expected_index, event in enumerate(self.manifest.get("events", [])):
            if event.get("index") != expected_index:
                errors.append(f"event {expected_index}: index mismatch")
            if event.get("previous_event_hash") != previous:
                errors.append(f"event {expected_index}: previous hash mismatch")

            event_without_hash = {
                key: value for key, value in event.items() if key != "event_hash"
            }
            expected_event_hash = digest(event_without_hash)
            if event.get("event_hash") != expected_event_hash:
                errors.append(f"event {expected_index}: event hash mismatch")

            record = self.root / event["path"]
            if not record.is_file():
                errors.append(f"event {expected_index}: missing record {event['path']}")
            else:
                actual = hashlib.sha256(record.read_bytes()).hexdigest()
                if actual != event.get("record_sha256"):
                    errors.append(f"event {expected_index}: record hash mismatch")
            previous = event.get("event_hash")
        return errors

    def summary(self) -> dict[str, Any]:
        errors = self.verify()
        return {
            "run_id": self.run_id,
            "status": self.manifest.get("status"),
            "created_at": self.manifest.get("created_at"),
            "finished_at": self.manifest.get("finished_at"),
            "record_count": len(self.manifest.get("events", [])),
            "chain_valid": not errors,
            "errors": errors,
            "root": str(self.root.resolve()),
        }

    def _write_manifest(self) -> None:
        target = self.root / "manifest.json"
        temporary = self.root / f".manifest-{uuid4().hex}.tmp"
        temporary.write_text(
            json.dumps(self.manifest, indent=2, sort_keys=True, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, target)
