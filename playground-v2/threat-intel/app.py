"""Threat-intel stub — VT/OTX-shaped reputation lookups, offline.

Seed is a flat list of Indicator records loaded at startup, indexed by `value`.
`/lookup/{value}` never 404s: unknowns synthesize an `unknown` record, matching
real VT/OTX semantics so callers can treat the lookup as a pure function.

Not for production. Auth-less; loopback-exposed on the VPS.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal, Optional

from fastapi import FastAPI
from pydantic import BaseModel, Field

SEED_PATH = Path(os.environ.get("TI_SEED_PATH", "/app/seed/indicators.json"))

IndicatorType = Literal["ipv4", "domain", "url", "sha256", "md5"]
Verdict = Literal["malicious", "suspicious", "clean", "unknown"]


class Indicator(BaseModel):
    value: str
    type: IndicatorType
    verdict: Verdict
    score: int = 0
    sources: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


INDICATORS: dict[str, Indicator] = {}


def _guess_type(value: str) -> IndicatorType:
    if len(value) == 64 and all(c in "0123456789abcdefABCDEF" for c in value):
        return "sha256"
    if len(value) == 32 and all(c in "0123456789abcdefABCDEF" for c in value):
        return "md5"
    if value.count(".") == 3 and all(p.isdigit() for p in value.split(".")):
        return "ipv4"
    if "://" in value:
        return "url"
    return "domain"


def _load_seed() -> int:
    INDICATORS.clear()
    if not SEED_PATH.exists():
        return 0
    raw = json.loads(SEED_PATH.read_text())
    for row in raw:
        ind = Indicator(**row)
        INDICATORS[ind.value] = ind
    return len(INDICATORS)


def _lookup(value: str) -> Indicator:
    hit = INDICATORS.get(value)
    if hit is not None:
        return hit
    return Indicator(value=value, type=_guess_type(value), verdict="unknown", score=0)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    _load_seed()
    yield


app = FastAPI(title="Playground threat-intel stub", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok", "indicator_count": len(INDICATORS)}


@app.get("/lookup/{value:path}")
def lookup(value: str):
    return _lookup(value)


class BulkLookup(BaseModel):
    values: list[str]


@app.post("/lookup")
def bulk_lookup(body: BulkLookup):
    return {"results": [_lookup(v) for v in body.values]}


@app.get("/indicators")
def list_indicators(
    verdict: Optional[Verdict] = None,
    type: Optional[IndicatorType] = None,
    tag: Optional[str] = None,
):
    out = list(INDICATORS.values())
    if verdict:
        out = [i for i in out if i.verdict == verdict]
    if type:
        out = [i for i in out if i.type == type]
    if tag:
        out = [i for i in out if tag in i.tags]
    return {"total": len(out), "indicators": out}


@app.post("/admin/reset")
def reset():
    count = _load_seed()
    return {"status": "reset", "indicator_count": count}
