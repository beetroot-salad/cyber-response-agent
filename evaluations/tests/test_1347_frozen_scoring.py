"""#1347 O6/P2, D4, D7, D8: scoring verifies each frozen case before it scores it."""
from __future__ import annotations

import hashlib
import io
import json
import uuid
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import yaml

from defender.records import RunPaths
from defender.tests.support.storage._alert_plant import plant_alert

GOOD, OTHER = "m05-lsass-access", "m07-cron-persistence"
FINGERPRINT = {"logs-system.auth-2026.10.20|2026-10-20T08": [1200, 1200]}
PART = "hosts/web-1.tar"
PART_BYTES = b"committed image of web-1"


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _case(root: Path, slug: str, disposition: str, *, parts: dict[str, str] | None = None) -> None:
    """A held-out fixture with a freeze file beside `ground_truth.yaml` (D8)."""
    member = root / slug
    member.mkdir(parents=True)
    (member / "alert.json").write_text("{}", encoding="utf-8")
    (member / "ground_truth.yaml").write_text(
        f"held_out: true\ndisposition: {disposition}\n", encoding="utf-8")
    freeze = {
        "moment": "2026-10-20T08:00:00Z",
        "window": ["2026-09-19T08:00:00Z", "2026-10-20T09:00:00Z"],
        "captured_at": "2026-10-20T09:03:17Z",
        "fingerprint": FINGERPRINT,
        "parts": parts if parts is not None else {},
        "status": "valid",
    }
    (member / "freeze.yaml").write_text(yaml.safe_dump(freeze), encoding="utf-8")


def _run(runs: Path, *, says: str, queries: list[dict] | None = None) -> str:
    run_dir = runs / str(uuid.uuid4())
    run_dir.mkdir(parents=True)
    plant_alert(run_dir)
    (run_dir / "report.md").write_text(
        f"---\ndisposition: {says}\noutcome: stands\n---\nbody\n", encoding="utf-8")
    rows = queries if queries is not None else [_esql('FROM logs-* | LIMIT 1')]
    RunPaths(run_dir).executed_queries.write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return run_dir.name


def _esql(query: str) -> dict:
    return {"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "esql",
            "query_id": "elastic.esql", "params": {"query": query}}


def _search(**params: Any) -> dict:
    return {"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "query",
            "query_id": "elastic.query", "params": params}


def _score(tmp_path: Path, runs: Path, fixtures: Path, rows: list[tuple[str, str]],
           recomputed: dict[str, Any], parts_dir: Path | None = None) -> tuple[int, str]:
    """`held_out.main` over an index of `rows`; `recomputed` is what the fingerprint recompute
    answers per slug (G2 seam). Returns (exit code, stdout + stderr)."""
    from evaluations import held_out

    index = tmp_path / "ops" / "held-out-index.jsonl"
    index.parent.mkdir(parents=True, exist_ok=True)
    index.write_text("".join(json.dumps({"slug": s, "run_id": r}) + "\n" for s, r in rows),
                     encoding="utf-8")
    argv = [str(runs), "--index", str(index), "--fixtures-dir", str(fixtures)]
    if parts_dir is not None:
        argv += ["--freeze-parts", str(parts_dir)]
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = held_out.main(argv, fingerprint=lambda slug, _freeze: recomputed[slug])
    return rc, f"{out.getvalue()}\n{err.getvalue()}"


def _verdicts(text: str) -> dict[str, str]:
    got = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("OK", "WRONG") and parts[1].endswith(":"):
            got[parts[1][:-1]] = parts[0]
    return got


def _listed_under(text: str, word: str) -> list[str]:
    """Slugs listed (first token) in the `## ...` section whose heading contains `word`."""
    lines, found, inside = text.splitlines(), [], False
    for line in lines:
        if line.startswith("#"):
            inside = word.lower() in line.lower()
            continue
        if inside and line.strip():
            found.append(line.split()[0].rstrip(":"))
    return found


def _two_cases(tmp_path: Path) -> tuple[Path, Path, str, str]:
    fixtures, runs = tmp_path / "held-out", tmp_path / "runs"
    _case(fixtures, GOOD, "benign")
    _case(fixtures, OTHER, "malicious")
    return fixtures, runs, _run(runs, says="benign"), _run(runs, says="malicious")


def test_a_case_whose_fingerprint_changed_is_stale_excluded_and_listed(tmp_path):
    """O6/P2: a recomputed fingerprint that differs from the freeze's marks the case stale;
    it leaves the accuracy and is listed."""
    fixtures, runs, good_run, other_run = _two_cases(tmp_path)
    changed = {"logs-system.auth-2026.10.20|2026-10-20T08": [1199, 1199]}

    _rc, said = _score(tmp_path, runs, fixtures, [(GOOD, good_run), (OTHER, other_run)],
                       {GOOD: FINGERPRINT, OTHER: changed})

    assert _verdicts(said) == {GOOD: "OK"}, said
    assert "Aggregate accuracy: 1/1" in said, said
    assert _listed_under(said, "stale") == [OTHER], said


def test_the_ship_gate_cannot_pass_while_any_case_is_stale(tmp_path):
    """D7: with a stale case the score reports the set incomplete and exits non-zero, rather than
    passing on the smaller denominator."""
    fixtures, runs, good_run, other_run = _two_cases(tmp_path)
    rows = [(GOOD, good_run), (OTHER, other_run)]

    clean_rc, clean = _score(tmp_path, runs, fixtures, rows,
                             {GOOD: FINGERPRINT, OTHER: FINGERPRINT})
    rc, said = _score(tmp_path, runs, fixtures, rows, {GOOD: FINGERPRINT, OTHER: {}})

    assert (clean_rc, "incomplete" in clean.lower()) == (0, False), clean
    assert rc != 0, said
    assert "incomplete" in said.lower(), said


def test_a_case_whose_freeze_part_is_missing_or_altered_is_refused_like_a_mismatch(tmp_path):
    """D8: a part named by digest that is absent or whose digest differs refuses the case
    (stale, excluded, listed); a case whose part matches is scored."""
    fixtures, runs, parts = tmp_path / "held-out", tmp_path / "runs", tmp_path / "parts"
    _case(fixtures, GOOD, "benign", parts={PART: _digest(PART_BYTES)})
    _case(fixtures, OTHER, "malicious", parts={PART: _digest(b"another image")})
    _case(fixtures, "m09-missing-part", "benign", parts={"hosts/db-1.tar": _digest(b"x")})
    (parts / GOOD / "hosts").mkdir(parents=True)
    (parts / GOOD / PART).write_bytes(PART_BYTES)
    (parts / OTHER / "hosts").mkdir(parents=True)
    (parts / OTHER / PART).write_bytes(PART_BYTES)
    rows = [(GOOD, _run(runs, says="benign")), (OTHER, _run(runs, says="malicious")),
            ("m09-missing-part", _run(runs, says="benign"))]

    rc, said = _score(tmp_path, runs, fixtures, rows,
                      {s: FINGERPRINT for s, _ in rows}, parts_dir=parts)

    assert _verdicts(said) == {GOOD: "OK"}, said
    assert sorted(_listed_under(said, "stale")) == sorted([OTHER, "m09-missing-part"]), said
    assert rc != 0, said


def test_a_run_that_reads_elasticsearchs_own_now_is_dropped_and_listed_for_rerun(tmp_path):
    """D4: a run whose recorded ES|QL uses `now(` (any case) is not scored; it is listed as
    needing a re-run, and the clean case beside it scores."""
    fixtures, runs = tmp_path / "held-out", tmp_path / "runs"
    _case(fixtures, GOOD, "benign")
    _case(fixtures, OTHER, "malicious")
    clean = _run(runs, says="benign")
    clock_read = _run(runs, says="malicious", queries=[
        _esql('FROM logs-* | WHERE @timestamp > now() - 1 hour | LIMIT 5')])

    _rc, said = _score(tmp_path, runs, fixtures, [(GOOD, clean), (OTHER, clock_read)],
                       {GOOD: FINGERPRINT, OTHER: FINGERPRINT})

    assert _verdicts(said) == {GOOD: "OK"}, said
    assert _listed_under(said, "re-run") == [OTHER], said


def test_three_consecutive_dropped_runs_make_the_case_unscorable(tmp_path):
    """D4: after three consecutive dropped runs of a slug (index rows, oldest first) the case is
    reported unscorable instead of asking for another re-run."""
    fixtures, runs = tmp_path / "held-out", tmp_path / "runs"
    _case(fixtures, GOOD, "benign")
    _case(fixtures, OTHER, "malicious")
    rows = [
        (OTHER, _run(runs, says="malicious", queries=[_esql("FROM logs-* | EVAL t = NOW()")])),
        (OTHER, _run(runs, says="malicious",
                     queries=[_search(native_query="user.name:root", start="now-1d")])),
        (OTHER, _run(runs, says="malicious",
                     queries=[_search(native_query="@timestamp:[now-1h TO *]")])),
        (GOOD, _run(runs, says="benign")),
    ]

    _rc, said = _score(tmp_path, runs, fixtures, rows, {GOOD: FINGERPRINT, OTHER: FINGERPRINT})

    assert _verdicts(said) == {GOOD: "OK"}, said
    assert _listed_under(said, "unscorable") == [OTHER], said
    assert OTHER not in _listed_under(said, "re-run"), said
