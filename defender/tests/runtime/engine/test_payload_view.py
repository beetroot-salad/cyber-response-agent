from __future__ import annotations

import json

import pytest

from defender.runtime import payload_view as pv

RUN = "gather_raw/l-001/0.json"


def _lucene(hits: list, *, total: int | None = None, key: str = "hits") -> str:
    """An elastic `query`/`alerts` envelope. `total > len(hits)` is the adapter's own cap."""
    returned = len(hits)
    return json.dumps({
        "index": "logs-*", "total": total if total is not None else returned,
        "returned": returned, "sort": "desc",
        "truncated": total is not None and total > returned, key: hits,
    })


def _docs(n: int, *, fields: int = 4) -> list[dict]:
    return [
        {f"f{j}": f"value-{i}-{j}" for j in range(fields)} | {"@timestamp": f"2026-08-07T11:{i:02d}:00Z"}
        for i in range(n)
    ]


def _view(text: str, *, ceiling: int, run_dir) -> str:
    return pv.render(text, RUN, run_dir, ceiling=ceiling)


# The gate: size, and nothing else.

def test_under_the_ceiling_the_payload_is_verbatim(tmp_path):
    """No prose, no samples, no reformatting — the bytes the adapter produced."""
    text = _lucene(_docs(2))
    assert _view(text, ceiling=65536, run_dir=tmp_path) == text


def test_the_key_name_decides_nothing_above_the_ceiling(tmp_path):
    """The load-bearing property."""
    hits = _docs(60)
    _, known = pv.walk(json.loads(_lucene(hits, key="hits")), 1200)
    _, exotic = pv.walk(json.loads(_lucene(hits, key="zzzz")), 1200)
    assert [(e.kind, e.kept, e.total) for e in known] == [(e.kind, e.kept, e.total) for e in exotic]
    assert known
    assert known[0].kind == "list"


# O1 — the view never asserts a limitation the payload in context does not have.

def test_a_complete_empty_envelope_carries_no_prohibition(tmp_path):
    """THE regression."""
    view = _view(_lucene([]), ceiling=65536, run_dir=tmp_path)
    assert "Do NOT count" not in view
    assert "not count" not in view.lower()
    assert "sample" not in view.lower()
    assert json.loads(view)["total"] == 0


# O3 — a view can never be mistaken for the payload.

def test_every_shortened_list_carries_a_marker_in_its_own_scope(tmp_path):
    """A silently-shortened array is valid JSON that parses clean and counts wrong. The marker
    lives INSIDE the array it describes, so a reader of that array cannot miss it."""
    view = _view(_lucene(_docs(60)), ceiling=1200, run_dir=tmp_path)
    body = json.loads(_json_block(view))
    assert isinstance(body["hits"][-1], str)
    assert body["hits"][-1].startswith(pv.ELISION_PREFIX)
    assert "60" in body["hits"][-1]


def test_the_marker_names_how_many_were_dropped(tmp_path):
    view = _view(_lucene(_docs(60)), ceiling=1200, run_dir=tmp_path)
    body = json.loads(_json_block(view))
    kept = len(body["hits"]) - 1
    assert f"{60 - kept} of 60" in body["hits"][-1]


# O5 — a kept element is a WHOLE element. Only long string leaves clip.

def test_kept_elements_keep_every_field(tmp_path):
    docs = _docs(60, fields=12)
    view = _view(_lucene(docs), ceiling=2000, run_dir=tmp_path)
    body = json.loads(_json_block(view))
    for element in body["hits"][:-1]:
        assert set(element) == set(docs[0]), "a kept element lost fields"


def test_a_long_string_clips_at_the_leaf_not_the_record(tmp_path):
    """Value shape and quirks are why samples beat a schema, so the element keeps all its keys;
    only the one bulky value is cut, and it says so where it was cut."""
    docs = [{"host": "web-1", "user": "svc", "message": "M" * 5000} for _ in range(4)]
    view = _view(_lucene(docs), ceiling=1500, run_dir=tmp_path)
    body = json.loads(_json_block(view))
    first = body["hits"][0]
    assert set(first) >= {"host", "user", "message"}
    assert first["host"] == "web-1"
    assert first["message"].endswith(">>")
    assert pv.ELISION_PREFIX in first["message"]


def test_a_payload_with_no_list_at_all_is_walked(tmp_path):
    text = json.dumps({"host": "web-1", "captured_at": "2026-08-07T00:00:00Z", "ps_output": "P" * 40000})
    view = _view(text, ceiling=2000, run_dir=tmp_path)
    body = json.loads(_json_block(view))
    assert body["host"] == "web-1"
    assert body["captured_at"] == "2026-08-07T00:00:00Z"
    assert pv.ELISION_PREFIX in body["ps_output"]


# N6 — no key is privileged. "The bulk" is a fact about bytes.

def test_a_small_sibling_list_survives_while_the_bulk_is_elided(tmp_path):
    payload = json.dumps({
        "query": "FROM logs-* | STATS c = COUNT(*) BY host",
        "columns": [{"name": "host", "type": "keyword"}, {"name": "c", "type": "long"}],
        "row_count": 400,
        "values": [{"host": f"h{i}", "c": i} for i in range(400)],
    })
    _, elisions = pv.walk(json.loads(payload), 1500)
    assert [e.path for e in elisions] == ["values"]


def test_the_bulk_is_whichever_list_is_big(tmp_path):
    payload = json.dumps({
        "query": "FROM logs-* | LIMIT 1",
        "columns": [{"name": f"field_number_{i}", "type": "keyword"} for i in range(1657)],
        "row_count": 1,
        "values": [{"field_number_0": "x"}],
    })
    _, elisions = pv.walk(json.loads(payload), 1500)
    assert [e.path for e in elisions] == ["columns"]


# O4 — server-side capping and view-side elision are two facts, never one.

def test_a_capped_envelope_states_the_servers_own_total(tmp_path):
    view = _view(_lucene(_docs(20), total=2471), ceiling=1200, run_dir=tmp_path)
    assert "2471" in view
    assert "EXACT" in view


# Bounds.

@pytest.mark.parametrize("ceiling", [400, 1200, 8192])
def test_the_view_respects_its_budget(tmp_path, ceiling):
    view = _view(_lucene(_docs(400, fields=10), total=99999), ceiling=ceiling, run_dir=tmp_path)
    assert len(_json_block(view)) <= ceiling


@pytest.mark.parametrize("ceiling", [400, 1200, 8192])
@pytest.mark.parametrize(
    "filler", ["x", "\n", '"', "café", "日本語"], ids=["ascii", "newline", "quote", "latin1", "cjk"]
)
def test_a_bounded_body_still_PARSES(tmp_path, ceiling, filler):
    """Fitting the budget is half the demand; the other half is that what fits can be read."""
    docs = [
        {"@timestamp": f"2026-08-07T11:{i % 60:02d}:00Z", "host": f"web-{i}", "message": filler * 40}
        for i in range(400)
    ]
    body = _json_block(_view(_lucene(docs, total=99999), ceiling=ceiling, run_dir=tmp_path))
    assert len(body) <= ceiling
    json.loads(body)  # raises if the view arrived cut mid-token


def test_an_oversized_payload_with_no_bulk_node_is_still_bounded(tmp_path):
    """A wide flat object of short scalars has no list and no long string to cut. It must still
    not blow the budget — the walk falls back to a marked hard cut rather than passing it."""
    text = json.dumps({f"field_number_{i}": i for i in range(4000)})
    view = _view(text, ceiling=2000, run_dir=tmp_path)
    assert len(view) < len(text)
    assert pv.ELISION_PREFIX in view


def test_wide_fields_are_cut_even_when_the_payload_also_carries_a_bulk_node(tmp_path):
    payload = {f"field_number_{i}": f"v{i}" for i in range(4000)} | {"note": "N" * 3000}
    body = _json_block(_view(json.dumps(payload), ceiling=2000, run_dir=tmp_path))
    assert len(body) <= 2000
    assert pv.ELISION_PREFIX in body
    json.loads(body)


def test_a_string_leaf_of_escaped_characters_stays_inside_the_budget(tmp_path):
    """`host-state proc-tree` returns its `ps` forest as ONE string, and a process forest is
    newlines. Clipped by character count against a byte share it serialized to twice its room."""
    text = json.dumps({"host": "web-1", "ps_output": "root 1 /sbin/init\n" * 3000})
    body = _json_block(_view(text, ceiling=2000, run_dir=tmp_path))
    assert len(body) <= 2000
    assert json.loads(body)["host"] == "web-1"
    assert pv.ELISION_PREFIX in json.loads(body)["ps_output"]


def test_a_mixed_offset_timestamp_batch_does_not_crash_the_view(tmp_path):
    """`sort` comparing a NAIVE `fromisoformat` result with an AWARE one raises `TypeError` —"""
    docs = [
        {"@timestamp": "2026-08-07T11:00:00Z", "m": "x" * 300},
        {"@timestamp": "2026-08-07T10:00:00", "m": "y" * 300},
    ] * 40
    view = _view(_lucene(docs, total=9999), ceiling=1200, run_dir=tmp_path)
    assert "2026-08-07T10:00:00 … 2026-08-07T11:00:00Z" in view


def test_a_non_json_payload_is_bounded_and_marked(tmp_path):
    view = _view("x" * 50000, ceiling=2000, run_dir=tmp_path)
    assert len(view) < 50000
    assert pv.ELISION_PREFIX in view


def test_the_disk_path_is_offered_when_the_view_elides(tmp_path):
    view = _view(_lucene(_docs(60)), ceiling=1200, run_dir=tmp_path)
    assert str(tmp_path / RUN) in view
    assert "defender-sql" in view


def test_the_full_payload_footer_offers_a_reduction_correct_for_any_shape(tmp_path):
    """#1138 O8: the `full payload` arm's example reduction must be right on every payload shape."""
    view = _view(_lucene(_docs(60)), ceiling=1200, run_dir=tmp_path)
    assert f"full payload: {tmp_path / RUN}" in view, "premise: this view is the full-payload arm"
    footer = view.partition(f"full payload: {tmp_path / RUN}")[2]
    assert "defender-sql" in footer, footer
    assert "DESCRIBE data" in footer, footer
    assert "count(*)" not in view, "the full-payload footer offers a whole-payload count"


def test_a_server_capped_payload_is_never_offered_a_count_over_its_own_file(tmp_path):
    """The file on disk holds the SERVER'S SLICE."""
    view = _view(_lucene(_docs(20), total=2471), ceiling=1200, run_dir=tmp_path)
    assert "NEVER count the returned docs" in view
    assert "count(*)" not in view
    assert str(tmp_path / RUN) in view


# #877 F-10 — the envelope may not derive a fact from itself.

def _esql_rows(n: int) -> list[list]:
    return [[f"host-{i:04d}", i] for i in range(n)]


def test_an_esql_payload_at_the_row_cap_is_never_called_complete(tmp_path):
    """THE regression, driven through the REAL adapter shape rather than a hand-built dict."""
    from defender.scripts.adapters.elastic_adapter import esql_payload

    payload = esql_payload("FROM logs-* | STATS c = COUNT(*) BY host", {
        "columns": [{"name": "host", "type": "keyword"}, {"name": "c", "type": "long"}],
        "values": _esql_rows(1000),
    })
    assert payload["row_count"] == 1000, "the adapter shape changed under the test"
    assert pv.completeness(payload).state != "complete"

    view = _view(json.dumps(payload), ceiling=8192, run_dir=tmp_path)
    assert "nothing was capped upstream" not in view
    assert "counts are exact" not in view


def test_an_unknown_envelope_is_not_offered_as_a_full_payload_to_count(tmp_path):
    """THE SAME CLAIM, ONE LINE FURTHER DOWN."""
    from defender.scripts.adapters.elastic_adapter import esql_payload

    payload = esql_payload("FROM logs-* | STATS c = COUNT(*) BY host", {
        "columns": [{"name": "host", "type": "keyword"}, {"name": "c", "type": "long"}],
        "values": _esql_rows(1000),
    })
    assert pv.completeness(payload).state == "unknown", "the fixture stopped exercising it"
    view = _view(json.dumps(payload), ceiling=8192, run_dir=tmp_path)

    assert "full payload" not in view, "an envelope declaring nothing was called complete"
    assert "count(*)" not in view, "a count over an unknown slice was offered as the answer"
    assert "payload on disk" in view, "the file the lead must read was not named at all"


def test_a_row_count_above_the_rows_present_is_still_a_cap(tmp_path):
    text = json.dumps({
        "query": "FROM logs-* | LIMIT 400", "columns": [{"name": "host", "type": "keyword"}],
        "row_count": 400, "values": _esql_rows(20),
    })
    assert pv.completeness(json.loads(text)) == pv.Completeness("capped", 400, 20)
    view = _view(text, ceiling=1200, run_dir=tmp_path)
    assert "400" in view
    assert "count(*)" not in view, "a capped payload was offered a count over its own slice"


def _json_block(view: str) -> str:
    """The payload region of a rendered view — everything after the `[record_query]` prose."""
    lines = [ln for ln in view.splitlines() if not ln.startswith(("[record_query]", "→", "  "))]
    return "\n".join(lines).strip()


def test_a_list_never_collapses_to_a_bare_marker(tmp_path):
    """Found against the LIVE stack, not in a fixture."""
    fat = [{f"field_{j}": f"value-{i}-{j}-{'x' * 40}" for j in range(60)} for i in range(20)]
    view = _view(_lucene(fat, total=37442), ceiling=8192, run_dir=tmp_path)
    body = json.loads(_json_block(view))
    first = body["hits"][0]
    assert isinstance(first, dict), "the list rendered as a bare marker — no field shape at all"
    assert len(first) >= 20, f"only {len(first)} fields survived the squeeze"
    assert body["hits"][-1].startswith(pv.ELISION_PREFIX)
    assert len(_json_block(view)) <= 8192


def test_the_squeeze_keeps_field_shape_before_value_shape(tmp_path):
    one = [{f"f{j}": "2026-05-25T15:27:22.928Z" for j in range(80)}]
    view = _view(_lucene(one), ceiling=2000, run_dir=tmp_path)
    body = json.loads(_json_block(view))
    first = body["hits"][0]
    assert isinstance(first, dict)
    assert len(first) >= 40, "fields were dropped while values were still clippable"
    assert any(v.startswith("2026") for v in first.values() if isinstance(v, str))


# A positional ROW degrades like a record does (#834).

def _esql(rows: list[list], names: list[str]) -> str:
    """The ES|QL envelope as the adapter now stores it: names once, rows as bare arrays."""
    return json.dumps({
        "query": "FROM logs-* | STATS ...",
        "columns": [{"name": n, "type": "keyword"} for n in names],
        "row_count": len(rows), "values": rows,
    })


def test_a_too_wide_row_keeps_cells_the_way_a_too_wide_record_keeps_fields(tmp_path):
    """The sibling of `test_a_list_never_collapses_to_a_bare_marker`, for the other element shape — and the regression #834 would have shipped without it."""
    names = [f"col_{j}" for j in range(1657)]
    row = [f"value-{j}-{'x' * 20}" for j in range(1657)]
    view = _view(_esql([row], names), ceiling=8192, run_dir=tmp_path)
    body = json.loads(_json_block(view))

    first = body["values"][0]
    assert isinstance(first, list), "the row rendered as a bare marker — no cell survived"
    assert len(first) > 1, f"only {len(first)} cells survived the squeeze"
    assert first[-1].startswith(pv.ELISION_PREFIX), "a cut row must say it was cut"
    assert len(_json_block(view)) <= 8192


def test_a_named_cell_is_bound_to_the_RIGHT_name(tmp_path):
    """The misattribution guarantee, which is what a positional encoding has to earn."""
    names = [f"col_{j}" for j in range(1657)]
    row = [f"value-{j}-{'x' * 20}" for j in range(1657)]
    body = json.loads(_json_block(_view(_esql([row], names), ceiling=8192, run_dir=tmp_path)))

    def _real(seq):
        return [x for x in seq if not (isinstance(x, str) and x.startswith(pv.ELISION_PREFIX))]

    kept_cells, kept_names = _real(body["values"][0]), _real(body["columns"])
    assert kept_cells == row[:len(kept_cells)], "cells are not the leading prefix"
    assert [c["name"] for c in kept_names] == names[:len(kept_names)], "columns are not the prefix"

    bindable = min(len(kept_cells), len(kept_names))
    assert bindable > 1, "nothing at all is bindable — the row carries no readable schema"
    for i in range(bindable):
        assert kept_cells[i] == f"value-{i}-{'x' * 20}", f"cell {i} does not belong to col_{i}"


def test_a_cut_row_never_reorders_the_cells_it_keeps(tmp_path):
    names = [f"col_{j}" for j in range(400)]
    row = [f"cell-{j:03d}" for j in range(400)]
    body = json.loads(_json_block(_view(_esql([row], names), ceiling=4096, run_dir=tmp_path)))

    kept = [c for c in body["values"][0] if not c.startswith(pv.ELISION_PREFIX)]
    assert kept == row[:len(kept)], "kept cells are not the leading prefix of the row"


def test_the_elision_marker_for_a_row_counts_cells_not_elements(tmp_path):
    names = [f"col_{j}" for j in range(400)]
    view = _view(_esql([[f"c{j}" for j in range(400)]], names), ceiling=4096, run_dir=tmp_path)
    marker = json.loads(_json_block(view))["values"][0][-1]
    assert "cells" in marker, f"row marker does not name cells: {marker!r}"
    assert marker.startswith(pv.ELISION_PREFIX)


def test_a_list_whose_ONE_element_was_salvaged_is_not_marked_as_shortened():
    """A marker means a real cut, or it means nothing."""
    names = [f"col_{j}" for j in range(1657)]
    row = [f"value-{j}-{'x' * 20}" for j in range(1657)]
    obj = json.loads(_esql([row], names))
    walked, elisions = pv.walk(obj, 8192)

    assert len(walked["values"]) == 1, "a list that kept its only element grew a marker"
    assert not any(e.path == "values" for e in elisions), (
        f"the row count was reported as elided: {[e for e in elisions if e.path == 'values']}"
    )
    assert any(e.path == "values[0]" and e.kind == "cells" for e in elisions), (
        "the cut that DID happen — inside the row — went unrecorded"
    )
