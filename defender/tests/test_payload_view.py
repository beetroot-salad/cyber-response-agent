"""The payload view (#832) — what a query result looks like by the time a lead reads it.

The view used to be decided by `_RECORD_KEYS`, a tuple of six vendor envelope key names
(`hits`/`results`/`events`/`records`/`data`/`rows`). Measured over 894 recorded payloads only
`hits` ever matched: defender's own adapters name each list after its contents (`values`,
`entries`, `packages`, `users`, `hosts`, `changes`, `tickets`, `indicators`, `keys`), a naming
rule with open range that no whitelist can track. So a 105-byte complete Lucene result was cut to
three docs and stamped "Do NOT count these", while a 19 KB package list went into context whole —
and neither was chosen.

These tests pin the properties that replaced it, and they are written so that the old design
CANNOT pass them:

  - key names decide nothing (`test_the_key_name_decides_nothing_*`)
  - a payload shown in full is never told it is a sample (`test_a_complete_*`)
  - a shortened list always says so, in its own scope (`test_every_shortened_list_*`)
  - a kept element is a WHOLE element; only long string leaves clip (`test_kept_elements_*`)
  - which list is "the bulk" is a fact about bytes, not about a key (`test_the_bulk_is_*`)
"""
from __future__ import annotations

import json

import pytest

from defender.scripts.gather_tools import payload_view as pv

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


# --------------------------------------------------------------------------------------- #
# The gate: size, and nothing else.
# --------------------------------------------------------------------------------------- #

def test_under_the_ceiling_the_payload_is_verbatim(tmp_path):
    """No prose, no samples, no reformatting — the bytes the adapter produced.

    94% of the recorded corpus lands here. The old code replaced a 105-byte complete result
    with a sampling notice; the payload is small enough to reason from directly and the view's
    only honest job is to get out of the way."""
    text = _lucene(_docs(2))
    assert _view(text, ceiling=65536, run_dir=tmp_path) == text


def test_the_key_name_decides_nothing_under_the_ceiling(tmp_path):
    hits = _docs(2)
    named = _view(_lucene(hits, key="hits"), ceiling=65536, run_dir=tmp_path)
    unnamed = _view(_lucene(hits, key="zzz_widgets"), ceiling=65536, run_dir=tmp_path)
    assert named == _lucene(hits, key="hits")
    assert unnamed == _lucene(hits, key="zzz_widgets")


def test_the_key_name_decides_nothing_above_the_ceiling(tmp_path):
    """The load-bearing property. Rename the list and the decision, the kept counts and the
    elision records are identical — which is exactly what `_is_event_payload` could not do.

    Equal-length names on purpose: the claim is that the name is never CONSULTED, not that it
    occupies no bytes. A longer key really does leave less budget for elements, and pretending
    otherwise would make this test assert something false about the arithmetic."""
    hits = _docs(60)
    _, known = pv.walk(json.loads(_lucene(hits, key="hits")), 1200)
    _, exotic = pv.walk(json.loads(_lucene(hits, key="zzzz")), 1200)
    assert [(e.kind, e.kept, e.total) for e in known] == [(e.kind, e.kept, e.total) for e in exotic]
    assert known
    assert known[0].kind == "list"


@pytest.mark.parametrize("key", ["hits", "values", "entries", "packages", "users", "zzz"])
def test_every_list_key_is_treated_alike(tmp_path, key):
    payload = json.dumps({"captured_at": "2026-08-07T00:00:00Z", key: _docs(60)})
    _, elisions = pv.walk(json.loads(payload), 1200)
    assert [e.path for e in elisions] == [key]


# --------------------------------------------------------------------------------------- #
# O1 — the view never asserts a limitation the payload in context does not have.
# --------------------------------------------------------------------------------------- #

def test_a_complete_empty_envelope_carries_no_prohibition(tmp_path):
    """THE regression. `{total: 0, truncated: false, hits: []}` is 94 bytes, complete, and
    entirely visible; the old view answered it with "0 records ... Do NOT count these or read
    values off them", i.e. forbade the lead from stating the one exact fact the payload holds.
    #809 is gather reporting a zero it cannot stand behind — this is the tool manufacturing it."""
    view = _view(_lucene([]), ceiling=65536, run_dir=tmp_path)
    assert "Do NOT count" not in view
    assert "not count" not in view.lower()
    assert "sample" not in view.lower()
    assert json.loads(view)["total"] == 0


def test_a_complete_payload_shown_in_full_is_never_called_a_sample(tmp_path):
    for n in (1, 3, 20):
        view = _view(_lucene(_docs(n)), ceiling=65536, run_dir=tmp_path)
        assert "sample" not in view.lower(), f"{n} complete records described as a sample"
        assert len(json.loads(view)["hits"]) == n


# --------------------------------------------------------------------------------------- #
# O3 — a view can never be mistaken for the payload.
# --------------------------------------------------------------------------------------- #

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


def test_nothing_is_marked_when_nothing_was_dropped(tmp_path):
    view = _view(_lucene(_docs(2)), ceiling=65536, run_dir=tmp_path)
    assert pv.ELISION_PREFIX not in view


# --------------------------------------------------------------------------------------- #
# O5 — a kept element is a WHOLE element. Only long string leaves clip.
# --------------------------------------------------------------------------------------- #

def test_kept_elements_keep_every_field(tmp_path):
    """`_SAMPLE_MAX_CHARS` used to clip `json.dumps(record)`, so 80 of 80 real elastic sample
    records arrived as mid-token prefixes with their trailing fields gone — a "FIELD-SHAPE
    sample" that dropped part of the field shape."""
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
    """`host-state proc-tree` returns its whole `ps` forest as one string under `ps_output`. With
    no list anywhere the old code fell to a blunt 1,800-char cut of the raw JSON — no record
    count, no field shape, the worst view in the module, reached by accident."""
    text = json.dumps({"host": "web-1", "captured_at": "2026-08-07T00:00:00Z", "ps_output": "P" * 40000})
    view = _view(text, ceiling=2000, run_dir=tmp_path)
    body = json.loads(_json_block(view))
    assert body["host"] == "web-1"
    assert body["captured_at"] == "2026-08-07T00:00:00Z"
    assert pv.ELISION_PREFIX in body["ps_output"]


# --------------------------------------------------------------------------------------- #
# N6 — no key is privileged. "The bulk" is a fact about bytes.
# --------------------------------------------------------------------------------------- #

def test_a_small_sibling_list_survives_while_the_bulk_is_elided(tmp_path):
    """ES|QL returns `columns` (the schema) beside `values` (the rows). Cutting `columns` to
    three would leave the kept rows uninterpretable — but no rule says "never cut columns",
    because the next test needs the opposite. The byte budget settles both."""
    payload = json.dumps({
        "query": "FROM logs-* | STATS c = COUNT(*) BY host",
        "columns": [{"name": "host", "type": "keyword"}, {"name": "c", "type": "long"}],
        "row_count": 400,
        "values": [{"host": f"h{i}", "c": i} for i in range(400)],
    })
    _, elisions = pv.walk(json.loads(payload), 1500)
    assert [e.path for e in elisions] == ["values"]


def test_the_bulk_is_whichever_list_is_big(tmp_path):
    """The inverse occurs in the corpus: 6 over-ceiling ES|QL payloads are `row_count: 1` with
    75-1,657 columns — a lead probing schema by pulling one wide row. There `columns` IS the
    bulk and `values` is trivial. A per-key rule cannot be right for both; a budget is."""
    payload = json.dumps({
        "query": "FROM logs-* | LIMIT 1",
        "columns": [{"name": f"field_number_{i}", "type": "keyword"} for i in range(1657)],
        "row_count": 1,
        "values": [{"field_number_0": "x"}],
    })
    _, elisions = pv.walk(json.loads(payload), 1500)
    assert [e.path for e in elisions] == ["columns"]


# --------------------------------------------------------------------------------------- #
# O4 — server-side capping and view-side elision are two facts, never one.
# --------------------------------------------------------------------------------------- #

def test_a_capped_envelope_states_the_servers_own_total(tmp_path):
    view = _view(_lucene(_docs(20), total=2471), ceiling=1200, run_dir=tmp_path)
    assert "2471" in view
    assert "EXACT" in view


def test_capped_and_complete_do_not_borrow_each_others_wording(tmp_path):
    capped = _view(_lucene(_docs(20), total=2471), ceiling=1200, run_dir=tmp_path)
    complete = _view(_lucene(_docs(60)), ceiling=1200, run_dir=tmp_path)
    assert "2471" in capped
    assert "EXACT" in capped
    assert "EXACT" not in complete, "a complete payload was described as a capped one"
    assert "total matches" not in complete


def test_view_side_elision_is_not_reported_as_a_server_cap(tmp_path):
    """A complete payload the VIEW shortened must not read as one the SERVER truncated: the
    rows exist, they are on disk, and `total` is still exact."""
    view = _view(_lucene(_docs(60)), ceiling=1200, run_dir=tmp_path)
    assert pv.ELISION_PREFIX in view
    assert "no `limit` reaches them" not in view


def test_the_span_line_survives_for_a_capped_envelope(tmp_path):
    """#830: a capped payload is ONE slice and the envelope never says which. Computed over the
    full returned list the walk holds, not over the elements that survived the budget."""
    view = _view(_lucene(_docs(20), total=142), ceiling=1200, run_dir=tmp_path)
    assert "2026-08-07T11:00:00Z" in view
    assert "2026-08-07T11:19:00Z" in view


# --------------------------------------------------------------------------------------- #
# Bounds.
# --------------------------------------------------------------------------------------- #

@pytest.mark.parametrize("ceiling", [400, 1200, 8192])
def test_the_view_respects_its_budget(tmp_path, ceiling):
    view = _view(_lucene(_docs(400, fields=10), total=99999), ceiling=ceiling, run_dir=tmp_path)
    assert len(_json_block(view)) <= ceiling


@pytest.mark.parametrize("ceiling", [400, 1200, 8192])
@pytest.mark.parametrize(
    "filler", ["x", "\n", '"', "café", "日本語"], ids=["ascii", "newline", "quote", "latin1", "cjk"]
)
def test_a_bounded_body_still_PARSES(tmp_path, ceiling, filler):
    """Fitting the budget is half the demand; the other half is that what fits can be read.

    The budget test above measured only LENGTH, and that is how two rulers-in-one-module shipped:
    the per-element cost counted a 1-byte `,` while `_dumps` wrote `", "`, and the string clipper
    counted CHARACTERS against a share denominated in serialized BYTES (`json.dumps` spends 2 on
    a newline, 6 on a non-ASCII codepoint). Both overshot, `render`'s floor then cut the
    serialized document at an arbitrary byte, and the view arrived as a mid-token prefix that
    `json.loads` rejects — the exact failure this module indicts `_SAMPLE_MAX_CHARS` for. Parsing
    is the property; length alone cannot see it."""
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
    """`_fit_fields` was reachable only when there was NO bulk node at all, so a wide flat object
    that happened to carry one long string kept all 4,000 of its fields and blew the budget by
    70 KB. The scalars are what overflows here; the walk has to say so."""
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
    """`sort` comparing a NAIVE `fromisoformat` result with an AWARE one raises `TypeError` —
    out of `render`, out of the `query` tool, and the lead loses the payload entirely. The
    fallback `timestamp` key this walks is exactly where a bespoke adapter omits the offset,
    so one such doc beside one elastic `...Z` doc was enough. `_clock.parse_iso_utc` reads a
    naive value AS UTC for this reason and its own docstring names this caller's failure."""
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


def test_a_server_capped_payload_is_never_offered_a_count_over_its_own_file(tmp_path):
    """The file on disk holds the SERVER'S SLICE. `SELECT count(*)` over it returns the cap —
    the number the same view's prose says never to count — so the footer must not advertise it.
    The old `sampled` footer withheld the example for exactly this reason; the rewrite made the
    footer unconditional and put the contradiction two lines apart."""
    view = _view(_lucene(_docs(20), total=2471), ceiling=1200, run_dir=tmp_path)
    assert "NEVER count the returned docs" in view
    assert "count(*)" not in view
    assert str(tmp_path / RUN) in view


def test_a_bare_truncated_flag_still_reports_the_server_cap(tmp_path):
    """`truncated: true` with no `total`/`returned` IS a server cap. It failed the prose branch's
    counts guard and fell through to a bare byte count, so the one fact the server declared went
    unsaid — and the elision line then told the lead the missing rows were "present in full on
    disk", which is false: the server never sent them."""
    text = json.dumps({"index": "logs-*", "truncated": True, "entries": _docs(200)})
    view = _view(text, ceiling=1200, run_dir=tmp_path)
    assert "The SERVER capped this result" in view
    assert "NEVER count these docs" in view
    assert "count(*)" not in view


def _json_block(view: str) -> str:
    """The payload region of a rendered view — everything after the `[record_query]` prose."""
    lines = [ln for ln in view.splitlines() if not ln.startswith(("[record_query]", "→", "  "))]
    return "\n".join(lines).strip()


def test_the_byte_ruler_holds_because_the_serializer_escapes():
    """The module compares BYTES but measures with `len()`, which counts codepoints. They agree
    only because `_dumps` leaves `ensure_ascii` on, so everything measured is pure ASCII.

    Pinned because the coupling is invisible at every use site and #834's compact encoding is
    exactly the change that would reach for `ensure_ascii=False`. Without it a CJK payload
    measures a third of its weight and rides through the ceiling whole.
    """
    for value in ({"m": "日本語 café"}, {"m": "M" * 100}, {"m": "\n\"\\ x"}):
        serialized = pv._dumps(value)
        assert len(serialized) == len(serialized.encode("utf-8")), (
            "ensure_ascii went off — len() is no longer the byte count this module compares"
        )


def test_a_list_never_collapses_to_a_bare_marker(tmp_path):
    """Found against the LIVE stack, not in a fixture.

    A real security alert document serializes to 8,568 bytes — larger than the whole 8,192-byte
    ceiling — so no element fit its share and a 163 KB `alerts` payload rendered as
    `hits: ["<<ELIDED 20 of 20 elements>>"]`. Honest and useless: not one field name survived,
    on exactly the payload a lead most needs field shape from to narrow its next query. The old
    sampler was wrong about completeness but did show three documents, so on the biggest
    documents the honest rewrite had regressed the one thing elements are shown for.
    """
    fat = [{f"field_{j}": f"value-{i}-{j}-{'x' * 40}" for j in range(60)} for i in range(20)]
    view = _view(_lucene(fat, total=37442), ceiling=8192, run_dir=tmp_path)
    body = json.loads(_json_block(view))
    first = body["hits"][0]
    assert isinstance(first, dict), "the list rendered as a bare marker — no field shape at all"
    assert len(first) >= 20, f"only {len(first)} fields survived the squeeze"
    assert body["hits"][-1].startswith(pv.ELISION_PREFIX)
    assert len(_json_block(view)) <= 8192


def test_the_squeeze_keeps_field_shape_before_value_shape(tmp_path):
    """Values clip progressively (`_SQUEEZE_CAPS`) before any FIELD is dropped: a 12-character
    value still tells the lead the field is an ISO stamp and not a count, which is the whole
    reason elements are shown instead of a key list."""
    one = [{f"f{j}": "2026-05-25T15:27:22.928Z" for j in range(80)}]
    view = _view(_lucene(one), ceiling=2000, run_dir=tmp_path)
    body = json.loads(_json_block(view))
    first = body["hits"][0]
    assert isinstance(first, dict)
    assert len(first) >= 40, "fields were dropped while values were still clippable"
    assert any(v.startswith("2026") for v in first.values() if isinstance(v, str))
