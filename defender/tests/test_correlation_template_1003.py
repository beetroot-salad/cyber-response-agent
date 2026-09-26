"""#1003 — the correlation lead's template is a per-deployment id the table must agree with.

THE DEFECT. #999 moved the lead's GRANT into `knowledge/environment/verb-grants.yaml` and left
everything the lead does at that target in Python: the template it binds
(`CORRELATION_TEMPLATE`, a literal naming one vendor), and a contract arguing in one vendor's
field namespace. So a table that moves the holder — the report's `splunk.search` rows, or the
same-vendor `elastic.alerts` -> `elastic.query` narrowing — loads clean, derives that system,
and dispatches a lead told to bind an id its own grant-filtered index cannot list. Eight
requests are spent discovering nothing is runnable; nothing raises, nothing warns.

THE SHAPE (settled on the issue). The unit of configuration is the TEMPLATE ID, read from a
one-key per-deployment file (`lead-zero.yaml`), because the template's front matter already
carries the system and the verb. The table's authority over the lead shrinks to grant-or-
withhold, and it must AGREE with the template: at run start, before any model exists, the id
is resolved against the deployment's own catalog and its `(system, verb)` compared with the
holder's one query pair. A withholding still degrades (the id is not consulted); an
unresolvable, malformed or disagreeing id REFUSES the run, naming both sides. The authored
contract keeps the neutral frame and hands the vendor facts to the template's own prose.

ONE RESOLVER. The check is composed of the lead's OWN machinery — the established-tier
filter its index applies (`_corpus.is_established`) and the id rule its query tool applies
when it binds (`query_tool.resolve_query_id`) — so "accepted by the check, unbindable by the
lead" is impossible by construction, not by test. The id is read from the RUN's tree at run
start, only for a run that will dispatch the lead, and the resolved identity is carried to
the dispatch rather than re-derived from import-time constants.

THE ORACLES. Every refusal is proved by a PLANTED input — a table through `write_table` +
`load_dispositions`, a template as a real `.md` read through `read_query_template` /
`iter_query_templates`, a config as a real yaml — beside a positive control on the same
address under the complementary condition. The shipped id is transcribed here as a literal
(`SHIPPED_TEMPLATE_ID`), never re-read from the file under test.

THE NAMES this suite pins (the implementation is written against them):
  * `defender/runtime/lead_zero_config.py` — `LEAD_ZERO_CONFIG_REL`, `lead_zero_config_path`,
    `LeadZeroConfigError`, `load_correlation_template`.
  * `defender/runtime/lead_zero/_agreement.py`, re-exported from `defender.runtime.lead_zero`
    — `CorrelationDispatch`, `CorrelationDispatchError`, `resolve_correlation_dispatch`.
  * `defender/runtime/driver/__init__.py` — `_correlation_dispatch_at_run_start`, the frame
    that reads the run's config and catalog and hands the result to the dispatch.
  * `defender/knowledge/environment/lead-zero.yaml` — one key, `correlation_template:`
    (since #1106: `knowledge/tenants/<id>/settings/lead-zero.yaml`).
"""
from __future__ import annotations

import re
import textwrap
from pathlib import Path

import pytest

from defender._corpus import iter_query_templates, read_query_template, section_bodies
from defender._paths import PATHS
from defender.runtime.verb_grant import VerbGrant
from defender.tests._dispositions995 import grant_for, load_dispositions, write_table
from defender.tests import _tenants1106 as T1106

DEFENDER = PATHS.defender_dir
SHIPPED_TEMPLATE = DEFENDER / "skills" / "gather" / "queries" / "elastic" / "correlate-alerts-by-entity.md"

#: The holder's name as the table spells it — a literal, as in `test_correlation_holder_999`.
HOLDER = "lead-zero-correlation"
#: The id the lead bound before #1003 moved it out of `_spec.py`, transcribed from the literal
#: as it stood. Conservation: the shipped config must name exactly this, and `_spec.py` must
#: no longer spell it.
SHIPPED_TEMPLATE_ID = "elastic.correlate-alerts-by-entity"

BOTH = {"roles": ["gather", HOLDER]}
GATHER_ONLY = {"roles": ["gather"]}


# =========================================================================================
# Planting helpers. Every expected value is the input, never a re-read.
# =========================================================================================

def _rows(tmp_path: Path, rows: dict) -> tuple:
    """A table holding exactly `rows`, loaded through the REAL loader (so its three narrowing
    rules have already passed — the tables here are all ones the loader stands behind)."""
    return load_dispositions(write_table(
        tmp_path / "settings" / "verb-grants.yaml", rows,
    ))


def _grant(tmp_path: Path, rows: dict) -> VerbGrant:
    return grant_for(HOLDER, _rows(tmp_path, rows))


def _shipped_shaped_grant(tmp_path: Path) -> VerbGrant:
    """The shipped table's holder rows, PLANTED rather than read off the process cache: the
    holder holds `elastic.alerts` and `elastic.health-check`; gather also holds `elastic.query`."""
    return _grant(tmp_path, {
        ("elastic", "alerts"): BOTH, ("elastic", "health-check"): BOTH,
        ("elastic", "query"): GATHER_ONLY,
    })


def _template_text(tid: str, *, verb: str | None, status: str = "established") -> str:
    """A minimal template document in the catalog's own shape (`SCHEMA.md`). `verb=None`
    OMITS the `verb:` line — the malformed shape #1003's O6 is about."""
    # The `verb:` line is spliced in AFTER the dedent: interpolated before it, its newline
    # leaves the following line unindented and `dedent` then strips nothing, so every planted
    # file reaches the corpus reader with an indented `---` and is skipped as malformed —
    # which would turn every "resolves" positive control below into a silent "not found".
    verb_line = f"verb: {verb}\n" if verb is not None else ""
    return textwrap.dedent(f"""\
        ---
        id: {tid}
        status: {status}
        @VERB@params: [end, start]
        body_substitutions: [entity_filter]
        ---

        ## Goal

        A planted correlation template for #1003's suite.

        ## Query

        ```
        ${{entity_filter}}
        ```
        """).replace("@VERB@", verb_line)


def _plant(
    catalog: Path, system: str, stem: str, *, tid: str | None = None, verb: str | None,
    status: str = "established", draft_dir: bool = False,
) -> Path:
    """Write ONE template file into a catalog tree and return its path. The id defaults to the
    location invariant (`{system}.{stem}`); pass `tid` to plant a file whose id disagrees."""
    where = catalog / system / ("_draft" if draft_dir else "")
    where.mkdir(parents=True, exist_ok=True)
    path = where / f"{stem}.md"
    path.write_text(_template_text(tid or f"{system}.{stem}", verb=verb, status=status),
                    encoding="utf-8")
    return path


def _templates(catalog: Path) -> list:
    """The catalog as the run-start check walks it — the REAL corpus walker over the planted
    tree, so `status`, `path.parts` and the `verb == ""` fallback are all the corpus's own."""
    return list(iter_query_templates(catalog))


class _NeverWalked:
    """A `templates` iterable that FAILS the test if anything iterates it — how a withheld
    lead proves the id was not consulted (O6, second sentence)."""

    def __iter__(self):
        raise AssertionError(
            "the catalog was walked for a WITHHELD lead — the id must not be consulted when "
            "the table grants the holder no query verb"
        )


def _config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "settings" / "lead-zero.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _pair(system: str, verb: str) -> str:
    """The spelling a refusal names a pair by — `system.verb`, the table's own (the spelling
    `_refuse_incoherent_narrowing` uses and the one an operator greps the table for)."""
    return f"{system}.{verb}"


# =========================================================================================
# The config file: one key, per-deployment, refused the way `verb-grants.yaml` is.
# =========================================================================================

def test_the_shipped_config_names_the_template_and_the_run_start_frame_reads_it():
    """Conservation and wiring in one: the shipped `lead-zero.yaml` exists at the path the
    module derives, names exactly the id `_spec.py` used to spell, and the RUN-START frame
    over this checkout (`run_tenant.resolve_run_tenant`, whose value the driver's
    `_correlation_dispatch_at_run_start` carries) resolves that file's value on the shipped
    table to a dispatch on `elastic` carrying the id and the table's projection. Serves O1: the id is authored config, and the dispatch is its projection —
    there is no import-time constant for it to be read from."""
    from defender.runtime import lead_zero
    from defender.runtime.driver import _correlation_dispatch_at_run_start
    from defender.runtime.lead_zero_config import (
        lead_zero_config_path,
        load_correlation_template,
    )
    from defender.runtime.run_tenant import resolve_run_tenant

    # #1106: the config lives in the RUN's tenant settings folder (the committed playground
    # tenant at the repo root), and the frame reads it from the tenant and grants it is handed.
    settings = T1106.PLAYGROUND_SETTINGS
    path = lead_zero_config_path(settings)
    assert path == settings / "lead-zero.yaml"
    assert path.is_file(), f"the shipped config is missing at {path}"
    assert path.relative_to(PATHS.repo_root).as_posix() == \
        "knowledge/tenants/playground/settings/lead-zero.yaml"

    assert load_correlation_template(path) == SHIPPED_TEMPLATE_ID
    grants = T1106.playground_grants()
    run_tenant = resolve_run_tenant(
        T1106.playground_tenant(), defender_dir=DEFENDER, dispatches_lead_zero=True)
    assert _correlation_dispatch_at_run_start(
        tenant=run_tenant, resume=None, lead_zero_verbs=object(),
    ) == lead_zero.CorrelationDispatch(
        template_id=SHIPPED_TEMPLATE_ID, system="elastic", grant=grants.correlation,
    )
    assert not hasattr(lead_zero, "CORRELATION_TEMPLATE"), (
        "the template id is a per-tree fact read at run start; a process-wide constant for "
        "it is the checkout's value pinned to every tree the run is pointed at"
    )


def test_a_planted_config_is_read_rather_than_a_literal(tmp_path):
    """O1: the id is what the FILE says. A planted config naming another backend's template
    returns THAT id — the loader carries no default and no fallback to the shipped value.
    The positive control on the same address is the shipped id round-tripping."""
    from defender.runtime.lead_zero_config import load_correlation_template

    planted = _config(tmp_path / "moved", "correlation_template: splunk.correlate-things\n")
    assert load_correlation_template(planted) == "splunk.correlate-things"

    shipped_shaped = _config(tmp_path / "same", f"correlation_template: {SHIPPED_TEMPLATE_ID}\n")
    assert load_correlation_template(shipped_shaped) == SHIPPED_TEMPLATE_ID


def test_the_loader_does_not_validate_the_id_against_catalog_or_grammar(tmp_path):
    """The loader returns the STRING; resolving it against a catalog and checking its grammar
    is the run-start check's job (`resolve_correlation_dispatch`), where the catalog is
    visible."""
    from defender.runtime.lead_zero_config import load_correlation_template

    assert load_correlation_template(_config(tmp_path, "correlation_template: not-an-id\n")) == "not-an-id"


def test_a_missing_config_is_refused_naming_the_path(tmp_path):
    """No file is not "the shipped default": a deployment tree without the config gets a
    typed refusal naming where the file was looked for, the way an absent table does."""
    from defender.runtime.lead_zero_config import LeadZeroConfigError, load_correlation_template

    missing = tmp_path / "settings" / "lead-zero.yaml"
    with pytest.raises(LeadZeroConfigError) as caught:
        load_correlation_template(missing)
    assert str(missing) in str(caught.value), str(caught.value)


@pytest.mark.parametrize(("text", "refused_key"), [
    # THE classic: the key misspelled, so the file says something the loader would not read.
    ("correlation_tempalte: elastic.correlate-alerts-by-entity\n", "correlation_tempalte"),
    # A second key beside the real one — a statement a reviewer reads and nothing honours.
    (f"correlation_template: {SHIPPED_TEMPLATE_ID}\nrequest_limit: 8\n", "request_limit"),
])
def test_an_unread_key_is_refused_naming_it(tmp_path, text, refused_key):
    """Unknown top-level keys are refused the way `verb-grants.yaml`'s are
    (`_reject_unread_keys`): a key nothing reads is the two-statements-one-honoured defect
    one level up. The refusal NAMES the key, so a typo sends the author to the typo and not
    to a hunt for a missing value. Positive control: exactly the one key loads."""
    from defender.runtime.lead_zero_config import LeadZeroConfigError, load_correlation_template

    assert load_correlation_template(
        _config(tmp_path / "ok", f"correlation_template: {SHIPPED_TEMPLATE_ID}\n")
    ) == SHIPPED_TEMPLATE_ID

    path = _config(tmp_path / "bad", text)
    with pytest.raises(LeadZeroConfigError) as caught:
        load_correlation_template(path)
    message = str(caught.value)
    assert refused_key in message, message
    assert str(path) in message, message


@pytest.mark.parametrize("text", [
    "correlation_template: 3\n",           # not a string
    'correlation_template: ""\n',          # empty
    "correlation_template:\n",             # null
    "{}\n",                                # the key absent
    "- correlation_template\n",            # top level is a list, not a mapping
    "correlation_template: [\n",           # does not parse
], ids=["int", "empty", "null", "absent", "list", "unparseable"])
def test_a_config_with_no_usable_id_is_refused_naming_the_path(tmp_path, text):
    """Every shape that carries no id is a refusal, never `""` or `None` handed on: an empty
    id would resolve to no template and be refused at run start as a TYPO, which sends the
    author to the catalog instead of to the file that is empty."""
    from defender.runtime.lead_zero_config import LeadZeroConfigError, load_correlation_template

    path = _config(tmp_path, text)
    with pytest.raises(LeadZeroConfigError) as caught:
        load_correlation_template(path)
    assert str(path) in str(caught.value), str(caught.value)


def test_an_undecodable_config_is_refused_naming_the_path_not_raised_raw(tmp_path):
    """The #677 shape: bytes that are not UTF-8. A raw `UnicodeDecodeError` out of an
    import-time read is a stack trace, not a refusal naming the file — the typed error is
    what an operator who just saved the file in the wrong encoding needs. Positive control:
    the same path, valid bytes, loads."""
    from defender.runtime.lead_zero_config import LeadZeroConfigError, load_correlation_template

    path = _config(tmp_path, f"correlation_template: {SHIPPED_TEMPLATE_ID}\n")
    assert load_correlation_template(path) == SHIPPED_TEMPLATE_ID
    path.write_bytes(b"correlation_template: \xff\xfe\n")
    with pytest.raises(LeadZeroConfigError) as caught:
        load_correlation_template(path)
    assert str(path) in str(caught.value), str(caught.value)


def test_a_repeated_key_is_refused_rather_than_last_wins(tmp_path):
    """Two `correlation_template:` lines are two statements, one of which YAML would silently
    honour — the duplicate-key defect the table loader refuses (#995), refused here the same
    way, naming the path. Positive control: one line loads."""
    from defender.runtime.lead_zero_config import LeadZeroConfigError, load_correlation_template

    assert load_correlation_template(
        _config(tmp_path / "ok", f"correlation_template: {SHIPPED_TEMPLATE_ID}\n")
    ) == SHIPPED_TEMPLATE_ID
    path = _config(tmp_path / "dup",
                   f"correlation_template: {SHIPPED_TEMPLATE_ID}\n"
                   "correlation_template: splunk.correlate-things\n")
    with pytest.raises(LeadZeroConfigError) as caught:
        load_correlation_template(path)
    assert str(path) in str(caught.value), str(caught.value)


def test_the_run_start_frame_reads_the_config_and_catalog_of_the_tree_it_is_handed(tmp_path):
    """`run_tenant.resolve_run_tenant(tenant, defender_dir=…)` joins THAT run's config (its
    tenant's settings folder, #1106) with THAT tree's catalog and the run's own grants, and the
    driver's `_correlation_dispatch_at_run_start` carries the value it resolved.
    A tree whose catalog holds only `elastic.other-alerts` and whose config names it resolves
    to a dispatch on that id — a frame reading the checkout's config would look for the
    shipped id in this catalog and refuse. Negative control on the same tree: the config
    removed is `LeadZeroConfigError` naming the tree's path, not the checkout's — and NOT
    raised for a run that will not dispatch the lead (a resume, no registry), which reads
    neither file."""
    from defender.runtime.driver import _correlation_dispatch_at_run_start
    from defender.runtime.lead_zero import CorrelationDispatch
    from defender.runtime.lead_zero_config import LeadZeroConfigError, lead_zero_config_path
    from defender.runtime.run_tenant import resolve_run_tenant

    tree = tmp_path / "repo" / "defender"
    _plant(tree / "skills" / "gather" / "queries", "elastic", "other-alerts", verb="alerts")
    # The run's tenant, planted outside the tree (its table grants the lead elastic.alerts).
    T1106.plant_tenant(tmp_path / "tenants", "acme",
                       lead_zero="correlation_template: elastic.other-alerts\n")
    tenant = T1106.tenants().tenant_dir(tmp_path / "tenants", "acme")
    grants = T1106.run_grants(tenant.settings)
    config = lead_zero_config_path(tenant.settings)
    assert config == tenant.settings / "lead-zero.yaml"
    assert config.is_file()

    dispatching = resolve_run_tenant(tenant, defender_dir=tree, dispatches_lead_zero=True)
    assert dispatching.correlation == CorrelationDispatch(
        template_id="elastic.other-alerts", system="elastic", grant=grants.correlation,
    )
    assert _correlation_dispatch_at_run_start(
        tenant=dispatching, resume=None, lead_zero_verbs=object()) == dispatching.correlation

    config.unlink()
    with pytest.raises(LeadZeroConfigError) as caught:
        resolve_run_tenant(tenant, defender_dir=tree, dispatches_lead_zero=True)
    assert str(config) in str(caught.value), str(caught.value)
    # A run that will not dispatch the lead reads neither file, and the driver keys on that.
    resumed = resolve_run_tenant(tenant, defender_dir=tree, dispatches_lead_zero=False)
    assert resumed.correlation is None
    assert _correlation_dispatch_at_run_start(
        tenant=resumed, resume=object(), lead_zero_verbs=object()) is None
    assert _correlation_dispatch_at_run_start(
        tenant=resumed, resume=None, lead_zero_verbs=None) is None
    # ...and a tenant resolved as not dispatching, handed to a run that WOULD, is refused
    # rather than dispatched unchecked.
    with pytest.raises(TypeError):
        _correlation_dispatch_at_run_start(tenant=resumed, resume=None, lead_zero_verbs=object())


# =========================================================================================
# O1 — nothing in Python names the vendor the lead dispatches to.
# =========================================================================================

def test_spec_no_longer_spells_the_template_id():
    """The literal is gone from `_spec.py`, and so is any read of the config: the vocabulary
    leaf a dozen modules import for two strings reads no tree, and the id reaches the lead
    only through the run-start frame. `ITEM1_SYSTEM` legitimately stays a literal (N2 — item
    1 is harness code on one vendor's fields and is not this issue's), and the budget stays
    the measured constant (N1)."""
    from defender.runtime.lead_zero import _spec

    source = Path(_spec.__file__).read_text(encoding="utf-8")
    assert SHIPPED_TEMPLATE_ID not in source, (
        "_spec.py still spells the template id as a literal — the id is per-deployment "
        "config now, read through lead_zero_config"
    )
    # The WHOLE runtime package, not only `_spec.py`: a loader that returned the literal
    # (file left on disk so the loader tests still pass) would move the vendor name one
    # module over and satisfy the scan above (adversary H2).
    runtime = Path(_spec.__file__).resolve().parents[1]
    spelled = sorted(
        str(f.relative_to(runtime)) for f in runtime.rglob("*.py")
        if SHIPPED_TEMPLATE_ID in f.read_text(encoding="utf-8")
    )
    assert spelled == [], f"the template id is spelled as a literal under runtime/: {spelled}"
    assert not hasattr(_spec, "CORRELATION_TEMPLATE")
    assert "lead_zero_config" not in source, "the vocabulary leaf must not read the config"
    assert _spec.ITEM1_SYSTEM == "elastic"
    assert _spec.CORRELATION_REQUEST_LIMIT == 8


def test_a_planted_backend_dispatches_on_its_own_system(tmp_path):
    """O1, by mechanism (N4: no second template ships). A second established correlation
    template on `splunk` binding `search`, the id configured, and the holder's rows on
    `splunk.search`: the resolved dispatch is ON `splunk`, carries the planted id, and
    its grant is the table's projection handed in, unchanged. Nothing in Python had to name
    the vendor."""
    from defender.runtime.lead_zero import CorrelationDispatch, resolve_correlation_dispatch

    catalog = tmp_path / "catalog"
    _plant(catalog, "splunk", "correlate-things", verb="search")
    # The shipped template sits beside it — a catalog with two backends' correlation
    # templates is exactly the tree a moved deployment has.
    _plant(catalog, "elastic", "correlate-alerts-by-entity", verb="alerts")
    grant = _grant(tmp_path, {
        ("splunk", "search"): BOTH, ("splunk", "health-check"): BOTH,
        ("elastic", "alerts"): GATHER_ONLY, ("elastic", "health-check"): GATHER_ONLY,
    })

    dispatch = resolve_correlation_dispatch("splunk.correlate-things", _templates(catalog), grant)

    assert dispatch == CorrelationDispatch(
        template_id="splunk.correlate-things", system="splunk", grant=grant,
    )
    assert set(dispatch.grant.entries) == set(grant.entries)


# =========================================================================================
# O2 (withheld arm) / O6 second sentence — a withholding degrades and consults no id.
# =========================================================================================

def test_a_withheld_lead_consults_no_template_and_stays_two_state(tmp_path):
    """When the table grants the holder no query verb, the dispatch is `system=None` and
    the catalog is NOT walked — proved by a `templates` iterable that
    fails the test on iteration, and by a garbage id that would be refused on any other arm
    passing through untouched. The grant still rides (it is the table's projection), and the
    ORIENT note stays the existing two-state one: `test_correlation_holder_999::
    test_the_orient_heading_says_the_lead_was_withheld` pins its text; N5 says no third state
    is threaded through, and this test only checks that arm is still the one taken."""
    from defender.runtime.lead_zero import (
        L3,
        CorrelationDispatch,
        LeadZeroResult,
        render_orient_section,
        resolve_correlation_dispatch,
    )

    withheld = _grant(tmp_path, {
        ("elastic", "alerts"): GATHER_ONLY, ("elastic", "health-check"): BOTH,
    })

    dispatch = resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, _NeverWalked(), withheld)
    assert dispatch == CorrelationDispatch(
        template_id=SHIPPED_TEMPLATE_ID, system=None, grant=withheld,
    )
    # The id is not consulted at all: an id no other arm would accept passes through.
    assert resolve_correlation_dispatch("not-an-id", _NeverWalked(), withheld).system is None

    # Positive control on the same address: with the pair granted, the catalog IS walked.
    granted = _shipped_shaped_grant(tmp_path / "granted")
    with pytest.raises(AssertionError, match="WITHHELD lead"):
        resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, _NeverWalked(), granted)

    # #1106 M4: the note names the run's resolved table — here the one `_grant` planted.
    table = str(tmp_path / "settings" / "verb-grants.yaml")
    orient = render_orient_section(LeadZeroResult(text="", status="resolved"), None,
                                   correlation_system=dispatch.system, grant_home=table)
    assert L3 in orient, orient
    assert table in orient, orient


# =========================================================================================
# O2 / O5 — the agreement check: the template's pair must be the holder's one query pair.
# =========================================================================================

def test_a_same_vendor_verb_mismatch_is_refused_naming_both_pairs(tmp_path):
    """The grounding's second row, the one a system-prefix check passes: the configured id
    resolves to an established `elastic` template binding `query`, and the table grants the
    holder `elastic.alerts`. Refused, naming the TEMPLATE's pair and the TABLE's pair and the
    id — so the operator sees both sides of the disagreement at once. Positive control: the
    same catalog, the id whose template binds `alerts`, resolves."""
    from defender.runtime.lead_zero import CorrelationDispatchError, resolve_correlation_dispatch

    catalog = tmp_path / "catalog"
    _plant(catalog, "elastic", "correlate-alerts-by-entity", verb="alerts")
    _plant(catalog, "elastic", "correlate-by-query", verb="query")
    grant = _shipped_shaped_grant(tmp_path)

    ok = resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, _templates(catalog), grant)
    assert (ok.system, ok.template_id) == ("elastic", SHIPPED_TEMPLATE_ID)

    with pytest.raises(CorrelationDispatchError) as caught:
        resolve_correlation_dispatch("elastic.correlate-by-query", _templates(catalog), grant)
    message = str(caught.value)
    assert "elastic.correlate-by-query" in message, message
    assert _pair("elastic", "query") in message, f"the template's pair is not named:\n{message}"
    assert _pair("elastic", "alerts") in message, f"the table's pair is not named:\n{message}"


def test_a_table_granting_a_different_verb_is_refused_naming_both_pairs(tmp_path):
    """O5 (i), the table side of the same disagreement: the holder's rows moved to
    `elastic.query` (a legitimate-looking narrowing under the loader's own rationale) while
    the configured id's template binds `alerts`. The loader passes it — all three narrowing
    rules hold — and the agreement check refuses it, naming `elastic.alerts` (the template)
    and `elastic.query` (the table). Positive control: the shipped-shaped table resolves."""
    from defender.runtime.lead_zero import CorrelationDispatchError, resolve_correlation_dispatch

    catalog = tmp_path / "catalog"
    _plant(catalog, "elastic", "correlate-alerts-by-entity", verb="alerts")
    templates = _templates(catalog)

    assert resolve_correlation_dispatch(
        SHIPPED_TEMPLATE_ID, templates, _shipped_shaped_grant(tmp_path / "ok"),
    ).system == "elastic"

    moved = _grant(tmp_path / "moved", {
        ("elastic", "alerts"): GATHER_ONLY, ("elastic", "health-check"): BOTH,
        ("elastic", "query"): BOTH,
    })
    with pytest.raises(CorrelationDispatchError) as caught:
        resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, templates, moved)
    message = str(caught.value)
    assert SHIPPED_TEMPLATE_ID in message, message
    assert _pair("elastic", "alerts") in message, f"the template's pair is not named:\n{message}"
    assert _pair("elastic", "query") in message, f"the table's pair is not named:\n{message}"


def test_the_reports_table_moving_the_holder_to_another_vendor_is_refused(tmp_path):
    """The report's own rows — `splunk.search` granted to the holder — with the shipped id
    still configured. Before #1003 this loaded clean and burned the budget; now it is a
    refusal naming `elastic.alerts` (what the template binds) and `splunk.search` (what the
    table grants). Positive control: the same rows with the id moved to the splunk template
    resolve on splunk."""
    from defender.runtime.lead_zero import CorrelationDispatchError, resolve_correlation_dispatch

    catalog = tmp_path / "catalog"
    _plant(catalog, "elastic", "correlate-alerts-by-entity", verb="alerts")
    _plant(catalog, "splunk", "correlate-things", verb="search")
    templates = _templates(catalog)
    report_rows = _grant(tmp_path, {
        ("splunk", "search"): BOTH, ("splunk", "health-check"): BOTH,
        ("elastic", "alerts"): GATHER_ONLY, ("elastic", "health-check"): GATHER_ONLY,
    })

    assert resolve_correlation_dispatch("splunk.correlate-things", templates, report_rows).system == "splunk"

    with pytest.raises(CorrelationDispatchError) as caught:
        resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, templates, report_rows)
    message = str(caught.value)
    assert _pair("elastic", "alerts") in message, message
    assert _pair("splunk", "search") in message, message


def test_a_template_binding_the_health_check_verb_is_not_a_dispatch_target(tmp_path):
    """Agreement is EQUALITY with the holder's one QUERY pair, not `grant.allows`: the holder
    also holds `elastic.health-check`, so a check written as "does the grant allow the
    template's pair" would accept an established template binding `verb: health-check` and
    dispatch a lead with an eight-request budget against a ping (adversary H3;
    `correlation_system`'s own docstring: "Health-check alone is not a target either").
    Refused naming `elastic.health-check` and `elastic.alerts`. Positive control: the
    `alerts` template on the same catalog resolves."""
    from defender.runtime.lead_zero import CorrelationDispatchError, resolve_correlation_dispatch

    catalog = tmp_path / "catalog"
    _plant(catalog, "elastic", "correlate-alerts-by-entity", verb="alerts")
    _plant(catalog, "elastic", "ping", verb="health-check")
    templates = _templates(catalog)
    grant = _shipped_shaped_grant(tmp_path)
    assert grant.allows("elastic", "health-check"), "the fixture's grant must hold the pair"
    assert resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, templates, grant).system == "elastic"
    with pytest.raises(CorrelationDispatchError) as caught:
        resolve_correlation_dispatch("elastic.ping", templates, grant)
    message = str(caught.value)
    assert _pair("elastic", "health-check") in message, message
    assert _pair("elastic", "alerts") in message, message


def test_the_grant_reaching_the_dispatch_is_the_tables_projection_whatever_the_id_says(tmp_path):
    """O5, the negative universal at the unit seam: no id value changes the GRANT a dispatch
    carries. Two ids resolving to two templates on the same pair yield dispatches whose
    grant is the table's projection, equal to each other and to what was handed in — the
    template selects, only the table grants. (`_NarrowedRegistry` pointing at the table is
    pinned by `test_correlation_holder_999::test_the_narrowed_registry_points_at_the_table`.)"""
    from defender.runtime.lead_zero import resolve_correlation_dispatch

    catalog = tmp_path / "catalog"
    _plant(catalog, "elastic", "correlate-alerts-by-entity", verb="alerts")
    _plant(catalog, "elastic", "another-alerts-template", verb="alerts")
    grant = _shipped_shaped_grant(tmp_path)
    templates = _templates(catalog)

    first = resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, templates, grant)
    second = resolve_correlation_dispatch("elastic.another-alerts-template", templates, grant)
    assert first.grant == second.grant == grant
    assert {(s, v) for s, v, _ in first.grant.entries} == {("elastic", "alerts"), ("elastic", "health-check")}
    assert first.template_id != second.template_id


# =========================================================================================
# O6 (a) — an id that is not a template id, or resolves to no established template.
# =========================================================================================

@pytest.mark.parametrize("bad_id", [
    "not-an-id", "Elastic.x", "elastic.",
    # A second dot: `resolve_query_id` refuses it (a second unvalidated path component at
    # the draft writer), so the lead could not bind it as its own id (adversary H6).
    "elastic.correlate.alerts",
    # A path shape and a render shape — the query tool's own forbidden characters.
    "elastic.a/b", "elastic.a#b",
    # THE misfiled file: an id naming another system than the directory it sits in — the
    # location invariant the corpus lints, met here at bind time. The prefix IS a well-formed
    # system name and the id IS `{system}.{kebab}`; only the location disagrees.
    "splunk.carrier",
])
def test_an_id_the_lead_could_not_bind_as_its_own_is_refused_even_when_a_file_carries_it(tmp_path, bad_id):
    """The bind-time arm is `query_tool.resolve_query_id`'s verdict, not a "not found": the
    catalog is planted with a file whose `id:` is exactly the string (the corpus reader
    accepts any string), established, binding the granted verb — and the id is still
    refused, naming it, because the lead's own `query` call would not record it verbatim.
    Without that file, "not found" would discharge the same assertion for the wrong reason.
    Positive control: a well-formed id over the same-shaped file resolves.

    NOT refused here: a suffix the tool binds (`elastic.Correlate_Alerts` — `_KEBAB_SEGMENT`
    admits it). Whether the corpus should carry such an id is the corpus lint's question; a
    run-start check that refused an id the lead can bind would be a second grammar, and the
    two would drift."""
    from defender.runtime.lead_zero import CorrelationDispatchError, resolve_correlation_dispatch
    from defender.runtime.query_tool import resolve_query_id

    catalog = tmp_path / "catalog"
    _plant(catalog, "elastic", "carrier", tid=bad_id, verb="alerts")
    _plant(catalog, "elastic", "correlate-alerts-by-entity", verb="alerts")
    templates = _templates(catalog)
    assert bad_id in {t.id for t in templates}, "the fixture must plant the malformed id"
    assert resolve_query_id("elastic", "alerts", bad_id) != bad_id, (
        "the fixture's id must be one the lead's query tool would NOT record verbatim"
    )
    grant = _shipped_shaped_grant(tmp_path)

    assert resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, templates, grant).system == "elastic"

    with pytest.raises(CorrelationDispatchError) as caught:
        resolve_correlation_dispatch(bad_id, templates, grant)
    message = str(caught.value)
    assert bad_id in message, message
    assert "not the table" in message, f"a fault in the file must not send the operator to the table:\n{message}"


def test_an_id_the_lead_binds_verbatim_is_accepted_exactly_when_the_tool_would(tmp_path):
    """The positive half of the bind-time arm, pinned to the tool: an id `resolve_query_id`
    hands back verbatim on the granted system is resolved, even a suffix the design's prose
    would not spell (uppercase, an underscore) — because a lead handed that id WILL bind it.
    One resolver: the check's verdict is the tool's verdict on the same string."""
    from defender.runtime.lead_zero import resolve_correlation_dispatch
    from defender.runtime.query_tool import resolve_query_id

    odd = "elastic.Correlate_Alerts"
    assert resolve_query_id("elastic", "alerts", odd) == odd, "the fixture's id must be one the tool binds"
    catalog = tmp_path / "catalog"
    _plant(catalog, "elastic", "carrier", tid=odd, verb="alerts")
    dispatch = resolve_correlation_dispatch(odd, _templates(catalog), _shipped_shaped_grant(tmp_path))
    assert (dispatch.system, dispatch.template_id) == ("elastic", odd)


def test_two_established_files_carrying_the_id_are_refused_naming_both_paths(tmp_path):
    """An ambiguous catalog is refused AS ambiguous, whichever file sorts first — never
    settled by `matches[0]`. Proved from both sides of the sort: with the granted verb on the
    later file the naive pick refuses as a MISMATCH (sending the operator to the table for a
    duplicate-id fault); with it on the earlier file the naive pick ACCEPTS. Both orders
    refuse here, naming both paths. Positive control: either file alone resolves."""
    from defender.runtime.lead_zero import CorrelationDispatchError, resolve_correlation_dispatch

    grant = _shipped_shaped_grant(tmp_path)
    for granted_first in (True, False):
        catalog = tmp_path / ("first" if granted_first else "second")
        a = _plant(catalog, "elastic", "a", tid=SHIPPED_TEMPLATE_ID, verb="alerts" if granted_first else "query")
        b = _plant(catalog, "elastic", "b", tid=SHIPPED_TEMPLATE_ID, verb="query" if granted_first else "alerts")
        with pytest.raises(CorrelationDispatchError) as caught:
            resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, _templates(catalog), grant)
        message = str(caught.value)
        assert str(a) in message, message
        assert str(b) in message, message
        assert _pair("elastic", "query") not in message, (
            f"an ambiguous catalog must not be reported as a table mismatch:\n{message}"
        )

    alone = tmp_path / "alone"
    _plant(alone, "elastic", "b", tid=SHIPPED_TEMPLATE_ID, verb="alerts")
    assert resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, _templates(alone), grant).system == "elastic"


def test_a_grant_holding_two_query_pairs_is_refused_as_the_functions_own_contract(tmp_path):
    """A grant that did not come through the loader (which refuses a second query verb for
    this holder) and holds two query pairs on one system: `correlation_system` derives one
    system from it, and the check must not compare the template with whichever pair sorts
    first — it raises `GrantError`, the way `correlation_system` does for two systems."""
    from defender.runtime.lead_zero import resolve_correlation_dispatch
    from defender.runtime.verb_grant import GrantError

    catalog = tmp_path / "catalog"
    _plant(catalog, "elastic", "correlate-alerts-by-entity", verb="alerts")
    two = VerbGrant(role=HOLDER, entries=(("elastic", "alerts", "r"), ("elastic", "query", "r")))
    with pytest.raises(GrantError) as caught:
        resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, _templates(catalog), two)
    assert _pair("elastic", "alerts") in str(caught.value)
    assert _pair("elastic", "query") in str(caught.value)


def test_a_typo_resolving_to_nothing_is_refused_naming_the_id(tmp_path):
    """The classic: one letter off. The id is well-formed and no established template carries
    it, so the refusal names the id and says it resolves to no established template — the
    operator is sent to the catalog, not to the table."""
    from defender.runtime.lead_zero import CorrelationDispatchError, resolve_correlation_dispatch

    catalog = tmp_path / "catalog"
    _plant(catalog, "elastic", "correlate-alerts-by-entity", verb="alerts")
    templates = _templates(catalog)
    grant = _shipped_shaped_grant(tmp_path)

    assert resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, templates, grant).system == "elastic"

    typo = "elastic.correlate-alert-by-entity"
    with pytest.raises(CorrelationDispatchError) as caught:
        resolve_correlation_dispatch(typo, templates, grant)
    message = str(caught.value)
    assert typo in message, message
    assert "established" in message, message


def test_a_draft_or_misfiled_copy_does_not_resolve(tmp_path):
    """"Established, non-draft" is BOTH halves, THE predicate `_template_index` filters on
    (`_corpus.is_established` — one function, both callers): a copy under `_draft/`
    (whatever its status says) and a file at the system root with `status: draft` each fail
    to resolve, because neither is in the index the lead is told to read. Positive control:
    the same file at the root, `status: established`, resolves."""
    from defender.runtime.lead_zero import CorrelationDispatchError, resolve_correlation_dispatch

    grant = _shipped_shaped_grant(tmp_path)

    drafted = tmp_path / "drafted"
    _plant(drafted, "elastic", "correlate-alerts-by-entity", verb="alerts", status="draft", draft_dir=True)
    with pytest.raises(CorrelationDispatchError) as caught:
        resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, _templates(drafted), grant)
    assert SHIPPED_TEMPLATE_ID in str(caught.value)

    misfiled = tmp_path / "misfiled"
    _plant(misfiled, "elastic", "correlate-alerts-by-entity", verb="alerts", status="established", draft_dir=True)
    with pytest.raises(CorrelationDispatchError):
        resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, _templates(misfiled), grant)

    demoted = tmp_path / "demoted"
    _plant(demoted, "elastic", "correlate-alerts-by-entity", verb="alerts", status="draft")
    with pytest.raises(CorrelationDispatchError):
        resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, _templates(demoted), grant)

    established = tmp_path / "established"
    _plant(established, "elastic", "correlate-alerts-by-entity", verb="alerts")
    ok = resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, _templates(established), grant)
    assert ok.system == "elastic"


def test_an_empty_catalog_is_refused_not_dispatched(tmp_path):
    """A deployment whose catalog dir is absent walks nothing (`iter_query_templates` yields
    nothing for a missing dir) — and that is an unresolvable id, not a dispatch: the lead
    would be told to bind a template no index lists."""
    from defender.runtime.lead_zero import CorrelationDispatchError, resolve_correlation_dispatch

    with pytest.raises(CorrelationDispatchError) as caught:
        resolve_correlation_dispatch(
            SHIPPED_TEMPLATE_ID, _templates(tmp_path / "nowhere"), _shipped_shaped_grant(tmp_path),
        )
    assert SHIPPED_TEMPLATE_ID in str(caught.value)


# =========================================================================================
# O6 (b) — a template with no `verb:` is malformed, not a table mismatch on `(system, '')`.
# =========================================================================================

def test_a_template_declaring_no_verb_is_refused_as_malformed_not_as_a_mismatch(tmp_path):
    """Built through the REAL reader: a `.md` with no `verb:` line parses to `verb == ""`
    (`_corpus.py`'s fallback, asserted as the precondition). The refusal says the template
    declares no `verb:` and names the id; it does NOT render `elastic.` with an empty verb as
    the template's pair, which would send the operator to the table for a fault in the file.
    Positive control: the same file with `verb: alerts` added resolves."""
    from defender.runtime.lead_zero import CorrelationDispatchError, resolve_correlation_dispatch

    grant = _shipped_shaped_grant(tmp_path)

    verbless = tmp_path / "verbless"
    path = _plant(verbless, "elastic", "correlate-alerts-by-entity", verb=None)
    parsed, reason = read_query_template(path)
    assert parsed is not None, reason
    assert parsed.verb == "", parsed

    with pytest.raises(CorrelationDispatchError) as caught:
        resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, _templates(verbless), grant)
    message = str(caught.value)
    assert "verb:" in message, f"the refusal must say the template declares no `verb:`:\n{message}"
    assert SHIPPED_TEMPLATE_ID in message, message
    assert "('elastic', '')" not in message, message
    assert re.search(r"elastic\.(?![a-z0-9])", message) is None, (
        f"the refusal presents an EMPTY verb as the template's pair — a table mismatch on "
        f"`(elastic, '')` rather than a malformed template:\n{message}"
    )

    repaired = tmp_path / "repaired"
    _plant(repaired, "elastic", "correlate-alerts-by-entity", verb="alerts")
    ok = resolve_correlation_dispatch(SHIPPED_TEMPLATE_ID, _templates(repaired), grant)
    assert ok.system == "elastic"


# =========================================================================================
# O4 — the template carries the vendor facts the harness stopped saying.
# =========================================================================================

def test_the_template_carries_the_rule_field_pitfall_and_its_declarations_are_intact():
    """The sentence the harness dropped — the documents the lead is bound from may carry
    `kibana.alert.rule.*`, and it is not an axis to AND into `${entity_filter}` — is ADDED
    to the template's Pitfalls (the grounding found it was not there). The front matter the
    estate stager consumes (`verb`, `params`, `body_substitutions`) is unchanged, and the
    template stays established under its id."""
    template, reason = read_query_template(SHIPPED_TEMPLATE)
    assert template is not None, reason
    assert template.id == SHIPPED_TEMPLATE_ID
    assert template.status == "established"
    assert template.verb == "alerts"
    assert template.params == ("end", "start")
    assert template.body_substitutions == ("entity_filter",)

    pitfalls = section_bodies(template.body).get("Pitfalls", "")
    assert "kibana.alert.rule" in pitfalls, (
        "the template's Pitfalls do not tell the lead that its input documents may carry "
        "`kibana.alert.rule.*` and that the rule is not an axis to bind"
    )
    # ONE bullet carries the field, the filter and the NEGATION together: presence of the
    # two tokens alone is satisfied by the inverted instruction ("AND the rule into the
    # filter so the count stays on this rule"), rendered to every gather lead on the system
    # (adversary H5). Bullets are the `- ` items of the section.
    bullets = [b for b in re.split(r"\n(?=- )", pitfalls) if "kibana.alert.rule" in b]
    assert bullets, pitfalls
    rule_bullet = bullets[0]
    assert "entity_filter" in rule_bullet, "the pitfall must say where the rule must NOT be ANDed"
    assert re.search(r"\b(?:do not|not an axis|is not an axis)\b", rule_bullet, re.IGNORECASE), (
        f"the rule-field pitfall does not NEGATE binding the rule:\n{rule_bullet}"
    )
    assert not re.search(r"\bso the count stays on this rule\b", rule_bullet, re.IGNORECASE)
