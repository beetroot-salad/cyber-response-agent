"""verb_roster audit: model-read surface enumeration and withheld-verb detection."""
from __future__ import annotations

from defender.systems import verb_roster


def test_model_surface_enumeration_and_withheld_verb_audit_survive(tmp_path):
    """D6: deleting generator/loader cannot delete the functioning audit of instruction text."""
    tree = tmp_path / 'defender'
    adapters = tree / "integrations"
    adapters.mkdir(parents=True)
    (adapters / 'cmdb_adapter.py').write_text(
        "SYSTEM = 'cmdb'\ndef lookup(ctx): pass\nVERBS = {'lookup': lookup}\n", encoding='utf-8')
    skill = tree / 'skills' / 'cmdb' / 'SKILL.md'
    skill.parent.mkdir(parents=True)
    skill.write_text('Use cmdb.lookup to retrieve the host.\n', encoding='utf-8')
    assert skill in verb_roster.model_read_surfaces(tree)
    hits = verb_roster.audit_read_surfaces(tree, {})
    assert len(hits) == 1
    assert 'skills/cmdb/SKILL.md' in hits[0]
    assert 'cmdb.lookup' in hits[0]
    skill.write_text('No query calls are advertised here.\n', encoding='utf-8')
    assert verb_roster.audit_read_surfaces(tree, {}) == (), 'clean control must stay clean'
