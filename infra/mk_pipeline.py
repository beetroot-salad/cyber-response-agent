#!/usr/bin/env python3
"""Build playground-v2/ingest/falco-ecs-entities.json from a readable Painless source."""
import json
import pathlib

SCRIPT = """
boolean usable(def v) {
  if (v == null) { return false; }
  if (v instanceof String) {
    String s = (String) v;
    return !s.isEmpty() && !s.equals('<NA>');
  }
  return true;
}

/* `container.id` carries the literal string 'host' for every event Falco saw OUTSIDE a
   container, and that is the majority of them (24 of the first 33 normalized, measured
   2026-08-13). It is a sentinel, not an id: copied through, it would mint a correlation axis
   matching every host-level Falco event — the same match-everything defect as correlating on
   the shared VPS host name, which is the whole of issue #867. */
boolean usable_container_id(def v) {
  return usable(v) && !(v instanceof String && ((String) v).equals('host'));
}

def of = ctx.falco?.output_fields;
if (of == null) { return; }

if (usable_container_id(of['container.id']) || usable_container_id(of['container.name'])) {
  if (!(ctx.container instanceof Map)) { ctx.container = [:]; }
  if (usable_container_id(of['container.id']) && ctx.container.id == null) {
    ctx.container.id = of['container.id'];
  }
  if (usable_container_id(of['container.name']) && ctx.container.name == null) {
    ctx.container.name = of['container.name'];
  }
}

if (usable(of['proc.name']) || usable(of['proc.cmdline'])
    || usable(of['proc.exepath']) || usable(of['proc.pname'])) {
  if (!(ctx.process instanceof Map)) { ctx.process = [:]; }
  if (usable(of['proc.name']) && ctx.process.name == null) {
    ctx.process.name = of['proc.name'];
  }
  if (usable(of['proc.cmdline']) && ctx.process.command_line == null) {
    ctx.process.command_line = of['proc.cmdline'];
  }
  if (usable(of['proc.exepath']) && ctx.process.executable == null) {
    ctx.process.executable = of['proc.exepath'];
  }
  if (usable(of['proc.pname'])) {
    if (!(ctx.process.parent instanceof Map)) { ctx.process.parent = [:]; }
    if (ctx.process.parent.name == null) { ctx.process.parent.name = of['proc.pname']; }
  }
}

if (usable(of['user.name']) || usable(of['user.uid'])) {
  if (!(ctx.user instanceof Map)) { ctx.user = [:]; }
  if (usable(of['user.name']) && ctx.user.name == null) {
    ctx.user.name = of['user.name'];
  }
  if (usable(of['user.uid']) && ctx.user.id == null) {
    ctx.user.id = String.valueOf(of['user.uid']);
  }
}
""".strip()

DESCRIPTION = (
    "Normalize Falco's output_fields onto the ECS entity fields the alerts index maps. Falco "
    "is ingested through a Fleet custom-logs input whose only processing is "
    "`decode_json_fields` into `falco.*` (playground-v2/docs/runbook.md §Falco), so the "
    "entities that actually discriminate a container-runtime alert — the container, the "
    "process, the command line — exist ONLY under `falco.output_fields.*`. That namespace is "
    "not mapped in `.internal.alerts-security.alerts-default-*`: `_field_caps` for `falco.*` "
    "there returns zero fields, so a detection alert carries those values in `_source` while "
    "no query can reach them, and a term on one returns `total: 0` with no error — "
    "indistinguishable from 'this entity has no other alerts' (issue #867, live validation "
    "2026-08-13). Copying them onto ECS fields the alerts index already maps makes the alert "
    "queryable by the entities it is about."
)

SCRIPT_DESC = (
    "A SCRIPT rather than `set` + `copy_from`: `output_fields` is an object whose KEYS contain "
    "literal dots (`{\"container.id\": \"...\"}`), while `copy_from` resolves its argument as a "
    "PATH through nested objects — so `falco.output_fields.container.id` walks to "
    "output_fields->container->id, finds nothing, and copies nothing, silently. Verified live: "
    "with the copy_from form attached and running, 31 new documents landed carrying zero ECS "
    "entity fields. Reading the key directly is the only form that addresses it. Existing "
    "values are never overwritten, and Falco's `<NA>` placeholder is skipped rather than "
    "copied — it is not an entity, and a literal '<NA>' user would correlate against every "
    "other unattributed event."
)

spec = {
    "description": DESCRIPTION,
    "processors": [
        {"script": {"description": SCRIPT_DESC, "lang": "painless", "source": SCRIPT}}
    ],
    "on_failure": [
        {"append": {"field": "error.message",
                    "value": "falco-ecs-entities: {{{ _ingest.on_failure_message }}}"}}
    ],
}

out = pathlib.Path(__file__).resolve().parents[1] / "playground-v2/ingest/falco-ecs-entities.json"
out.write_text(json.dumps(spec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
print("wrote", out)
