// A later page's answer, checked against what the document says its body is (#1581 G8). Page 1's answer is trusted to
// match the document, as every read's is (PR3): a body that breaks it is a fault, and the boundary shows the error
// state. A later page's is checked, because a failure there must stay that page's state with the rows already shown:
// one that is not a page of the read's items, field types included, is that page's failure, never thrown while those
// rows are drawn. The schemas are the document's own (`src/generated/pages.ts`), so nothing here describes a response
// by hand.
import { COMPONENTS, PAGE_BODIES } from "../generated/pages";

const COMPONENT = /^#\/components\/schemas\/(.+)$/;

/** The fields of `value` by name when it is a non-null object that is not an array; null when it is not one. */
function fieldsOf(value: unknown): Map<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  const entries: [string, unknown][] = Object.entries(value);
  return new Map(entries);
}

/** True when `value` is of the JSON Schema type `type`. */
function isOfType(type: unknown, value: unknown): boolean {
  switch (type) {
    case "string":
      return typeof value === "string";
    case "integer":
      return Number.isInteger(value);
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "boolean":
      return typeof value === "boolean";
    case "null":
      return value === null;
    case "array":
      return Array.isArray(value);
    case "object":
      return fieldsOf(value) !== null;
    default:
      return false;
  }
}

/** True when `value` is what `schema` says: its `$ref`, `type`, `enum`, `const`, `anyOf`, `items`, `properties`,
 * `required` and a `date-time` format (a time `Date.parse` reads, as the screens read it). What only describes or
 * bounds a value (a pattern, a length) is not checked: a value that breaks those is still the value its screen
 * shows. */
function matches(schema: unknown, value: unknown): boolean {
  if (schema === true) return true;
  const rule = fieldsOf(schema);
  if (rule === null) return false;
  const ref = rule.get("$ref");
  if (ref !== undefined) {
    const name = typeof ref === "string" ? COMPONENT.exec(ref)?.[1] : undefined;
    if (name === undefined || !Object.hasOwn(COMPONENTS, name) || !matches(COMPONENTS[name], value)) return false;
  }
  const type = rule.get("type");
  if (type !== undefined) {
    const types: readonly unknown[] = Array.isArray(type) ? type : [type];
    if (!types.some((each) => isOfType(each, value))) return false;
  }
  const choices = rule.get("enum");
  if (Array.isArray(choices)) {
    const listed: readonly unknown[] = choices;
    if (!listed.includes(value)) return false;
  }
  if (rule.has("const") && rule.get("const") !== value) return false;
  const anyOf = rule.get("anyOf");
  if (Array.isArray(anyOf)) {
    const options: readonly unknown[] = anyOf;
    if (!options.some((option) => matches(option, value))) return false;
  }
  if (rule.get("format") === "date-time" && typeof value === "string" && Number.isNaN(Date.parse(value))) return false;
  if (Array.isArray(value) && rule.has("items")) {
    const entries: readonly unknown[] = value;
    const items = rule.get("items");
    if (!entries.every((entry) => matches(items, entry))) return false;
  }
  const fields = fieldsOf(value);
  if (fields !== null) {
    const required = rule.get("required");
    if (Array.isArray(required)) {
      const names: readonly unknown[] = required;
      if (!names.every((name) => typeof name === "string" && fields.has(name))) return false;
    }
    const properties = rule.get("properties");
    for (const [name, property] of fieldsOf(properties) ?? []) {
      if (fields.has(name) && !matches(property, fields.get(name))) return false;
    }
  }
  return true;
}

/** True when `body` is what the document says the paged read `key` answers with on a 200; false for a key the document
 * names no paged body for. */
export function isPageOf(key: string, body: unknown): boolean {
  return Object.hasOwn(PAGE_BODIES, key) && matches(PAGE_BODIES[key], body);
}
