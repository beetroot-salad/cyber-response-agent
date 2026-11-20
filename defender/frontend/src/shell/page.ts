// A later page's answer, checked against what the document says its body is (#1581 G8). Page 1's answer is trusted to
// match the document, as every read's is (PR3): a body that breaks it is a fault, and the boundary shows the error
// state. A later page's is checked, because a failure there must stay that page's state with the rows already shown:
// one that is not a page of the read's items, field types included, is that page's failure, never thrown while those
// rows are drawn. The validators are compiled by Ajv from the document's own schemas when the code is generated
// (`src/generated/pages.ts`, r3.4), so nothing here describes a response by hand. They check what a value is (types,
// enums, required fields, refs, a `date-time` that `Date.parse` reads), not how it is described or bounded.
import { VALIDATORS } from "../generated/pages";

/** True when `body` is what the document says the paged read `key` answers with on a 200; false for a key the document
 * names no paged body for. */
export function isPageOf(key: string, body: unknown): boolean {
  const validate = Object.hasOwn(VALIDATORS, key) ? VALIDATORS[key] : undefined;
  return validate?.(body) ?? false;
}
