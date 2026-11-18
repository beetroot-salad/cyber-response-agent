// The frontend's addresses (#1161 S2): the shapes in ../api/addresses.json (via the build), compiled to the one
// membership meaning the API's reader has: a value is a member when the WHOLE string matches a shape, as ASCII,
// case-sensitive, with no decoding, normalising or trailing-/ tolerance. The build writes each shape's whole pattern;
// nothing here parses a template. No DOM here: Node loads this file's build.
import { LITERAL_ADDRESSES, PATTERNS, SHAPES, VALUES, type LiteralShape, type ShapeName, type ShapeValues } from "./generated/shapes";

export type { ShapeName, ShapeValues };

/** The shapes a person may be sent back to after sign-in. */
export const RETURNABLE: ReadonlySet<ShapeName> = new Set(SHAPES.filter((shape) => shape.returnable).map((shape) => shape.name));

/** The one address of a shape with no placeholder (its template). A shape with placeholders is not a `LiteralShape`. */
export function literalAddress(name: LiteralShape): string {
  return LITERAL_ADDRESSES[name];
}

/** The name of the shape `value` is a member of, or null. */
export function match(value: string): ShapeName | null {
  return SHAPES.find((shape) => PATTERNS[shape.name].test(value))?.name ?? null;
}

/** The placeholder values of `value`, a member of shape `name`, in the template's order. Throws when it is not one: the
 * caller had the shape from `match`, so that is a bug, not an address. */
export function valuesOf<N extends ShapeName>(name: N, value: string): ShapeValues[N] {
  const found = PATTERNS[name].exec(value);
  if (found === null) throw new Error(`${value} is not a ${name} address`);
  return VALUES[name]((index) => {
    const group = found[index + 1];
    if (group === undefined) throw new Error(`${name}'s pattern has no group ${index + 1}`);
    return group;
  });
}
