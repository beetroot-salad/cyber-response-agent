// The frontend's addresses (#1161 S2): the shapes in ../api/addresses.json (via the build), compiled to the one
// membership meaning the API's reader has: a value is a member when the WHOLE string matches a shape, as ASCII,
// case-sensitive, with no decoding, normalising or trailing-/ tolerance. The build writes each shape's whole pattern;
// nothing here parses a template. No DOM here: Node loads this file's build.
import { PATTERNS, SHAPES, VALUES, type ShapeName, type ShapeValues } from "./generated/shapes";

export type { ShapeName, ShapeValues };

const COMPILED: readonly (readonly [ShapeName, RegExp])[] = SHAPES.map((shape) => [shape.name, new RegExp(PATTERNS[shape.name])] as const);

/** The shapes a person may be sent back to after sign-in. */
export const RETURNABLE: ReadonlySet<ShapeName> = new Set(SHAPES.filter((shape) => shape.returnable).map((shape) => shape.name));

/** The address of a shape with no placeholder (a literal template). */
export function literalAddress(name: ShapeName): string {
  const shape = SHAPES.find((candidate) => candidate.name === name);
  if (shape === undefined || shape.template.includes("{")) throw new Error(`${name} has no literal address`);
  return shape.template;
}

/** The name of the shape `value` is a member of, or null. */
export function match(value: string): ShapeName | null {
  for (const [name, pattern] of COMPILED) {
    if (pattern.test(value)) return name;
  }
  return null;
}

/** The placeholder values of `value`, a member of shape `name`, in the template's order. Throws when it is not one: the
 * caller had the shape from `match`, so that is a bug, not an address. */
export function valuesOf<N extends ShapeName>(name: N, value: string): ShapeValues[N] {
  const found = new RegExp(PATTERNS[name]).exec(value);
  if (found === null) throw new Error(`${value} is not a ${name} address`);
  return VALUES[name]((index) => {
    const group = found[index + 1];
    if (group === undefined) throw new Error(`${name}'s pattern has no group ${index + 1}`);
    return group;
  });
}
