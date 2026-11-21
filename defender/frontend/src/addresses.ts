// The frontend's addresses (#1161 S2): the shapes in ../api/addresses.json (via the build), compiled to the one
// membership meaning the API's reader has: a value is a member when the WHOLE string matches a shape, as ASCII,
// case-sensitive, with no decoding, normalising or trailing-/ tolerance. The build writes each shape's whole pattern;
// membership is never judged from a template here (`addressOf` fills one, then checks the result against the shape's
// pattern). No DOM here: Node loads this file's build. One function makes an address that is not the app's own:
// `repoLink`, the tenant repository's page on the forge, which only takes a value the shell has checked.
import type { RepoAddress } from "./shell/provider";
import {
  LITERAL_ADDRESSES,
  PATTERNS,
  SHAPES,
  VALUES,
  type LiteralShape,
  type ShapeName,
  type ShapeValues,
} from "./generated/shapes";

export type { ShapeName, ShapeValues };

/** The shapes a person may be sent back to after sign-in. */
export const RETURNABLE: ReadonlySet<ShapeName> = new Set(
  SHAPES.filter((shape) => shape.returnable).map((shape) => shape.name),
);

/** The one address of a shape with no placeholder (its template). A shape with placeholders is not a `LiteralShape`. */
export function literalAddress(name: LiteralShape): string {
  return LITERAL_ADDRESSES[name];
}

/** A `{name}` template segment: a placeholder (as the build reads the templates). */
const PLACEHOLDER = /^\{[a-z]+\}$/;

/** The address of shape `name` with `values` in its placeholders, in the template's order (as `valuesOf` answers
 * them). Throws when the result is not a member of the shape (a value outside its placeholder's alphabet, or the wrong
 * number of values): an address that `match` would not read back is never made. */
export function addressOf<N extends ShapeName>(name: N, values: ShapeValues[N]): string {
  const shape = SHAPES.find((each) => each.name === name);
  if (shape === undefined) throw new Error(`no shape ${name}`);
  let used = 0;
  const address = shape.template
    .split("/")
    .map((segment) => {
      if (!PLACEHOLDER.test(segment)) return segment;
      const value = values[used];
      used += 1;
      if (value === undefined) throw new Error(`${name} needs more than ${values.length} values`);
      return value;
    })
    .join("/");
  if (used !== values.length || !PATTERNS[name].test(address))
    throw new Error(`${JSON.stringify(values)} do not make a ${name} address`);
  return address;
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

/** The tenant repository's page on the forge, for a link: the one address this module makes that is not the app's own.
 * It takes only a `RepoAddress`, which only the shell makes, after checking it is an absolute http or https address on
 * another origin (`shell/repo.ts`); a screen gets one from `useRepoAddress`. */
export function repoLink(address: RepoAddress): string {
  return address;
}
