// The frontend's addresses (#1161 S2): the shapes in ../api/addresses.json (via the build), compiled to the one
// membership meaning the API's reader has: a value is a member when the WHOLE string matches a shape, as ASCII,
// case-sensitive, with no decoding, normalising or trailing-/ tolerance. No DOM here: Node loads this file's build.
import { PLACEHOLDERS, SHAPES } from "./generated/shapes";

export type ShapeName = (typeof SHAPES)[number]["name"];

const SEGMENT = /^\{([a-z]+)\}$/;

function escapeLiteral(text: string): string {
  return text.replace(/[\\^$.*+?()[\]{}|/-]/g, "\\$&");
}

/** A template as `^(?:...)$`, no flags: literals escaped, each `{name}` replaced by that placeholder's grammar. */
function compile(template: string): RegExp {
  const parts = template
    .split("/")
    .slice(1)
    .map((segment) => {
      const named = SEGMENT.exec(segment);
      const grammar = named === null ? undefined : (PLACEHOLDERS as Record<string, string>)[named[1] ?? ""];
      return grammar ?? escapeLiteral(segment);
    });
  return new RegExp(`^(?:/${parts.join("/")})$`);
}

const COMPILED: readonly (readonly [ShapeName, RegExp])[] = SHAPES.map((shape) => [shape.name, compile(shape.template)] as const);

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
