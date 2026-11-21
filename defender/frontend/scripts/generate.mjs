// The generated sources (#1161 S2, #1540 F1 a, F3): the shape list's file becomes the router's types and patterns, and
// the API's OpenAPI document becomes the API's types and the paged reads' body schemas. Both inputs are named in
// package.json's `defender.inputs` (PR6) and read from there, never from a copy. `generate()` is run first by every
// command (`scripts/run.mjs`).
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { _ } from "ajv";
import Ajv2020 from "ajv/dist/2020.js";
import standaloneCode from "ajv/dist/standalone/index.js";
import openapiTS, { astToString } from "openapi-typescript";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const generatedDir = path.join(root, "src", "generated");
/** A `{name}` template segment: a placeholder. */
const PLACEHOLDER = /^\{([a-z]+)\}$/;

/** An input the generator refuses: its message is the problem reported. */
class Refused extends Error {}
function refuse(message) {
  throw new Refused(message);
}

/** The file package.json's `defender.inputs` names `name` by (PR6: every file read from outside this folder is
 * named). */
function declaredInput(name) {
  const declared = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")).defender?.inputs;
  if (!Array.isArray(declared)) refuse("package.json must name the build's inputs in `defender.inputs`");
  const entry = declared.find((item) => typeof item === "string" && path.basename(item) === name);
  if (entry === undefined) refuse(`package.json's defender.inputs does not name ${name}`);
  return path.resolve(root, entry);
}

function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    return refuse(`cannot read ${file}: ${error.message}`);
  }
}

// The file holds no regular expression (addresses.py says the same): a placeholder is a list of pieces over named
// alphabets, each an explicit list of segment characters; a piece is literal text or [alphabet, count] /
// [alphabet, least, most]. Each placeholder's pattern is made from its pieces, as the API's reader makes it.
const SEGMENT_CHARACTER = /^[A-Za-z0-9_-]$/;
const segmentText = (text) =>
  typeof text === "string" && text !== "" && [...text].every((c) => SEGMENT_CHARACTER.test(c));
const isCount = (value) => Number.isInteger(value) && value >= 1;
const escapeCharacter = (c) => (c === "-" ? "\\-" : c);
const escapeLiteral = (text) => text.replace(/[\\^$.*+?()[\]{}|/-]/g, "\\$&");

/** Each placeholder's pattern, from its pieces. */
function placeholderPatterns(alphabets, placeholders) {
  if (typeof alphabets !== "object" || alphabets === null || Array.isArray(alphabets))
    refuse("addresses.json must hold `alphabets` (an object)");
  for (const [name, characters] of Object.entries(alphabets)) {
    if (!segmentText(characters))
      refuse(`alphabet ${name} must list segment characters only (letters, digits, _ and -)`);
  }
  const patterns = {};
  for (const [name, pieces] of Object.entries(placeholders)) {
    if (!Array.isArray(pieces) || pieces.length === 0) refuse(`placeholder ${name} must be a non-empty list of pieces`);
    const parts = [];
    for (const piece of pieces) {
      if (segmentText(piece)) {
        parts.push([...piece].map(escapeCharacter).join(""));
      } else if (
        Array.isArray(piece) &&
        (piece.length === 2 || piece.length === 3) &&
        typeof piece[0] === "string" &&
        Object.hasOwn(alphabets, piece[0]) &&
        piece.slice(1).every(isCount) &&
        piece[1] <= piece[piece.length - 1]
      ) {
        const counts = piece.length === 2 || piece[1] === piece[2] ? `${piece[1]}` : `${piece[1]},${piece[2]}`;
        parts.push(`[${[...alphabets[piece[0]]].map(escapeCharacter).join("")}]{${counts}}`);
      } else {
        refuse(
          `placeholder ${name} has a piece that is neither text of segment characters nor ` +
            `[a known alphabet, a count of at least 1, optionally a larger one]: ${JSON.stringify(piece)}`,
        );
      }
    }
    patterns[name] = parts.join("");
  }
  return patterns;
}

/** Each shape checked, with its whole pattern (`^(?:...)$`, no flags: literals escaped, each placeholder its pattern in
 * a group of its own, so a match holds the values in the template's order) and its number of placeholders. */
function compiledShapes(shapes, patterns) {
  const names = new Set();
  return shapes.map((shape) => {
    if (
      typeof shape?.name !== "string" ||
      typeof shape.template !== "string" ||
      typeof shape.returnable !== "boolean"
    ) {
      refuse(`a shape needs a string name, a string template and a boolean returnable: ${JSON.stringify(shape)}`);
    }
    if (names.has(shape.name)) refuse(`duplicate shape name ${shape.name}`);
    names.add(shape.name);
    if (!shape.template.startsWith("/")) refuse(`template ${shape.template} does not start with /`);
    let count = 0;
    const parts = shape.template
      .split("/")
      .slice(1)
      .map((segment) => {
        const named = PLACEHOLDER.exec(segment);
        if (named) {
          if (!Object.hasOwn(patterns, named[1]))
            refuse(`template ${shape.template} names an unknown placeholder ${named[1]}`);
          count += 1;
          return `(${patterns[named[1]]})`;
        }
        if (!/^[\x20-\x7e]*$/.test(segment) || /[{}]/.test(segment))
          refuse(`template ${shape.template} has a bad literal segment ${JSON.stringify(segment)}`);
        return escapeLiteral(segment);
      });
    return { ...shape, pattern: new RegExp(`^(?:/${parts.join("/")})$`), count };
  });
}

/** `src/generated/shapes.ts`: the shapes, their patterns, the type of each one's values, and the literal addresses. */
function shapesModule(compiled) {
  const key = (name) => JSON.stringify(name);
  const entries = (make) => compiled.map((shape) => `  ${key(shape.name)}: ${make(shape)},\n`).join("");
  const literal = compiled.filter((shape) => shape.count === 0);
  const list = compiled.map(({ name, template, returnable }) => ({ name, template, returnable }));
  return (
    `// Generated by scripts/generate.mjs from ../api/addresses.json; do not edit.\n` +
    `export const SHAPES = ${JSON.stringify(list, null, 2)} as const;\n` +
    `export type ShapeName = (typeof SHAPES)[number]["name"];\n` +
    `/** Each shape's whole pattern; a placeholder is a group, in the template's order. */\n` +
    `export const PATTERNS: { readonly [K in ShapeName]: RegExp } = {\n${entries((shape) => String(shape.pattern))}};\n` +
    `/** Each shape's placeholder values, in the template's order. */\n` +
    `export interface ShapeValues {\n` +
    compiled
      .map((shape) => `  ${key(shape.name)}: readonly [${Array(shape.count).fill("string").join(", ")}];\n`)
      .join("") +
    `}\n` +
    `/** Each shape's values from a match of its pattern: \`value(i)\` is its i-th group. */\n` +
    `export const VALUES: { readonly [K in ShapeName]: (value: (index: number) => string) => ShapeValues[K] } = {\n` +
    entries(
      (shape) =>
        `(${shape.count === 0 ? "" : "value"}) => [${Array.from({ length: shape.count }, (_, i) => `value(${i})`).join(", ")}]`,
    ) +
    `};\n` +
    `/** The shapes with no placeholder: each has one address, its template. */\n` +
    `export type LiteralShape = ${literal.map((shape) => key(shape.name)).join(" | ") || "never"};\n` +
    `export const LITERAL_ADDRESSES: { readonly [K in LiteralShape]: string } = {\n` +
    literal.map((shape) => `  ${key(shape.name)}: ${JSON.stringify(shape.template)},\n`).join("") +
    `};\n`
  );
}

/** `src/generated/api.ts`: the API's types, from the document the API's own app produced (PR3). */
async function apiModule(document) {
  return `// Generated by scripts/generate.mjs from ../api/openapi.json; do not edit.\n/* eslint-disable */\n${astToString(await openapiTS(document))}`;
}

/** What of a schema the shell's runtime check of a later page reads (`src/shell/page.ts`): what a value is, not how it
 * is described or bounded. */
const CHECKED_KEYWORDS = new Set([
  "$ref",
  "type",
  "enum",
  "const",
  "anyOf",
  "items",
  "properties",
  "required",
  "format",
]);
const COMPONENT = /^#\/components\/schemas\/(.+)$/;
/** The keyword a `date-time` format becomes: a string `Date.parse` reads (as `format` was checked before r3.4). */
const DATE_TIME = "x-date-time";

/** `schema` with only the checked keywords (every property kept), and the components it names added to `named`. */
function checkedSchema(document, schema, named) {
  if (typeof schema !== "object" || schema === null) return schema;
  const kept = {};
  for (const [keyword, value] of Object.entries(schema)) {
    if (!CHECKED_KEYWORDS.has(keyword)) continue;
    if (keyword === "$ref") {
      const name = COMPONENT.exec(value)?.[1];
      if (name === undefined) refuse(`openapi.json: a $ref the generator does not follow: ${value}`);
      if (!Object.hasOwn(named, name)) {
        named[name] = null; // taken before it is made, so a schema that names itself ends
        named[name] = checkedSchema(document, document.components?.schemas?.[name], named);
      }
      kept[keyword] = value;
    } else if (keyword === "properties") {
      kept[keyword] = Object.fromEntries(
        Object.entries(value).map(([field, each]) => [field, checkedSchema(document, each, named)]),
      );
    } else if (keyword === "anyOf") {
      kept[keyword] = value.map((each) => checkedSchema(document, each, named));
    } else if (keyword === "items") {
      kept[keyword] = checkedSchema(document, value, named);
    } else if (keyword === "format") {
      // The one format checked, as the screens read a time (`Date.parse`); Ajv's own formats are not loaded.
      if (value === "date-time") kept[DATE_TIME] = true;
    } else {
      kept[keyword] = value;
    }
  }
  return kept;
}

/** The 200 body's schema of every GET whose body is a page (`{items, next_cursor}`), and the components they name. */
function pagedBodies(document) {
  const named = {};
  const bodies = {};
  for (const [key, item] of Object.entries(document.paths ?? {})) {
    const schema = item?.get?.responses?.["200"]?.content?.["application/json"]?.schema;
    const ref = COMPONENT.exec(schema?.$ref ?? "")?.[1];
    const resolved = ref === undefined ? schema : document.components?.schemas?.[ref];
    const properties = resolved?.properties;
    if (properties?.items?.type === "array" && properties.next_cursor !== undefined) {
      bodies[key] = checkedSchema(document, schema, named);
    }
  }
  return { bodies, named };
}

/** `src/generated/pages.ts`: a validator for each paged read's 200 body, compiled by Ajv from the document's own
 * schemas (#1581 r3.4), as standalone code the shell checks a later page with. No Ajv at runtime: the output imports
 * nothing (`refuse` if it ever does). */
function pagesModule(document) {
  const { bodies, named } = pagedBodies(document);
  const keys = Object.keys(bodies).sort();
  const ajv = new Ajv2020({
    code: { source: true, esm: true },
    strict: false,
    validateFormats: false,
    messages: false,
  });
  ajv.addKeyword({
    keyword: DATE_TIME,
    schemaType: "boolean",
    code(cxt) {
      cxt.fail(_`typeof ${cxt.data} == "string" && Number.isNaN(Date.parse(${cxt.data}))`);
    },
  });
  ajv.addSchema({
    $id: "pages",
    components: { schemas: named },
    pages: Object.fromEntries(keys.map((k, i) => [`p${i}`, bodies[k]])),
  });
  const code = standaloneCode(ajv, Object.fromEntries(keys.map((_key, i) => [`p${i}`, `pages#/pages/p${i}`])));
  if (/\brequire\(|^\s*import\s/m.test(code)) refuse("the page validators import a runtime module");
  const table = keys.map((key, i) => `  ${JSON.stringify(key)}: p${i},`).join("\n");
  return (
    `// Generated by scripts/generate.mjs from ../api/openapi.json by Ajv; do not edit.\n` +
    `// @ts-nocheck\n` +
    `${code}\n` +
    `/** Each paged read's 200 body validator, by its path key. */\n` +
    `export const VALIDATORS: { readonly [key: string]: (data: unknown) => boolean } = {\n${table}\n};\n`
  );
}

/** One address of each shape the app serves, its placeholders filled with the shortest value of their pieces: the
 * addresses a screen's markup is read from (the source check's rule 5). Run after `generate`, which refuses an input
 * these could not be made from. */
export function sampleAddresses() {
  const { alphabets, placeholders, shapes } = readJson(declaredInput("addresses.json"));
  const sample = (name) =>
    placeholders[name].map((piece) => (typeof piece === "string" ? piece : alphabets[piece[0]][0].repeat(piece[1])));
  return shapes.map((shape) => shape.template.replace(/\{([^}]*)\}/g, (_, name) => sample(name).join("")));
}

/** Write the generated modules; the problems with the inputs, or none. Nothing is written when an input is refused. */
export async function generate() {
  try {
    const list = readJson(declaredInput("addresses.json"));
    const api = readJson(declaredInput("openapi.json"));
    if (typeof list?.placeholders !== "object" || list.placeholders === null || !Array.isArray(list.shapes)) {
      refuse("addresses.json must hold `placeholders` (an object) and `shapes` (an array)");
    }
    const shapes = shapesModule(compiledShapes(list.shapes, placeholderPatterns(list.alphabets, list.placeholders)));
    const types = await apiModule(api);
    const pages = pagesModule(api);
    mkdirSync(generatedDir, { recursive: true });
    writeFileSync(path.join(generatedDir, "shapes.ts"), shapes);
    writeFileSync(path.join(generatedDir, "api.ts"), types);
    writeFileSync(path.join(generatedDir, "pages.ts"), pages);
    return [];
  } catch (error) {
    if (error instanceof Refused) return [error.message];
    throw error;
  }
}
