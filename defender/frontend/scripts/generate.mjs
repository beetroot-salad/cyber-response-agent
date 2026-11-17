// The generated sources (#1161 S2, #1540 F1 a, F3): the shape list's file -> the router's types, and the API's OpenAPI
// document -> the API's types. Both inputs are named in package.json's `defender.inputs` (PR6) and read from there, never
// from a copy. Run by `bun run generate`, and first by `build`, `check`, `test` and `dev`.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import openapiTS, { astToString } from "openapi-typescript";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const generatedDir = path.join(root, "src", "generated");

function fail(message) {
  console.error(`build: ${message}`);
  process.exit(1);
}

// PR6: every file the build reads from outside this folder is named here.
function declaredInput(name) {
  const declared = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"))?.defender?.inputs;
  if (!Array.isArray(declared)) fail("package.json must name the build's inputs in `defender.inputs`");
  const entry = declared.find((item) => typeof item === "string" && path.basename(item) === name);
  if (entry === undefined) fail(`package.json's defender.inputs does not name ${name}`);
  return path.resolve(root, entry);
}
const listFile = declaredInput("addresses.json");
const documentFile = declaredInput("openapi.json");
const generated = path.join(generatedDir, "shapes.ts");

// 1. The shape list, read from the file the API reads (never a copy), and checked against the bound format.
let document;
try {
  document = JSON.parse(readFileSync(listFile, "utf8"));
} catch (error) {
  fail(`cannot read ${listFile}: ${error.message}`);
}
const placeholders = document?.placeholders;
const shapes = document?.shapes;
if (typeof placeholders !== "object" || placeholders === null || !Array.isArray(shapes)) {
  fail("addresses.json must hold `placeholders` (an object) and `shapes` (an array)");
}
// The file holds no regular expression (addresses.py says the same): a placeholder is a list of pieces over named
// alphabets, each an explicit list of segment characters; a piece is literal text or [alphabet, count] /
// [alphabet, least, most]. The build makes each placeholder's pattern from its pieces, as the API's reader does.
const SEGMENT_CHARACTER = /^[A-Za-z0-9_-]$/;
const segmentText = (text) => typeof text === "string" && text !== "" && [...text].every((c) => SEGMENT_CHARACTER.test(c));
const isCount = (value) => Number.isInteger(value) && value >= 1;
const escapeCharacter = (c) => (c === "-" ? "\\-" : c);
const alphabets = document?.alphabets;
if (typeof alphabets !== "object" || alphabets === null || Array.isArray(alphabets)) fail("addresses.json must hold `alphabets` (an object)");
for (const [name, characters] of Object.entries(alphabets)) {
  if (!segmentText(characters)) fail(`alphabet ${name} must list segment characters only (letters, digits, _ and -)`);
}
const patterns = {};
for (const [name, pieces] of Object.entries(placeholders)) {
  if (!Array.isArray(pieces) || pieces.length === 0) fail(`placeholder ${name} must be a non-empty list of pieces`);
  const parts = [];
  for (const piece of pieces) {
    if (segmentText(piece)) {
      parts.push([...piece].map(escapeCharacter).join(""));
    } else if (Array.isArray(piece) && (piece.length === 2 || piece.length === 3) && typeof piece[0] === "string" &&
               Object.hasOwn(alphabets, piece[0]) && piece.slice(1).every(isCount) && piece[1] <= piece[piece.length - 1]) {
      const counts = piece.length === 2 || piece[1] === piece[2] ? `${piece[1]}` : `${piece[1]},${piece[2]}`;
      parts.push(`[${[...alphabets[piece[0]]].map(escapeCharacter).join("")}]{${counts}}`);
    } else {
      fail(`placeholder ${name} has a piece that is neither text of segment characters nor ` +
           `[a known alphabet, a count of at least 1, optionally a larger one]: ${JSON.stringify(piece)}`);
    }
  }
  patterns[name] = parts.join("");
}
const names = new Set();
for (const shape of shapes) {
  if (typeof shape?.name !== "string" || typeof shape.template !== "string" || typeof shape.returnable !== "boolean") {
    fail(`a shape needs a string name, a string template and a boolean returnable: ${JSON.stringify(shape)}`);
  }
  if (names.has(shape.name)) fail(`duplicate shape name ${shape.name}`);
  names.add(shape.name);
  if (!shape.template.startsWith("/")) fail(`template ${shape.template} does not start with /`);
  for (const segment of shape.template.split("/").slice(1)) {
    const named = /^\{([a-z]+)\}$/.exec(segment);
    if (named) {
      if (!Object.hasOwn(patterns, named[1])) fail(`template ${shape.template} names an unknown placeholder ${named[1]}`);
    } else if (!/^[\x20-\x7e]*$/.test(segment) || /[{}]/.test(segment)) {
      fail(`template ${shape.template} has a bad literal segment ${JSON.stringify(segment)}`);
    }
  }
}
mkdirSync(generatedDir, { recursive: true });
writeFileSync(
  generated,
  `// Generated by scripts/generate.mjs from ../api/addresses.json; do not edit.\n` +
    `export const PLACEHOLDERS = ${JSON.stringify(patterns, null, 2)} as const; // patterns made from the pieces\n` +
    `export const SHAPES = ${JSON.stringify(shapes, null, 2)} as const;\n`,
);


// 2. The API's types, from the document the API's own app produced (PR3).
let apiDocument;
try {
  apiDocument = JSON.parse(readFileSync(documentFile, "utf8"));
} catch (error) {
  fail(`cannot read ${documentFile}: ${error.message}`);
}
const ast = await openapiTS(apiDocument);
writeFileSync(
  path.join(generatedDir, "api.ts"),
  `// Generated by scripts/generate.mjs from ../api/openapi.json; do not edit.\n/* eslint-disable */\n${astToString(ast)}`,
);
