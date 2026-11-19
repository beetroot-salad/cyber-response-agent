// The type check and the source check (#1540 F1 b, F8). A function only: `scripts/run.mjs` calls it.
//
// 1. The whole project (screens, shell and unit-test files alike) is type-checked with the browser library.
// 2. Everything outside `src/shell/` is type-checked again without it (`tsconfig.screens.json`), with only what
//    `screens-env.d.ts` declares. There `window`, `document`, `fetch`, storage and `location` do not exist, and React's
//    types give a DOM element no members beyond those declared, so no script there can reach the network, storage or
//    the address, however it is spelled (PR2). The compiler is the boundary; nothing below lists the browser's names.
// 3. Everywhere (shell included, the generated types aside) the compiler is kept honest: no `any`, no value of type
//    `any` (but one given the type `unknown` where it is made, as `JSON.parse`'s), no comment that switches type
//    checking off, and no type assertion but `as const`. A type predicate (`x is T`, `asserts x`) is an assertion too:
//    the compiler never checks its body. In the shell, an assertion is allowed only under a `// trust: <reason>`
//    comment on the line above: the step the compiler cannot check, said out loud.
// 4. Outside the shell: imports from the shell only of `src/shell/provider` (types from anywhere in it), no import of a
//    test file into the app, and no `/api/auth/` path in a string. That last one is a guard against an accident, not a
//    boundary: a string can be built any way.
// 5. Outside the shell, the markup the browser sends requests for: an address attribute (`src`, `href`, `action`, ...)
//    is a path written out from the root and not under `/api`, an imported asset's URL, or made by `src/addresses.ts`
//    (which makes only the app's own addresses). What could carry an address past that is refused: a spread onto an
//    HTML element, raw HTML, an inline style, and React's element-making functions called directly. So a screen's
//    markup makes the browser request no API path: the shell's client, and its 401 policy, sends every one.
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const AUTH_PREFIX = "/api/auth/";
/** The attributes whose value the browser requests or navigates to. */
const ADDRESS_ATTRIBUTES = new Set([
  "src",
  "srcSet",
  "href",
  "action",
  "formAction",
  "poster",
  "data",
  "ping",
  "cite",
  "background",
  "xlinkHref",
]);
/** Markup that could carry an address past the address-attribute rule. */
const OPAQUE_ATTRIBUTES = new Set(["dangerouslySetInnerHTML", "style"]);
/** React's element-making functions and runtimes, which take attributes as a plain object. */
const ELEMENT_MAKERS = new Set(["createElement", "cloneElement", "jsx", "jsxs", "jsxDEV"]);
const ELEMENT_RUNTIMES = new Set([
  "react/jsx-runtime",
  "react/jsx-dev-runtime",
  "react-dom",
  "react-dom/client",
  "react-dom/server",
]);
const ASSET = /\.(svg|png|jpe?g|gif|webp|avif|ico)$/;
const SCREENS_HINT =
  "(outside src/shell/ the browser library does not exist: src/shell/ owns the network, storage and the " +
  "address, and screens-env.d.ts declares what else a screen may use)";

function program(config) {
  const configPath = path.join(root, config);
  const read = ts.readConfigFile(configPath, ts.sys.readFile);
  if (read.error) return { problems: [`${config}: ${ts.flattenDiagnosticMessageText(read.error.messageText, "\n")}`] };
  const parsed = ts.parseJsonConfigFileContent(read.config, ts.sys, root, undefined, configPath);
  const made = ts.createProgram({ rootNames: parsed.fileNames, options: parsed.options });
  const problems = [];
  for (const diagnostic of ts.getPreEmitDiagnostics(made)) {
    const text = ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n");
    if (diagnostic.file && diagnostic.start !== undefined) {
      const { line } = diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start);
      problems.push(`${path.relative(root, diagnostic.file.fileName)}:${line + 1}: TS${diagnostic.code}: ${text}`);
    } else {
      problems.push(`TS${diagnostic.code}: ${text}`);
    }
  }
  return { program: made, problems };
}

/** True when the import or export moves only types (`import type`, `export type`, or every name marked `type`). */
function typeOnly(node) {
  if (ts.isExportDeclaration(node)) return node.isTypeOnly;
  if (ts.isCallExpression(node)) return false;
  const clause = node.importClause;
  if (!clause) return false; // `import "./x"`: runs the module
  if (clause.isTypeOnly) return true;
  const named = clause.namedBindings;
  return (
    !clause.name &&
    named !== undefined &&
    ts.isNamedImports(named) &&
    named.elements.length > 0 &&
    named.elements.every((element) => element.isTypeOnly)
  );
}

/** True for `x as const`, the one assertion that claims nothing about what a value is. */
function isConstAssertion(node) {
  return (
    ts.isTypeReferenceNode(node.type) && ts.isIdentifier(node.type.typeName) && node.type.typeName.text === "const"
  );
}

/** True when the `any`-typed `node` is given the type `unknown` where it is made (`const x: unknown =
 * JSON.parse(s)`). */
function madeUnknown(node) {
  const parent = node.parent;
  return (
    ts.isVariableDeclaration(parent) &&
    parent.initializer === node &&
    parent.type?.kind === ts.SyntaxKind.UnknownKeyword
  );
}

/** True when the line above `node` is a `// trust: <reason>` comment. */
function trusted(file, node) {
  const { line } = file.getLineAndCharacterOfPosition(node.getStart(file));
  if (line === 0) return false;
  const above = file.text.slice(
    file.getPositionOfLineAndCharacter(line - 1, 0),
    file.getPositionOfLineAndCharacter(line, 0),
  );
  return /^\s*\/\/ trust: \S/.test(above);
}

const SRC = path.join(root, "src") + path.sep;
const SHELL = path.join(root, "src", "shell") + path.sep;
const GENERATED = path.join(root, "src", "generated") + path.sep;
const PROVIDER_MODULE = path.join(root, "src", "shell", "provider");
const ADDRESSES_MODULE = path.join(root, "src", "addresses.ts");
const TEST_FILE = /\.test\.tsx?$/;

/** The app's own sources in `made` (not the generated types, not declaration files), in the shell or outside it. */
function sourcesOf(made, inShell) {
  return made.getSourceFiles().filter((file) => {
    const name = path.resolve(file.fileName);
    return (
      name.startsWith(SRC) &&
      !name.startsWith(GENERATED) &&
      !file.isDeclarationFile &&
      name.startsWith(SHELL) === inShell
    );
  });
}

/** Problems found in `file`, each `file:line: what`, with `hint` after it. */
function reporterFor(file, problems, hint) {
  const where = path.relative(root, path.resolve(file.fileName));
  return (position, what) => {
    const { line } = file.getLineAndCharacterOfPosition(
      typeof position === "number" ? position : position.getStart(file),
    );
    problems.push(`${where}:${line + 1}: ${what}${hint}`);
  };
}

/** The file `specifier` resolves to from `file`, or null when it resolves to none. */
function resolve(made, file, specifier) {
  const resolved = ts.resolveModuleName(specifier, file.fileName, made.getCompilerOptions(), ts.sys).resolvedModule;
  return resolved ? path.resolve(resolved.resolvedFileName) : null;
}

/** Rule 3, honesty, over the files of `made` in `part` ("shell" or "outside"): the problems found. */
function honesty(made, part) {
  const inShell = part === "shell";
  const checker = made.getTypeChecker();
  const problems = [];
  for (const file of sourcesOf(made, inShell)) {
    const report = reporterFor(file, problems, inShell ? "" : ` ${SCREENS_HINT}`);
    for (const match of file.text.matchAll(/@ts-(ignore|expect-error|nocheck)\b/g)) {
      report(match.index, `no comment may switch type checking off (${match[0]})`);
    }
    const visit = (node) => {
      if (
        (ts.isAsExpression(node) && !isConstAssertion(node)) ||
        ts.isTypeAssertionExpression(node) ||
        ts.isTypePredicateNode(node)
      ) {
        if (!(inShell && trusted(file, node))) {
          report(
            node,
            inShell
              ? "a type assertion needs a `// trust: <reason>` comment on the line above (only `as const` needs none)"
              : "no type assertion outside the shell (only `as const`): it could claim a value is anything",
          );
        }
      }
      if (node.kind === ts.SyntaxKind.AnyKeyword) report(node, "no `any`: it could hold anything");
      if (
        (ts.isCallExpression(node) ||
          ts.isNewExpression(node) ||
          ts.isPropertyAccessExpression(node) ||
          ts.isElementAccessExpression(node)) &&
        checker.getTypeAtLocation(node).flags & ts.TypeFlags.Any &&
        !madeUnknown(node)
      ) {
        report(node, "no value of type `any` (give it the type `unknown` where it is made): it could hold anything");
      }
      ts.forEachChild(node, visit);
    };
    visit(file);
  }
  return problems;
}

/** The import that binds `identifier` in `file`: its declaration, its module's text and the file it resolves to; or
 * null when no import binds it. */
function importOf(made, file, identifier) {
  const declaration = made.getTypeChecker().getSymbolAtLocation(identifier)?.declarations?.[0];
  let node = declaration;
  while (node && !ts.isImportDeclaration(node)) node = node.parent;
  if (!node || !ts.isStringLiteral(node.moduleSpecifier)) return null;
  const specifier = node.moduleSpecifier.text;
  return { declaration, specifier, target: resolve(made, file, specifier) };
}

/** True for an address attribute's value that can only be an app address or an asset (rule 5). */
function appAddress(made, file, value) {
  if (value === undefined) return true;
  if (ts.isStringLiteral(value)) {
    const text = value.text;
    return (text.startsWith("/") && !text.startsWith("//") && !/^\/api(\/|$)/i.test(text)) || text.startsWith("#");
  }
  if (!ts.isJsxExpression(value) || !value.expression) return false;
  const expression = value.expression;
  if (ts.isIdentifier(expression)) {
    const bound = importOf(made, file, expression);
    return bound !== null && ts.isImportClause(bound.declaration) && ASSET.test(bound.specifier);
  }
  if (ts.isCallExpression(expression) && ts.isIdentifier(expression.expression)) {
    return importOf(made, file, expression.expression)?.target === ADDRESSES_MODULE;
  }
  return false;
}

/** True for an import of React's element-making functions or runtimes, or a use of one through React's namespace. */
function makesElements(made, file, node) {
  if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
    const from = node.moduleSpecifier.text;
    if (ELEMENT_RUNTIMES.has(from)) return true;
    const named = node.importClause?.namedBindings;
    return (
      from === "react" &&
      named !== undefined &&
      ts.isNamedImports(named) &&
      named.elements.some((element) => ELEMENT_MAKERS.has((element.propertyName ?? element.name).text))
    );
  }
  return (
    ts.isPropertyAccessExpression(node) &&
    ELEMENT_MAKERS.has(node.name.text) &&
    ts.isIdentifier(node.expression) &&
    importOf(made, file, node.expression)?.specifier === "react"
  );
}

/** The module an import or export names, as written: a declaration's, or a dynamic `import()`'s first argument. */
function specifierOf(node) {
  return ts.isCallExpression(node) ? node.arguments[0] : node.moduleSpecifier;
}

/** Rule 4 for one import or export of `file`. */
function checkImport(made, file, node, report) {
  const specifier = specifierOf(node);
  if (!specifier || !ts.isStringLiteralLike(specifier)) {
    report(node, "outside the shell, an import's path must be written out");
    return;
  }
  const name = path.resolve(file.fileName);
  const target = resolve(made, file, specifier.text) ?? path.resolve(path.dirname(name), specifier.text);
  if (TEST_FILE.test(target))
    report(node, `outside the shell, no module may import a test file (${path.relative(root, target)})`);
  // A test file is never bundled into the app, so it may import the module it tests.
  if (TEST_FILE.test(name) || typeOnly(node)) return;
  if (target.startsWith(SHELL) && target.replace(/\.(d\.)?tsx?$/, "") !== PROVIDER_MODULE) {
    report(
      node,
      `outside the shell, a module imports from the shell only src/shell/provider, not ${path.relative(root, target)}`,
    );
  }
}

/** Rules 4 and 5, the boundary, over the files outside the shell in the screens' compile: the problems found. */
function boundary(made) {
  const problems = [];
  for (const file of sourcesOf(made, false)) {
    const report = reporterFor(file, problems, ` ${SCREENS_HINT}`);
    const visit = (node) => {
      if (ts.isJsxAttribute(node)) {
        const attribute = node.name.getText(file);
        if (OPAQUE_ATTRIBUTES.has(attribute))
          report(node, `outside the shell, no \`${attribute}\`: it could carry an address past the markup rule`);
        if (ADDRESS_ATTRIBUTES.has(attribute) && !appAddress(made, file, node.initializer)) {
          report(
            node,
            `outside the shell, \`${attribute}\` is a path written out from the root (not under /api), an imported asset, or made by src/addresses.ts`,
          );
        }
      }
      if (ts.isJsxSpreadAttribute(node)) {
        const tag = node.parent.parent.tagName;
        if (ts.isIdentifier(tag) && /^[a-z]/.test(tag.text))
          report(node, "outside the shell, no spread onto an HTML element: it could carry an address");
      }
      if (makesElements(made, file, node))
        report(node, "outside the shell, no element made by React's functions directly: write it as markup");
      if (
        ts.isStringLiteralLike(node) ||
        ts.isTemplateHead(node) ||
        ts.isTemplateMiddle(node) ||
        ts.isTemplateTail(node)
      ) {
        if (node.text.includes(AUTH_PREFIX))
          report(node, `outside the shell, a path under ${AUTH_PREFIX} is the shell's`);
      }
      const isImport = ts.isImportDeclaration(node) || (ts.isExportDeclaration(node) && node.moduleSpecifier);
      if (isImport || (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword)) {
        checkImport(made, file, node, report);
      }
      ts.forEachChild(node, visit);
    };
    visit(file);
  }
  return problems;
}

/** The type checks and the rules: every problem, or none. */
export function check() {
  // The whole project's type errors stop the check: its rules read types, and would report the errors' echoes.
  const whole = program("tsconfig.json");
  if (whole.problems.length > 0) return whole.problems;
  // The screens' compile is expected to refuse a browser name; that is reported beside the rules, which still run. Only
  // a config that can't be read at all leaves nothing to check.
  const screens = program("tsconfig.screens.json");
  if (!screens.program) return screens.problems;
  // Each file is read with the types it is compiled with: the shell's with the browser library, every other with the
  // screens' compile, where a browser name is a value of type `any`.
  const problems = [
    ...honesty(whole.program, "shell"),
    ...honesty(screens.program, "outside"),
    ...boundary(screens.program),
  ];
  const compiled = screens.problems.length > 0 ? [...screens.problems, SCREENS_HINT] : [];
  return [...new Set([...compiled, ...problems])];
}
