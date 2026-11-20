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
// 5. Outside the shell, the markup the browser could send requests for (#1581 r3.3: no attribute list decides it).
//    Every string a screen writes into an attribute of any element (a JSX string, read with its entities decoded, and
//    each string and template part of an attribute's expression) is refused when the browser could resolve it, from
//    any address the app serves, to `/api` or under it: dot segments, `\`, tabs, newlines and percent-escapes read as
//    the browser and the server read them; the whole string and each of its words that holds a slash alike, so a list
//    (`srcSet`, `ping`, `imageSrcSet`) is read address by address; and an absolute web address of any host, since the
//    app's own host is not known here. Ordinary words ("API docs", "/apix") stay allowed. On top of that, an attribute
//    the browser is known to request or navigate to (`src`, `href`, `action`, ..., matched in any case) must be a path
//    written out from the root on the app's origin, an imported asset's URL, or made by `src/addresses.ts` (which makes
//    only the app's own addresses), so an address held in a variable or built in a template is refused there. What
//    could carry an address past both is refused outright: an attribute that holds HTML or a navigation instruction in
//    a string (`srcDoc`, raw HTML, a `meta` element's `content` beside `httpEquiv`), an inline style, a spread onto an
//    HTML element, and React's element-making functions called directly. So a screen's markup makes the browser
//    request no API path: the shell's client, and its 401 policy, sends every one. Known limit: a bare word with no
//    slash inside a list attribute the check does not know (`archive="a api"`) is read only as part of the whole.
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { sampleAddresses } from "./generate.mjs";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const AUTH_PREFIX = "/api/auth/";
/** The attributes the browser is known to request or navigate to, whose value must have an address's shape (rule 5),
 * by `attributeKey`. Not what decides the `/api` refusal: that reads every attribute. */
const ADDRESS_ATTRIBUTES = new Set([
  "src",
  "srcset",
  "href",
  "action",
  "formaction",
  "poster",
  "data",
  "ping",
  "cite",
  "background",
  "xlinkhref",
]);
/** Address attributes that hold a list of addresses, by `attributeKey`. */
const LIST_ATTRIBUTES = new Set(["srcset", "ping"]);
/** Attributes that could carry an address past rule 5's string reading, by `attributeKey`: HTML in a string or object,
 * and an inline style. */
const OPAQUE_ATTRIBUTES = new Set(["dangerouslysetinnerhtml", "srcdoc", "style"]);
/** The web's schemes, whose addresses a browser requests whatever their host. */
const WEB_SCHEMES = new Set(["http:", "https:", "ws:", "wss:"]);
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

/** Where a literal address is resolved from: an origin of its own, the app's served from it. */
const ORIGIN = "https://app.invalid";
/** The entities a JSX string may spell an address with that `decodeJsx` reads; any other is refused. */
const NAMED_ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
/** A `srcSet` candidate's width or density, which is not an address. */
const DESCRIPTOR = /^\d+(\.\d+)?[wx]$/i;

/** A JSX string as the element gets it (the JSX compile decodes HTML entities in it), or null when it holds an entity
 * not read here. */
function decodeJsx(text) {
  let unknown = false;
  const decoded = text.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z][a-z0-9]*);/gi, (entity, name) => {
    const lower = name.toLowerCase();
    if (lower.startsWith("#")) {
      const code = lower.startsWith("#x") ? parseInt(lower.slice(2), 16) : parseInt(lower.slice(1), 10);
      if (code <= 0x10ffff) return String.fromCodePoint(code);
    } else if (Object.hasOwn(NAMED_ENTITIES, name)) {
      return NAMED_ENTITIES[name];
    }
    unknown = true;
    return entity;
  });
  return unknown ? null : decoded;
}

/** True when `pathname` names `/api` or a path under it, as a server matching its first segment, in any case, reads
 * it. */
function namesApi(pathname) {
  const first = pathname.split(/[/\\]/).find((segment) => segment !== "");
  return first !== undefined && first.toLowerCase() === "api";
}

/** `pathname` with each percent-escape of an ASCII character decoded, the rest left as written: what a server that
 * decodes what it can reads of a path `decodeURIComponent` refuses. */
function decodeAscii(pathname) {
  return pathname.replace(/%([0-7][0-9a-f])/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
}

/** Where `text`, requested by the browser from `address`, resolves: `api` (a path at or under `/api`, on the app's
 * origin or any host of a web scheme), `off` (the app's origin, off `/api`), `elsewhere` (another origin or scheme) or
 * `unreadable` (an address the browser cannot parse, or a path whose escapes a server cannot read). Resolved as the
 * browser resolves it (dot segments, `\`, tabs and newlines), then with its percent-escapes decoded as a server
 * decodes them, and again until nothing changes. */
function resolution(text, address) {
  let base;
  let url;
  try {
    base = new URL(address, ORIGIN);
    url = new URL(text, base);
  } catch {
    return "unreadable";
  }
  if (!WEB_SCHEMES.has(url.protocol)) return "elsewhere";
  let elsewhere = url.origin !== base.origin;
  let readable = true;
  // The parser escapes what decoding gave back (a space, say), so a path can come round again: then it is done.
  const seen = new Set();
  while (!seen.has(url.pathname)) {
    seen.add(url.pathname);
    if (namesApi(url.pathname)) return "api";
    let decoded;
    try {
      decoded = decodeURIComponent(url.pathname);
    } catch {
      readable = false;
      decoded = decodeAscii(url.pathname);
    }
    if (decoded === url.pathname) break;
    if (namesApi(decoded)) return "api";
    try {
      url = new URL(decoded, base);
    } catch {
      return "unreadable";
    }
    if (url.origin !== base.origin) elsewhere = true;
  }
  if (elsewhere) return "elsewhere";
  return readable ? "off" : "unreadable";
}

/** True when `text`, requested by the browser from `address`, stays on the app's origin and reaches no path at or under
 * `/api` (`resolution`). An address the browser or a server cannot read is refused. */
function staysOffApiFrom(text, address) {
  return resolution(text, address) === "off";
}

/** True when the browser could resolve `text`, as a whole or any of its words that holds a slash, from any address the
 * app serves to `/api` or under it (rule 5, every attribute). */
function couldReachApi(text, addresses) {
  const candidates = [text, ...text.split(/[\s,]+/).filter((word) => word !== text && /[/\\]/.test(word))];
  return candidates.some((candidate) => addresses.some((address) => resolution(candidate, address) === "api"));
}

/** Each string an attribute's value writes: its JSX string, or every string and template part of its expression (an
 * element inside it is checked as its own markup). `null` stands for a JSX string with an entity not read here. */
function attributeStrings(value) {
  if (value === undefined) return [];
  if (ts.isStringLiteral(value)) return [decodeJsx(value.text)];
  const strings = [];
  const walk = (node) => {
    if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node) || ts.isJsxFragment(node)) return;
    if (
      ts.isStringLiteralLike(node) ||
      ts.isTemplateHead(node) ||
      ts.isTemplateMiddle(node) ||
      ts.isTemplateTail(node)
    ) {
      strings.push(node.text);
    }
    ts.forEachChild(node, walk);
  };
  walk(value);
  return strings;
}

/** An attribute's name as the browser matches it: HTML attribute names in any case, a namespace's `:` and a hyphen
 * aside (`xlink:href` and `xlinkHref`, `http-equiv` and `httpEquiv`, `SRCDOC` and `srcDoc`). */
function attributeKey(name) {
  return name.replace(/[-:]/g, "").toLowerCase();
}

/** True when the JSX attribute `node` sits on a `meta` element that has an `httpEquiv`: its `content` is a navigation
 * or header instruction in a string. */
function onHttpEquivMeta(file, node) {
  const element = node.parent.parent;
  return (
    attributeKey(element.tagName.getText(file)) === "meta" &&
    node.parent.properties.some(
      (property) => ts.isJsxAttribute(property) && attributeKey(property.name.getText(file)) === "httpequiv",
    )
  );
}

/** True for a literal address the browser requests or navigates to that is an app address (rule 5): a path written out
 * from the root that stays off `/api`, or a fragment. */
function literalAppAddress(text, addresses) {
  if (text.startsWith("#")) return true;
  return text.startsWith("/") && !text.startsWith("//") && addresses.every((address) => staysOffApiFrom(text, address));
}

/** True for an address attribute's value that can only be an app address or an asset (rule 5). */
function appAddress({ made, file, addresses }, attribute, value) {
  if (value === undefined) return true;
  if (ts.isStringLiteral(value)) {
    const text = decodeJsx(value.text);
    if (text === null) return false;
    // `srcSet` and `ping` hold lists of addresses: each must be one (a `srcSet` candidate's descriptor aside).
    if (LIST_ATTRIBUTES.has(attribute)) {
      const tokens = text.split(/[\s,]+/).filter((token) => token !== "" && !DESCRIPTOR.test(token));
      return tokens.length > 0 && tokens.every((token) => literalAppAddress(token, addresses));
    }
    return literalAppAddress(text, addresses);
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
  const addresses = sampleAddresses();
  for (const file of sourcesOf(made, false)) {
    const report = reporterFor(file, problems, ` ${SCREENS_HINT}`);
    const visit = (node) => {
      if (ts.isJsxAttribute(node)) {
        const attribute = node.name.getText(file);
        const key = attributeKey(attribute);
        if (OPAQUE_ATTRIBUTES.has(key))
          report(node, `outside the shell, no \`${attribute}\`: it could carry an address past the markup rule`);
        if (key === "content" && onHttpEquivMeta(file, node))
          report(node, "outside the shell, no `content` on a `meta` with `httpEquiv`: it could carry an address");
        for (const text of attributeStrings(node.initializer)) {
          if (text === null)
            report(node, `outside the shell, \`${attribute}\` holds an entity the markup rule does not read`);
          else if (couldReachApi(text, addresses))
            report(node, `outside the shell, \`${attribute}\` holds a string the browser could resolve to /api`);
        }
        if (ADDRESS_ATTRIBUTES.has(key) && !appAddress({ made, file, addresses }, key, node.initializer)) {
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
