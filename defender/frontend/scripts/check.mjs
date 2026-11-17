// The type check and the source check (#1540 F1 b, F8): one TypeScript program over the whole project (screens, shell and
// unit-test files alike), whose diagnostics fail the run, and a syntactic scan of every source outside `src/shell/` and
// `src/generated/` for what only the shell may do (PR2). Run by `bun run check`, and by `bun run build` before it writes anything.
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

// The DOM library's network, storage and navigation declarations, by name; a member is refused only on the containers
// named (so `document.open()` and `XMLHttpRequest`'s own methods are not caught by a bare name).
const GLOBAL_OR_WINDOW = new Set(["", "Window", "WindowOrWorkerGlobalScope", "WorkerGlobalScope", "WindowLocalStorage", "WindowSessionStorage"]);
const REFUSED_NAMES = new Map([
  ["fetch", null],
  ["XMLHttpRequest", null],
  ["EventSource", null],
  ["WebSocket", null],
  ["localStorage", null],
  ["sessionStorage", null],
  ["indexedDB", null],
  ["caches", null],
  ["location", null],
  ["history", null],
  ["navigation", null],
  ["sendBeacon", new Set(["Navigator"])],
  ["cookie", new Set(["Document"])],
  ["open", GLOBAL_OR_WINDOW],
]);
const AUTH_PREFIX = "/api/auth/";

/** The name of the interface (or "" for the global scope) a declaration belongs to. */
function containerOf(declaration) {
  const parent = declaration.parent;
  return parent && (ts.isInterfaceDeclaration(parent) || ts.isClassDeclaration(parent)) && parent.name ? parent.name.text : "";
}

function isDomLibrary(declaration) {
  return /[\\/]lib\.(dom|webworker)[^\\/]*\.d\.ts$/.test(declaration.getSourceFile().fileName);
}

/** Whether `symbol` is one of the DOM library's refused declarations. */
function refusedSymbol(symbol) {
  if (!symbol) return null;
  const rule = REFUSED_NAMES.get(symbol.name);
  if (rule === undefined) return null;
  const declarations = (symbol.declarations ?? []).filter(isDomLibrary);
  if (declarations.length === 0) return null;
  if (rule !== null && !declarations.some((declaration) => rule.has(containerOf(declaration)))) return null;
  return symbol.name;
}

export function check() {
  const configPath = path.join(root, "tsconfig.json");
  const read = ts.readConfigFile(configPath, ts.sys.readFile);
  if (read.error) return [ts.flattenDiagnosticMessageText(read.error.messageText, "\n")];
  const config = ts.parseJsonConfigFileContent(read.config, ts.sys, root);
  const program = ts.createProgram({ rootNames: config.fileNames, options: config.options });
  const problems = [];
  for (const diagnostic of ts.getPreEmitDiagnostics(program)) {
    const text = ts.flattenDiagnosticMessageText(diagnostic.messageText, "\n");
    if (diagnostic.file && diagnostic.start !== undefined) {
      const { line } = diagnostic.file.getLineAndCharacterOfPosition(diagnostic.start);
      problems.push(`${path.relative(root, diagnostic.file.fileName)}:${line + 1}: TS${diagnostic.code}: ${text}`);
    } else {
      problems.push(`TS${diagnostic.code}: ${text}`);
    }
  }
  if (problems.length > 0) return problems;

  const checker = program.getTypeChecker();
  const shell = path.join(root, "src", "shell") + path.sep;
  const generated = path.join(root, "src", "generated") + path.sep;
  for (const file of program.getSourceFiles()) {
    const name = path.resolve(file.fileName);
    if (!name.startsWith(path.join(root, "src") + path.sep) || name.startsWith(shell) || name.startsWith(generated)) continue;
    const report = (node, what) => {
      const { line } = file.getLineAndCharacterOfPosition(node.getStart(file));
      problems.push(`${path.relative(root, name)}:${line + 1}: only the shell may use ${what} (src/shell/ owns the network, storage and the address)`);
    };
    const visit = (node) => {
      if (ts.isStringLiteralLike(node) || ts.isTemplateHead(node)) {
        if (node.text.startsWith(AUTH_PREFIX)) report(node, `a path under ${AUTH_PREFIX}`);
      }
      if (ts.isIdentifier(node)) {
        const refused = refusedSymbol(checker.getSymbolAtLocation(node));
        if (refused) report(node, refused);
      }
      if (ts.isBindingElement(node) && ts.isObjectBindingPattern(node.parent)) {
        // `const { fetch } = window`: the name is a new local, so ask the destructured value's type for the property.
        const key = node.propertyName ?? node.name;
        const declaration = node.parent.parent;
        if (ts.isIdentifier(key) && ts.isVariableDeclaration(declaration) && declaration.initializer) {
          const property = checker.getPropertyOfType(checker.getTypeAtLocation(declaration.initializer), key.text);
          const refused = refusedSymbol(property);
          if (refused) report(node, refused);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(file);
  }
  return [...new Set(problems)];
}

if (import.meta.main) {
  const problems = check();
  if (problems.length > 0) {
    for (const problem of problems) console.error(problem);
    console.error("check: failed");
    process.exit(1);
  }
}
