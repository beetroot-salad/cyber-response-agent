// The type check and the source check (#1540 F1 b, F8): one TypeScript program over the whole project (screens, shell and
// unit-test files alike), whose diagnostics fail the run, and a scan of every source outside `src/shell/` and
// `src/generated/` for what only the shell may do (PR2). A function only: `scripts/check.mjs` (`bun run check`) and
// `scripts/build.mjs` call it in their own process, so no command depends on how it was started.
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");

const AUTH_PREFIX = "/api/auth/";

// PR2 by its roots, not by a list of the DOM's network, storage and navigation names. Every way to those starts at a value
// the DOM library declares globally (`window`, `document`, `fetch`, `localStorage`, `location`, ...) or at `globalThis`,
// or at a value typed as one of those globals' own types (`Window`, `Document`, `Storage`, ...). Outside the shell no
// such value and no such type may be named, so how a member is then reached (`.x`, `["x"]`, destructuring, an alias)
// does not matter. A module outside the shell imports from it only `src/shell/provider` (types from anywhere in it):
// the shell's other modules are its own. Not covered: a DOM object a screen is handed (a React event's
// `currentTarget.ownerDocument`); only a sandbox would close that.

function isDomLibrary(sourceFile) {
  return /[\\/]lib\.(dom|webworker)[^\\/]*\.d\.ts$/.test(sourceFile.fileName);
}

/** The names of the DOM library's global values, and of the named types they are declared with. */
function domGlobals(program) {
  const values = new Set();
  const types = new Set();
  for (const file of program.getSourceFiles()) {
    if (!isDomLibrary(file)) continue;
    for (const statement of file.statements) {
      if (ts.isFunctionDeclaration(statement) && statement.name) values.add(statement.name.text);
      if (!ts.isVariableStatement(statement)) continue;
      for (const declaration of statement.declarationList.declarations) {
        if (!ts.isIdentifier(declaration.name)) continue;
        values.add(declaration.name.text);
        const type = declaration.type;
        for (const part of type && ts.isIntersectionTypeNode(type) ? type.types : type ? [type] : []) {
          if (ts.isTypeReferenceNode(part) && ts.isIdentifier(part.typeName)) types.add(part.typeName.text);
        }
      }
    }
  }
  return { values, types };
}

/** True when `symbol` is the DOM library's own global: declared at a DOM library file's top level (a member such as
 * `Document.location` or `HTMLElement.focus` is not), and nowhere in the project's own sources (a local is not). */
function isDomGlobal(symbol) {
  const declarations = symbol?.declarations ?? [];
  const topLevel = (declaration) => {
    const file = declaration.getSourceFile();
    const statement = ts.isVariableDeclaration(declaration) ? declaration.parent.parent : declaration;
    return isDomLibrary(file) && statement.parent === file;
  };
  return declarations.some(topLevel) && declarations.every((declaration) => declaration.getSourceFile().isDeclarationFile);
}

/** True when `node` is the name in a type reference (`x: Window`), where a type, not a value, is meant. */
function isTypeName(node) {
  let child = node;
  while (ts.isQualifiedName(child.parent)) child = child.parent;
  return ts.isTypeReferenceNode(child.parent) && child.parent.typeName === child;
}

/** True when the import or export moves only types (`import type`, `export type`, or every name marked `type`). */
function typeOnly(node) {
  if (ts.isImportTypeNode(node)) return true;
  if (ts.isExportDeclaration(node)) return node.isTypeOnly;
  if (ts.isCallExpression(node)) return false;
  const clause = node.importClause;
  if (!clause) return false; // `import "./x"`: runs the module
  if (clause.isTypeOnly) return true;
  const named = clause.namedBindings;
  return !clause.name && named !== undefined && ts.isNamedImports(named) && named.elements.length > 0
    && named.elements.every((element) => element.isTypeOnly);
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
  const { values, types } = domGlobals(program);
  const src = path.join(root, "src") + path.sep;
  const shell = path.join(root, "src", "shell") + path.sep;
  const generated = path.join(root, "src", "generated") + path.sep;
  const door = path.join(root, "src", "shell", "provider");
  for (const file of program.getSourceFiles()) {
    const name = path.resolve(file.fileName);
    if (!name.startsWith(src) || name.startsWith(shell) || name.startsWith(generated)) continue;
    const isTest = /\.test\.tsx?$/.test(name); // never bundled into the app, so it may import the module it tests
    const report = (node, what) => {
      const { line } = file.getLineAndCharacterOfPosition(node.getStart(file));
      problems.push(`${path.relative(root, name)}:${line + 1}: only the shell may use ${what} (src/shell/ owns the network, storage and the address)`);
    };
    const importsFrom = (node, specifier) => {
      if (isTest || typeOnly(node)) return;
      if (!specifier || !ts.isStringLiteralLike(specifier)) {
        report(node, "an import whose path is not written out");
        return;
      }
      const resolved = ts.resolveModuleName(specifier.text, file.fileName, program.getCompilerOptions(), ts.sys).resolvedModule;
      const target = resolved ? path.resolve(resolved.resolvedFileName) : path.resolve(path.dirname(name), specifier.text);
      if (target.startsWith(shell) && target.replace(/\.(d\.)?tsx?$/, "") !== door) {
        report(node, `${path.relative(root, target)} (import the shell's hooks from src/shell/provider)`);
      }
    };
    const visit = (node) => {
      if (ts.isStringLiteralLike(node) || ts.isTemplateHead(node)) {
        if (node.text.startsWith(AUTH_PREFIX)) report(node, `a path under ${AUTH_PREFIX}`);
      }
      if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
        if (node.moduleSpecifier) importsFrom(node, node.moduleSpecifier);
      } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        importsFrom(node, node.arguments[0]);
      }
      if (ts.isIdentifier(node)) {
        const symbol = ts.isShorthandPropertyAssignment(node.parent) && node.parent.name === node
          ? checker.getShorthandAssignmentValueSymbol(node.parent)
          : checker.getSymbolAtLocation(node);
        if (symbol && symbol.name === "globalThis" && !(symbol.declarations ?? []).some((d) => !d.getSourceFile().isDeclarationFile)) {
          report(node, "globalThis");
        } else if (isTypeName(node)) {
          if (types.has(node.text) && isDomGlobal(symbol)) report(node, `the type ${node.text}`);
        } else if (values.has(node.text) && isDomGlobal(symbol)) {
          report(node, node.text);
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(file);
  }
  return [...new Set(problems)];
}
