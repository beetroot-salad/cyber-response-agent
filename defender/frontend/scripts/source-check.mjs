// The type check and the source check (#1540 F1 b, F8). A function only: `scripts/check.mjs` (`bun run check`) and
// `scripts/build.mjs` call it in their own process, so no command depends on how it was started.
//
// 1. The whole project (screens, shell and unit-test files alike) is type-checked with the browser library.
// 2. Everything outside `src/shell/` is type-checked again without it (`tsconfig.screens.json`), with only what
//    `screens-env.d.ts` declares. There `window`, `document`, `fetch`, storage and `location` do not exist, and React's
//    types give a DOM element no members beyond those declared, so no route to the network, storage or the address can be
//    written there, however it is spelled (PR2). The compiler is the boundary; nothing below lists the browser's names.
// 3. Everywhere (shell included, the generated types aside) the compiler is kept honest: no `any`, no value of type
//    `any` (but one given the type `unknown` where it is made, as `JSON.parse`'s), no comment that switches type checking
//    off, and no type assertion but `as const`. In the shell, an assertion is allowed only under a `// trust: <reason>`
//    comment on the line above: the step the compiler cannot check, said out loud.
// 4. Outside the shell: imports from the shell only of `src/shell/provider` (types from anywhere in it), no import of a
//    test file into the app, and no `/api/auth/` path in a string. That last one is a guard against an accident, not a
//    boundary: a string can be built any way.
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const AUTH_PREFIX = "/api/auth/";
const SCREENS_HINT = "(outside src/shell/ the browser library does not exist: src/shell/ owns the network, storage and the "
  + "address, and screens-env.d.ts declares what else a screen may use)";

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
  return !clause.name && named !== undefined && ts.isNamedImports(named) && named.elements.length > 0
    && named.elements.every((element) => element.isTypeOnly);
}

/** True for `x as const`, the one assertion that claims nothing about what a value is. */
function isConstAssertion(node) {
  return ts.isTypeReferenceNode(node.type) && ts.isIdentifier(node.type.typeName) && node.type.typeName.text === "const";
}

/** True when the `any`-typed `node` is given the type `unknown` where it is made: `const x: unknown = JSON.parse(s)`. */
function madeUnknown(node) {
  const parent = node.parent;
  return ts.isVariableDeclaration(parent) && parent.initializer === node && parent.type?.kind === ts.SyntaxKind.UnknownKeyword;
}

/** True when the line above `node` is a `// trust: <reason>` comment. */
function trusted(file, node) {
  const { line } = file.getLineAndCharacterOfPosition(node.getStart(file));
  if (line === 0) return false;
  const above = file.text.slice(file.getPositionOfLineAndCharacter(line - 1, 0), file.getPositionOfLineAndCharacter(line, 0));
  return /^\s*\/\/ trust: \S/.test(above);
}

export function check() {
  const whole = program("tsconfig.json");
  if (whole.problems.length > 0) return whole.problems;
  const screens = program("tsconfig.screens.json");
  if (!screens.program) return screens.problems;

  const src = path.join(root, "src") + path.sep;
  const shell = path.join(root, "src", "shell") + path.sep;
  const generated = path.join(root, "src", "generated") + path.sep;
  const door = path.join(root, "src", "shell", "provider");
  const problems = [];
  const reporter = (file, name, hint) => (node, what) => {
    const { line } = file.getLineAndCharacterOfPosition(node.getStart(file));
    problems.push(`${path.relative(root, name)}:${line + 1}: ${what}${hint}`);
  };

  // 3. Honesty, everywhere but the generated types. Each file is read with the types it is compiled with: the shell's
  // with the browser library, every other with the screens' compile, where a browser name is a value of type `any`.
  const honest = [
    { made: whole.program, inShell: true },
    { made: screens.program, inShell: false },
  ];
  for (const { made, inShell } of honest) {
    const checker = made.getTypeChecker();
    for (const file of made.getSourceFiles()) {
      const name = path.resolve(file.fileName);
      if (!name.startsWith(src) || name.startsWith(generated) || file.isDeclarationFile) continue;
      if (name.startsWith(shell) !== inShell) continue;
      const report = reporter(file, name, inShell ? "" : ` ${SCREENS_HINT}`);
      for (const match of file.text.matchAll(/@ts-(ignore|expect-error|nocheck)\b/g)) {
        const { line } = file.getLineAndCharacterOfPosition(match.index);
        problems.push(`${path.relative(root, name)}:${line + 1}: no comment may switch type checking off (${match[0]})`);
      }
      const visit = (node) => {
        if ((ts.isAsExpression(node) && !isConstAssertion(node)) || ts.isTypeAssertionExpression(node)) {
          if (!(inShell && trusted(file, node))) {
            report(node, inShell
              ? "a type assertion needs a `// trust: <reason>` comment on the line above (only `as const` needs none)"
              : "no type assertion outside the shell (only `as const`): it could claim a value is anything");
          }
        }
        if (node.kind === ts.SyntaxKind.AnyKeyword) report(node, "no `any`: it could hold anything");
        if ((ts.isCallExpression(node) || ts.isNewExpression(node) || ts.isPropertyAccessExpression(node)
             || ts.isElementAccessExpression(node)) && (checker.getTypeAtLocation(node).flags & ts.TypeFlags.Any)
            && !madeUnknown(node)) {
          report(node, "no value of type `any` (give it the type `unknown` where it is made): it could hold anything");
        }
        ts.forEachChild(node, visit);
      };
      visit(file);
    }
  }

  // 4. The boundary's own rules, outside the shell, over the screens' compile.
  for (const file of screens.program.getSourceFiles()) {
    const name = path.resolve(file.fileName);
    if (!name.startsWith(src) || name.startsWith(shell) || name.startsWith(generated)) continue;
    const isTest = /\.test\.tsx?$/.test(name); // never bundled into the app, so it may import the module it tests
    const report = reporter(file, name, ` ${SCREENS_HINT}`);
    const importsFrom = (node, specifier) => {
      if (!specifier || !ts.isStringLiteralLike(specifier)) {
        report(node, "outside the shell, an import's path must be written out");
        return;
      }
      const resolved = ts.resolveModuleName(specifier.text, file.fileName, screens.program.getCompilerOptions(), ts.sys).resolvedModule;
      const target = resolved ? path.resolve(resolved.resolvedFileName) : path.resolve(path.dirname(name), specifier.text);
      if (/\.test\.tsx?$/.test(target)) report(node, `outside the shell, no module may import a test file (${path.relative(root, target)})`);
      if (isTest || typeOnly(node)) return;
      if (target.startsWith(shell) && target.replace(/\.(d\.)?tsx?$/, "") !== door) {
        report(node, `outside the shell, a module imports from the shell only src/shell/provider, not ${path.relative(root, target)}`);
      }
    };
    const visit = (node) => {
      if (ts.isStringLiteralLike(node) || ts.isTemplateHead(node) || ts.isTemplateMiddle(node) || ts.isTemplateTail(node)) {
        if (node.text.includes(AUTH_PREFIX)) report(node, `outside the shell, a path under ${AUTH_PREFIX} is the shell's`);
      }
      if (ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) {
        if (node.moduleSpecifier) importsFrom(node, node.moduleSpecifier);
      } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        importsFrom(node, node.arguments[0]);
      }
      ts.forEachChild(node, visit);
    };
    visit(file);
  }
  // The screens' compile and the rules both report: a file the compile refuses may break a rule too.
  const compiled = screens.problems.length > 0 ? [...screens.problems, SCREENS_HINT] : [];
  return [...new Set([...compiled, ...problems])];
}
