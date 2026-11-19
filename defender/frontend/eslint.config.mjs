// The frontend's lint (#1540): what the type check and the source check don't cover. Type-aware rules for the app (a
// promise nobody handles, a switch that misses a case, a method handed on without its object), the size of a function
// and of a line everywhere, and no comment may switch a rule off: a finding is fixed, or the rule is changed here.
import js from "@eslint/js";
import { defineConfig } from "eslint/config";
import reactHooks from "eslint-plugin-react-hooks";
import globals from "globals";
import tseslint from "typescript-eslint";

export default defineConfig(
  { ignores: ["src/generated/**", "dist/**", "dist-builds/**", "node_modules/**", "**/*.d.ts"] },
  { linterOptions: { noInlineConfig: true, reportUnusedDisableDirectives: "error" } },
  js.configs.recommended,
  {
    rules: {
      // Prettier lays out the code at this width; this holds comments to it. A string is whole text, so not wrapped.
      "max-len": [
        "error",
        { code: 120, ignoreUrls: true, ignoreStrings: true, ignoreTemplateLiterals: true, ignoreRegExpLiterals: true },
      ],
      "max-lines-per-function": ["error", { max: 60, skipBlankLines: true, skipComments: true }],
      "max-depth": ["error", 3],
      "max-nested-callbacks": ["error", 3],
      "max-params": ["error", 4],
      "no-empty": ["error", { allowEmptyCatch: false }],
    },
  },
  {
    files: ["src/**/*.{ts,tsx}"],
    extends: [
      tseslint.configs.strictTypeChecked,
      tseslint.configs.stylisticTypeChecked,
      reactHooks.configs.flat.recommended,
    ],
    languageOptions: { parserOptions: { projectService: true, tsconfigRootDir: import.meta.dirname } },
    rules: {
      "@typescript-eslint/switch-exhaustiveness-check": "error",
      // A function in an interface is a property, so it can be handed on alone (`read: load.client.read`).
      "@typescript-eslint/method-signature-style": ["error", "property"],
      "@typescript-eslint/restrict-template-expressions": ["error", { allowNumber: true, allowBoolean: true }],
      // `onClick={() => actions.retry()}` is how a handler is written; a void call returned from a block is not.
      "@typescript-eslint/no-confusing-void-expression": ["error", { ignoreArrowShorthand: true }],
    },
  },
  { files: ["**/*.mjs"], languageOptions: { globals: globals.node } },
);
