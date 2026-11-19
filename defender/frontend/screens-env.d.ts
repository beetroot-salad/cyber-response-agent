// The browser, as screens see it (#1540 PR2, F8): screens are compiled without the browser library
// (tsconfig.screens.json), so this file is everything of it they may use. None of it reaches the network, storage or
// the address. Add to it deliberately: what is not declared here does not exist outside src/shell/.

declare function setTimeout(handler: () => void, timeout?: number): number;
declare function clearTimeout(id: number | undefined): void;
declare function setInterval(handler: () => void, timeout?: number): number;
declare function clearInterval(id: number | undefined): void;

declare var console: {
  log(...data: unknown[]): void;
  warn(...data: unknown[]): void;
  error(...data: unknown[]): void;
};

// React's types declare the DOM's interfaces empty when the browser library is absent; these members are added back.
interface HTMLElement {
  focus(): void;
  blur(): void;
}
