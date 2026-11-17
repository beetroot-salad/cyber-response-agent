// The router: a total map from the shape list's names to screens. The type check holds both halves: a shape with no
// screen and a screen with no shape are build errors. What matches no shape is the not-found screen, not a route.
import { match, RETURNABLE, type ShapeName } from "./addresses";
import { investigation } from "./screens/investigation";
import { notFound } from "./screens/notFound";
import { root } from "./screens/root";
import { signInFailed } from "./screens/signInFailed";
import type { Screen } from "./screen";

const SCREENS: Record<ShapeName, Screen> = {
  root,
  investigation,
  "sign-in-failed": signInFailed,
};

export interface Route {
  readonly screen: Screen;
  /** The pathname when it is a member of a returnable shape: what sign-in brings the person back to. */
  readonly target: string | null;
}

export function route(pathname: string): Route {
  const shape = match(pathname);
  if (shape === null) return { screen: notFound, target: null };
  return { screen: SCREENS[shape], target: RETURNABLE.has(shape) ? pathname : null };
}
