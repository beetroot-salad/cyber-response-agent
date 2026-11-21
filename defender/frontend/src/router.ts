// The router: a total map from the shape list's names to screens. The type check holds both halves: a shape with no
// screen and a screen with no shape are build errors. What matches no shape is the not-found screen, not a route (PR4).
import type { ComponentType } from "react";
import { match, RETURNABLE, type ShapeName } from "./addresses";
import { Alerts } from "./screens/alerts/Alerts";
import { Home } from "./screens/Home";
import { Investigation } from "./screens/Investigation";
import { NotFound } from "./screens/NotFound";
import { Root } from "./screens/Root";
import { SignInFailed } from "./screens/SignInFailed";

const SCREENS: Record<ShapeName, ComponentType> = {
  root: Root,
  home: Home,
  investigation: Investigation,
  alerts: Alerts,
  "sign-in-failed": SignInFailed,
};

export interface Route {
  readonly shape: ShapeName | null;
  readonly Screen: ComponentType;
  /** The pathname when it is a member of a returnable shape: what sign-in brings the person back to. */
  readonly target: string | null;
  /** Whether the screen needs `/api/me` first: a returnable shape does, a non-returnable one does not (F4), and the
   * not-found screen does. */
  readonly needsSession: boolean;
}

export function route(pathname: string): Route {
  const shape = match(pathname);
  if (shape === null) return { shape, Screen: NotFound, target: null, needsSession: true };
  const returnable = RETURNABLE.has(shape);
  return { shape, Screen: SCREENS[shape], target: returnable ? pathname : null, needsSession: returnable };
}
