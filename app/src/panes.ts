// Pane shares of the main window, worked out from pixel targets. Splitpanes takes percentages, and the drawing gives pixels, so this turns one into the other.
// The rail and the right column keep the drawing's widths. The middle column gets the rest, so the Message bytes panel can hold its field list beside the grids.

/** The pixel targets at one window width. */
export interface PaneTargets { rail: number; side: number; bytes: number }

/** Padding and gaps around the panes, in px: the shell's padding, the top bar, the status bar, and the gaps between them. */
const SHELL_X = 16
const SHELL_Y = 90
/** The Message bytes panel stacks its field list under the grids below this width (the `@container` rule in style.css). */
export const STACK_BELOW = 700

export function paneTargets(width: number): PaneTargets {
  const wide = width >= 1400
  const rail = wide ? 250 : 228
  const side = wide ? 400 : 328
  const middle = width - SHELL_X - rail - side
  // The bytes pane holds a short message with every row and field in view: 360 px with the field list beside the grids, 480 px with it stacked.
  return { rail, side, bytes: middle >= STACK_BELOW ? 360 : 480 }
}

const clamp = (v: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, v))

/** Percent shares for the 3 split levels: rail of the window, right column of the workspace, bytes of the middle column. */
export function paneShares(width: number, height: number): { rail: number; side: number; bytes: number } {
  const t = paneTargets(width)
  const inner = Math.max(1, width - SHELL_X)
  const work = Math.max(1, inner - t.rail)
  return {
    rail: clamp((t.rail / inner) * 100, 11, 30),
    side: clamp((t.side / work) * 100, 26, 50),
    bytes: clamp(Math.ceil((t.bytes / Math.max(1, height - SHELL_Y)) * 100), 46, 70),
  }
}
