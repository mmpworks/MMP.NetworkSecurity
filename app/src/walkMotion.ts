// The motion for each stop of the AES walk (docs/walkthrough-design.md section 2.2a). Each motion is decoration over the end frame:
// the cells already hold the engine's new bytes when it starts, and an old byte shows only through the cell's ::after layer, read
// from data-old. Every animation goes through the timeline, so Pause, a click, Back and an unmount reach it.
import { byteAt, cellIndex, type AesTables, type Stop } from './walk'

type Animate = (el: Element, keyframes: Keyframe[], o: { duration: number; delay?: number; pseudo?: string; fill?: FillMode; easing?: string }) => Animation | null

const ROWS = [0, 1, 2, 3]
const cellOf = (root: HTMLElement, r: number, c: number) => root.querySelector<HTMLElement>(`[data-testid="aes-walk-cell-${r}-${c}"]`)

/** Removes every old-byte layer, so no mark is left from an earlier step. */
export function clearMarks(root: HTMLElement) {
  root.querySelectorAll<HTMLElement>('[data-old]').forEach(el => { delete el.dataset.old })
}

/** For a ShiftRows or InvShiftRows cell: how many columns it travelled, signed, and whether it wrapped round the edge. Read from the engine's map. */
export function shiftOf(map: number[], i: number, inverse: boolean): { by: number; wrapped: boolean } {
  const c = Math.floor(i / 4), from = Math.floor(map[i] / 4)
  if (!inverse) return { by: (from - c + 4) % 4, wrapped: from < c }
  return { by: -((c - from + 4) % 4), wrapped: from > c }
}

/**
 * One cell flips from its old byte to its new one. Until its turn it shows the old byte. The first half turns the old byte away,
 * and the second half turns the new byte in.
 */
function flip(animate: Animate, el: HTMLElement, old: string, delay: number, duration: number, flash?: string) {
  el.dataset.old = old
  animate(el, [{ opacity: 1 }, { opacity: 1, offset: 0.5 }, { opacity: 0, offset: 0.5 }, { opacity: 0 }], { duration, delay, pseudo: '::after', easing: 'linear' })
  const frames: Keyframe[] = flash
    ? [{ transform: 'rotateX(0deg)' }, { transform: 'rotateX(90deg)', offset: 0.5 }, { transform: 'rotateX(0deg)', backgroundColor: flash, offset: 0.8 }, { transform: 'rotateX(0deg)' }]
    : [{ transform: 'rotateX(0deg)' }, { transform: 'rotateX(90deg)', offset: 0.5 }, { transform: 'rotateX(0deg)' }]
  animate(el, frames, { duration, delay, fill: 'forwards' })
}

/**
 * The ShiftRows roll, like a ticker tape (design 2.2a). The whole row slides `by` columns, so every cell starts `by` columns away and
 * rolls into place: a byte that wraps starts past the far edge and rolls in. The old bytes that roll out past the near edge ride on
 * their cell's old-byte layer at a fixed offset of `-by` columns, so they leave while the new bytes arrive. One element per byte cannot
 * both leave on one side and arrive on the other, so the leaving copy is the layer (Richard on #255). No slot is ever empty.
 */
export function rollLeaves(c: number, by: number): boolean {
  return c - by < 0 || c - by > 3
}

export interface MotionInput { root: HTMLElement; to: Stop; tables: AesTables; nk: number; animate: Animate }

/** Starts the motion from one stop to the next. A stop with no motion (the decrypt Start view) starts none. */
export function startMotion({ root, to, tables, nk, animate }: MotionInput) {
  clearMarks(root)
  if (to.kind === 'fill') {
    if (to.filled === 0) return
    const i = to.filled - 1, el = cellOf(root, i % 4, Math.floor(i / 4))
    if (el) animate(el, [{ transform: 'translateY(-28px)', opacity: 0 }, { transform: 'translateY(0)', opacity: 1 }], { duration: 300 })
    return
  }
  if (to.kind === 'keys') {
    if (to.built === 0) return
    const word = nk + to.built - 1
    for (let b = 0; b < 4; b++) {
      const el = root.querySelector(`[data-testid="aes-walk-table-cell-${4 * word + b}"]`)
      if (el) animate(el, [{ transform: 'scale(0.4)', opacity: 0 }, { transform: 'scale(1)', opacity: 1 }], { duration: 260, delay: 110 * b })
    }
    return
  }
  if (to.kind !== 'step') return
  const kind = to.step.kind
  const old = (i: number) => byteAt(to.prev, i)
  if (kind === 'SubBytes' || kind === 'InvSubBytes') {
    // One cell at a time, in the block's own order: down each column.
    for (let i = 0; i < 16; i++) { const el = cellOf(root, i % 4, Math.floor(i / 4)); if (el) flip(animate, el, old(i), 55 * i, 300) }
    return
  }
  if (kind === 'AddRoundKey') {
    const flash = getComputedStyle(root).getPropertyValue('--k-key').trim() || undefined
    for (let i = 0; i < 16; i++) { const el = cellOf(root, i % 4, Math.floor(i / 4)); if (el) flip(animate, el, old(i), 45 * i, 280, flash) }
    return
  }
  if (kind === 'MixColumns' || kind === 'InvMixColumns') {
    // One column at a time lifts, its 4 bytes join, and 4 new bytes come out.
    for (const c of ROWS) for (const r of ROWS) {
      const el = cellOf(root, r, c)
      if (!el) continue
      el.dataset.old = old(cellIndex(r, c))
      animate(el, [{ opacity: 1 }, { opacity: 1, offset: 0.45 }, { opacity: 0 }], { duration: 520, delay: 360 * c, pseudo: '::after' })
      animate(el, [{ transform: 'translateY(0) scale(1)' }, { transform: `translateY(${(1.5 - r) * 18}px) scale(0.86)`, offset: 0.45 }, { transform: 'translateY(0) scale(1)' }], { duration: 520, delay: 360 * c })
    }
    return
  }
  if (kind === 'ShiftRows' || kind === 'InvShiftRows') {
    // A roll, one row at a time, like a ticker tape. See rollLeaves for how the row stays full.
    const inverse = kind === 'InvShiftRows'
    const map = inverse ? tables.inverseShiftRows : tables.shiftRows
    const a = cellOf(root, 0, 0), b = cellOf(root, 0, 1)
    const pitch = a && b ? b.offsetLeft - a.offsetLeft : 70
    for (const r of [1, 2, 3]) for (const c of ROWS) {
      const el = cellOf(root, r, c)
      if (!el) continue
      const { by } = shiftOf(map, cellIndex(r, c), inverse)
      const timing = { duration: 160 * Math.abs(by) + 360, delay: 300 * (r - 1), easing: 'linear' }
      animate(el, [{ transform: `translateX(${by * pitch}px)` }, { transform: 'translateX(0)' }], timing)
      if (rollLeaves(c, by)) {
        // The old byte of this column rolls out: it holds still against the moving cell, so it travels from column c to c - by.
        el.dataset.old = old(cellIndex(r, c))
        const away = `translateX(${-by * pitch}px)`
        animate(el, [{ transform: away, opacity: 1 }, { transform: away, opacity: 1, offset: 0.999 }, { transform: away, opacity: 0 }], { ...timing, pseudo: '::after' })
      }
    }
  }
}
