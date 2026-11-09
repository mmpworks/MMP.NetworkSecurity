import type { Locator, Page } from '@playwright/test'

// WCAG contrast of an element's text on what is really behind it. The page function turns any CSS color into rgba through a canvas,
// then lays the background layers from the page root down to the element, so a translucent box reads as the color the eye sees.
export interface Contrast { ratio: number; fg: string; bg: string }

export async function contrastOf(el: Locator): Promise<Contrast> {
  return el.evaluate((node: Element) => {
    const ctx = document.createElement('canvas').getContext('2d', { willReadFrequently: true })!
    const rgba = (css: string): [number, number, number, number] => {
      ctx.clearRect(0, 0, 1, 1)
      ctx.fillStyle = '#000'
      ctx.fillStyle = css
      ctx.fillRect(0, 0, 1, 1)
      const d = ctx.getImageData(0, 0, 1, 1).data
      return [d[0], d[1], d[2], d[3] / 255]
    }
    const over = (top: number[], under: number[]): number[] => {
      const a = top[3] + under[3] * (1 - top[3])
      if (a === 0) return [0, 0, 0, 0]
      return [0, 1, 2].map(i => (top[i] * top[3] + under[i] * under[3] * (1 - top[3])) / a).concat(a)
    }
    const chain: Element[] = []
    for (let e: Element | null = node; e; e = e.parentElement) chain.unshift(e)
    let bg: number[] = [255, 255, 255, 1]
    for (const e of chain) {
      const cs = getComputedStyle(e)
      bg = over(rgba(cs.backgroundColor), bg)
      const op = Number(cs.opacity)
      if (op < 1 && e !== node) bg = over([...bg.slice(0, 3), op], [255, 255, 255, 1])
    }
    const cs = getComputedStyle(node)
    const fgRaw = rgba(cs.color)
    const fg = over([fgRaw[0], fgRaw[1], fgRaw[2], fgRaw[3] * Number(cs.opacity)], bg)
    const lum = (c: number[]) => { const [r, g, b] = c.slice(0, 3).map(v => { const s = v / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4 }); return 0.2126 * r + 0.7152 * g + 0.0722 * b }
    const [hi, lo] = [lum(fg), lum(bg)].sort((a, b) => b - a)
    return { ratio: (hi + 0.05) / (lo + 0.05), fg: `rgba(${fg.map(v => Math.round(v)).join(',')})`, bg: `rgb(${bg.slice(0, 3).map(v => Math.round(v)).join(',')})` }
  })
}

export const MIN_RATIO = 4.5

// The theme control sits in the Settings menu. A dialog's scrim may cover the top bar, and the theme still has to change under it, so the click goes straight to the button.
export async function setTheme(page: Page, theme: 'system' | 'light' | 'dark') {
  const button = page.getByTestId('settings-button')
  await button.dispatchEvent('click')
  await page.getByTestId('theme-select').selectOption(theme)
  await button.dispatchEvent('click')
}

/**
 * Waits until the screen is still enough to scan: finite transitions end, so a button caught half-way between disabled and enabled is
 * not read as its own color. A transition a Vue update starts appears only after the next frames, and under full CPU load those frames
 * come late. So the check waits 2 frames, and it passes only when 2 checks in a row find no running transition and no aria-busy element
 * (#323: the light sweep once read 3 wizard buttons in their faded colors).
 */
export async function settle(page: Page): Promise<void> {
  let still = 0
  for (let i = 0; i < 25 && still < 2; i++) {
    const moving = await page.evaluate(async () => {
      await new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))
      const running = document.getAnimations().filter(a => a.playState === 'running' && a.effect?.getComputedTiming().iterations !== Infinity)
      await Promise.all(running.map(a => a.finished.catch(() => null)))
      return running.length + document.querySelectorAll('[aria-busy="true"]').length
    })
    still = moving === 0 ? still + 1 : 0
    await page.waitForTimeout(moving === 0 ? 150 : 100)
  }
  // The scan reads anyway. A screen still moving can only read lower, so this line explains a fail; it never hides one (Jared on #325).
  if (still < 2) console.log('settle: the screen did not settle after 25 checks, so the scan reads it while it moves')
}

export interface ScanFail { where: string; text: string; ratio: number; fg: string; bg: string }
export interface Scan { checked: number; fails: ScanFail[] }

/** Every visible element that owns text, tested for contrast. Disabled controls are exempt (WCAG 1.4.3). Large text needs 3 to 1. */
export async function scanPage(page: Page): Promise<Scan> {
  return page.evaluate((min: number) => {
    const ctx = document.createElement('canvas').getContext('2d', { willReadFrequently: true })!
    const rgba = (css: string): number[] => {
      ctx.clearRect(0, 0, 1, 1); ctx.fillStyle = '#000'; ctx.fillStyle = css; ctx.fillRect(0, 0, 1, 1)
      const d = ctx.getImageData(0, 0, 1, 1).data
      return [d[0], d[1], d[2], d[3] / 255]
    }
    const over = (top: number[], under: number[]): number[] => {
      const a = top[3] + under[3] * (1 - top[3])
      if (a === 0) return [0, 0, 0, 0]
      return [0, 1, 2].map(i => (top[i] * top[3] + under[i] * under[3] * (1 - top[3])) / a).concat(a)
    }
    const lum = (c: number[]) => { const [r, g, b] = c.slice(0, 3).map(v => { const s = v / 255; return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4 }); return 0.2126 * r + 0.7152 * g + 0.0722 * b }
    // Background layers from the root down. An element with opacity below 1 fades everything inside it toward the backdrop it sat on,
    // so each such element keeps its backdrop and the text color and the box color are both faded toward it at the end.
    const bgOf = (node: Element): { bg: number[]; fades: { op: number; back: number[] }[] } => {
      const chain: Element[] = []
      for (let e: Element | null = node; e; e = e.parentElement) chain.unshift(e)
      let bg = [255, 255, 255, 1]
      const fades: { op: number; back: number[] }[] = []
      for (const e of chain) {
        const cs = getComputedStyle(e)
        const op = Number(cs.opacity)
        if (op < 1) fades.push({ op, back: bg })
        if (!(e instanceof SVGElement) || e instanceof SVGSVGElement) bg = over(rgba(cs.backgroundColor), bg)
      }
      // A shape drawn before this SVG text and under its center is the box behind it (a chip, a note).
      if (node instanceof SVGTextElement) {
        const tb = node.getBoundingClientRect()
        const cx = tb.x + tb.width / 2
        const cy = tb.y + tb.height / 2
        const shapes = Array.from(node.ownerSVGElement?.querySelectorAll('rect,circle,ellipse,path,polygon') ?? [])
        let behind: Element | null = null
        for (const s of shapes) {
          if (!(s.compareDocumentPosition(node) & Node.DOCUMENT_POSITION_FOLLOWING)) continue
          const sb = s.getBoundingClientRect()
          if (sb.width > 0 && cx >= sb.x && cx <= sb.x + sb.width && cy >= sb.y && cy <= sb.y + sb.height && getComputedStyle(s).fill !== 'none') behind = s
        }
        if (behind) { const f = getComputedStyle(behind); const c = rgba(f.fill); bg = over([c[0], c[1], c[2], c[3] * Number(f.fillOpacity) * Number(f.opacity)], bg) }
      }
      return { bg, fades }
    }
    const where = (e: Element) => {
      const t = e.closest('[data-testid]')?.getAttribute('data-testid')
      return `${e.tagName.toLowerCase()}${e.className && typeof e.className === 'string' ? '.' + e.className.split(' ')[0] : ''}${t ? '[' + t + ']' : ''}`
    }
    const fails: { where: string; text: string; ratio: number; fg: string; bg: string }[] = []
    let checked = 0
    for (const node of Array.from(document.querySelectorAll('body *'))) {
      const own = Array.from(node.childNodes).filter(n => n.nodeType === 3 && (n.textContent ?? '').trim()).map(n => (n.textContent ?? '').trim()).join(' ')
      if (!own) continue
      const r = node.getBoundingClientRect()
      const cs = getComputedStyle(node)
      if (r.width < 1 || r.height < 1 || cs.visibility === 'hidden' || cs.display === 'none') continue
      if (node.closest('[disabled],[aria-disabled="true"],.v-btn--disabled,.v-chip--disabled,script,style')) continue
      if (node.closest('.v-overlay--active') === null && node.closest('.v-overlay')) continue
      const svg = node instanceof SVGElement
      const colorCss = svg ? cs.fill : cs.color
      const raw = rgba(colorCss)
      const model = bgOf(node)
      let bg = model.bg
      let fg = over([raw[0], raw[1], raw[2], raw[3]], bg)
      for (const f of model.fades.slice().reverse()) { bg = over([bg[0], bg[1], bg[2], f.op], f.back); fg = over([fg[0], fg[1], fg[2], f.op], f.back) }
      const [hi, lo] = [lum(fg), lum(bg)].sort((a, b) => b - a)
      const ratio = (hi + 0.05) / (lo + 0.05)
      const px = parseFloat(cs.fontSize)
      const large = px >= 24 || (px >= 18.66 && Number(cs.fontWeight) >= 700)
      checked++
      if (ratio < (large ? 3 : min)) fails.push({ where: where(node), text: own.slice(0, 40), ratio: Math.round(ratio * 100) / 100, fg: `rgb(${fg.slice(0, 3).map(v => Math.round(v)).join(',')})`, bg: `rgb(${bg.slice(0, 3).map(v => Math.round(v)).join(',')})` })
    }
    return { checked, fails }
  }, MIN_RATIO)
}
