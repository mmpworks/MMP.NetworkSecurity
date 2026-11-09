import { expect, test, type Page } from '@playwright/test'
import { fieldMultiplyWords } from '../src/walk'
import { scanPage, setTheme } from './contrast'
import { open } from './walk'

// Steve's 3 block-walk items from the mock ("The block" tab): the round key grid beside the state on AddRoundKey, the MixColumns multiply
// panel, and the bit lines. The checks compute XOR and the field multiply themselves, so they test the screen against FIPS 197, not
// against the app's own code.

async function openPractice(page: Page) {
  await page.emulateMedia({ reducedMotion: 'reduce' })
  await open(page)
  await page.getByTestId('section-techniques').click()
  await page.getByTestId('walk-item-aes').click()
  await expect(page.getByTestId('aes-walk-step-kind')).toBeVisible()
}
async function toStop(page: Page, n: number) { for (let i = 0; i < n; i++) await page.getByTestId('aes-walk-next').click() }
const FILL_END = 16
const FIRST_STEP = FILL_END + 1 + 41 // AES-128: 17 fill stops, 41 key stops, then AddRoundKey of round 0
const hexAt = async (page: Page, prefix: string, r: number, c: number) => (await page.getByTestId(`${prefix}-${r}-${c}`).getAttribute('data-hex')) ?? ''
async function grid(page: Page, prefix: string): Promise<string[]> {
  const out: string[] = []
  for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) out[r + 4 * c] = await hexAt(page, prefix, r, c)
  return out
}
const xor = (a: string, b: string) => (parseInt(a, 16) ^ parseInt(b, 16)).toString(16).padStart(2, '0')
const bits = (h: string) => parseInt(h, 16).toString(2).padStart(8, '0')
/** FIPS 197 section 4.2: multiply by 1, 2 or 3 in GF(2^8). The test's own oracle. */
function mul(factor: number, h: string): string {
  const b = parseInt(h, 16), d = ((b << 1) ^ (b & 0x80 ? 0x1b : 0)) & 0xff
  return (factor === 1 ? b : factor === 2 ? d : d ^ b).toString(16).padStart(2, '0')
}
const flat = async (page: Page, id: string) => ((await page.getByTestId(id).textContent()) ?? '').replace(/\s+/g, '')

test('AddRoundKey of round 0 shows the round key grid titled "Round key 0", and each state byte is the byte before XOR the key byte', async ({ page }) => {
  await openPractice(page)
  await toStop(page, FILL_END)
  const before = await grid(page, 'aes-walk-cell')
  await toStop(page, FIRST_STEP - FILL_END)
  await expect(page.getByTestId('aes-walk-step-kind')).toHaveText('AddRoundKey')
  await expect(page.getByTestId('aes-walk-round-key-label')).toHaveText('Round key 0')
  const key = await grid(page, 'aes-walk-round-key-cell'), after = await grid(page, 'aes-walk-cell')
  for (let i = 0; i < 16; i++) {
    expect(key[i], `key byte ${i}`).toMatch(/^[0-9a-f]{2}$/)
    expect(after[i], `byte ${i}: before XOR key`).toBe(xor(before[i], key[i]))
  }
  // The bit lines for the picked byte: the state byte, the key byte and the result, each as 8 bits.
  await page.getByTestId('aes-walk-cell-2-1').click()
  const i = 2 + 4 * 1
  const line = await flat(page, 'aes-walk-ark-bits')
  for (const v of [before[i], key[i], after[i]]) expect(line, `the bit lines show ${v}`).toContain(bits(v))
  for (const part of ['state', 'key', 'result']) await expect(page.getByTestId(`aes-walk-bits-${part}`)).toBeVisible()
  // Round 1's AddRoundKey names its own key.
  await toStop(page, 4)
  await expect(page.getByTestId('aes-walk-step-kind')).toHaveText('AddRoundKey')
  await expect(page.getByTestId('aes-walk-round-key-label')).toHaveText('Round key 1')
})

// Under reduced motion no step plays, so no cell may keep an old byte on its top layer: the learner must see the engine's new byte.
// Found in this PR's pictures: AddRoundKey showed the bytes before the XOR, under the result (pre-existing on main).
test('under reduced motion every step lands on its new bytes, with no old byte left on top of a cell', async ({ page }) => {
  await openPractice(page)
  await toStop(page, FIRST_STEP)
  for (let n = 0; n < 5; n++) {
    const kind = ((await page.getByTestId('aes-walk-step-kind').textContent()) ?? '').trim()
    expect(await page.locator('[data-testid^="aes-walk-cell-"][data-old]').count(), `${kind}: no old byte on top`).toBe(0)
    await toStop(page, 1)
  }
})

test('with motion on, the round key bytes move to meet the state bytes on AddRoundKey', async ({ page }) => {
  await openPractice(page)
  await toStop(page, FIRST_STEP - 1)
  await page.emulateMedia({ reducedMotion: 'no-preference' })
  await page.getByTestId('aes-walk-next').click()
  const moving = await page.evaluate(() => document.getAnimations().filter(a => {
    const t = (a.effect as KeyframeEffect | null)?.target as Element | null
    return !!t?.closest?.('[data-testid="aes-walk-round-key-grid"]')
  }).length)
  expect(moving, 'the key cells animate').toBeGreaterThan(0)
})

test('MixColumns shows the multiply panel: the fixed matrix, the state column, each product, the XOR sum, and the column filling', async ({ page }) => {
  await openPractice(page)
  await toStop(page, FIRST_STEP + 2)
  const before = await grid(page, 'aes-walk-cell')
  await toStop(page, 1)
  await expect(page.getByTestId('aes-walk-step-kind')).toHaveText('MixColumns')
  const after = await grid(page, 'aes-walk-cell')
  await expect(page.getByTestId('aes-walk-mix-panel')).toBeVisible()
  for (let c = 0; c < 4; c++) await expect(page.getByTestId(`aes-walk-mix-col-${c}`)).toHaveText(`Column ${c}`)
  const factors: string[] = []
  for (let k = 0; k < 4; k++) factors.push(((await page.getByTestId(`aes-walk-mix-matrix-0-${k}`).textContent()) ?? '').trim())
  expect(factors, 'row 0 of the fixed matrix').toEqual(['2', '3', '1', '1'])
  expect(await grid(page, 'aes-walk-mix-before'), 'the panel shows the state before').toEqual(before)
  // Position 0: row 0 times byte 0 of column 0, boxed, with its product line.
  await expect(page.getByTestId('aes-walk-mix-matrix-0-0')).toHaveAttribute('data-pair', 'true')
  await expect(page.getByTestId('aes-walk-mix-before-0-0')).toHaveAttribute('data-pair', 'true')
  await expect(page.getByTestId('aes-walk-mix-line')).toContainText(`2 × ${before[0]} = ${mul(2, before[0])}`)
  // The field multiply's own numbers, from the engine's doubling: the shift before the 11b XOR, and the byte it gives.
  const shifted = (b: string) => (parseInt(b, 16) << 1).toString(16).padStart(3, '0')
  const big = (b: string) => (parseInt(b, 16) & 0x80) !== 0
  // An overflowing byte shows its 3-digit shift; a byte that fits shows the doubled byte itself.
  if (big(before[0])) await expect(page.getByTestId('aes-walk-mix-line')).toContainText(`to get ${shifted(before[0])}. That is too big for a byte, so XOR 11b. It gives ${mul(2, before[0])}`)
  else await expect(page.getByTestId('aes-walk-mix-line')).toContainText(`left by one: ${mul(2, before[0])}. It fits in a byte`)
  // Step through row 0: 4 products, then the XOR sum, which lands in the state after.
  for (let k = 1; k < 4; k++) {
    await page.getByTestId('aes-walk-mix-next').click()
    await expect(page.getByTestId('aes-walk-mix-line')).toContainText(`${factors[k]} × ${before[k]} = ${mul(Number(factors[k]), before[k])}`)
    // A factor of 3 is the doubled byte XOR the byte itself.
    if (factors[k] === '3') await expect(page.getByTestId('aes-walk-mix-line')).toContainText(`${mul(2, before[k])} XOR ${before[k]} = ${mul(3, before[k])}`)
  }
  await expect(page.getByTestId('aes-walk-mix-after-0-0')).toHaveAttribute('data-hex', '')
  await page.getByTestId('aes-walk-mix-next').click()
  const products = [0, 1, 2, 3].map(k => mul(Number(factors[k]), before[k]))
  const sum = products.reduce(xor)
  expect(sum, 'the oracle agrees with the engine').toBe(after[0])
  await expect(page.getByTestId('aes-walk-mix-after-0-0')).toHaveAttribute('data-hex', after[0])
  await expect(page.getByTestId('aes-walk-mix-line')).toContainText(`Output byte 0 = ${after[0]}`)
  const sumBits = await flat(page, 'aes-walk-mix-bits')
  for (const v of [...products, after[0]]) expect(sumBits, `the XOR sum's bit lines show ${v}`).toContain(bits(v))
  // Fill all: the state after equals the step's result.
  await page.getByTestId('aes-walk-mix-fill').click()
  expect(await grid(page, 'aes-walk-mix-after')).toEqual(after)
  // A column tab starts that column at its first product.
  await page.getByTestId('aes-walk-mix-col-2').click()
  await expect(page.getByTestId('aes-walk-mix-before-0-2')).toHaveAttribute('data-pair', 'true')
  await expect(page.getByTestId('aes-walk-mix-line')).toContainText(`2 × ${before[8]} = ${mul(2, before[8])}`)
})

/** FIPS 197 section 4.2 for any factor: the sum of the doublings its set bits pick. The decrypt walk uses 9, 11, 13 and 14. */
function mulAny(factor: number, h: string): { result: string; doubles: string[]; over: string[] } {
  let x = parseInt(h, 16), out = 0
  const doubles: string[] = [], over: string[] = []
  for (let bit = 0; 1 << bit <= factor; bit++) {
    if (factor & (1 << bit)) out ^= x
    if (1 << (bit + 1) <= factor) {
      if (x & 0x80) over.push(`×${1 << (bit + 1)}`)
      x = ((x << 1) ^ (x & 0x80 ? 0x1b : 0)) & 0xff
      doubles.push(x.toString(16).padStart(2, '0'))
    }
  }
  return { result: out.toString(16).padStart(2, '0'), doubles, over }
}
/** The overflow words both panels use for a factor with several doublings (Richard on #330). */
const overWords = (over: string[]) => over.length === 0 ? '' : over.length === 1 ? `${over[0]} was too big for a byte, so it got XOR 11b`
  : `${over.join(' and ')} were too big for a byte, so each got XOR 11b`

// Jared on #330: with no doublings in a reply, the line falls back to words with no numbers, and never prints "Double 0 times".
test('a term with no doublings gets the general sentence, with no invented numbers', () => {
  const words = fieldMultiplyWords({ factor: 9, input: '96', reduced: true, result: '4a' })
  expect(words).toContain('9 is 8 + 1')
  expect(words).not.toContain('Double 0')
  expect(words).not.toMatch(/×[248] = [0-9a-f]{2}/)
  expect(words).toContain('The result is 4a.')
  expect(words, 'no stray ": =" (Jared on #337)').not.toContain(': =')
})

// Richard on #330: on the decrypt walk the factors are 14, 11, 13 and 9, and each line must say how that factor is built, not "times 3".
test('on the decrypt walk, InvMixColumns explains factors 14, 11, 13 and 9 by their doublings', async ({ page }) => {
  await openPractice(page)
  for (let i = 0; i < 140 && ((await page.getByTestId('aes-walk-step-kind').textContent()) ?? '').trim() !== 'InvMixColumns'; i++) await toStop(page, 1)
  await expect(page.getByTestId('aes-walk-step-kind')).toHaveText('InvMixColumns')
  const before = await grid(page, 'aes-walk-mix-before')
  const factors: number[] = []
  for (let k = 0; k < 4; k++) factors.push(Number(((await page.getByTestId(`aes-walk-mix-matrix-0-${k}`).textContent()) ?? '').trim()))
  expect(factors, 'row 0 of the inverse matrix').toEqual([14, 11, 13, 9])
  const words: Record<number, string> = { 9: '9 is 8 + 1', 11: '11 is 8 + 2 + 1', 13: '13 is 8 + 4 + 1', 14: '14 is 8 + 4 + 2' }
  for (let k = 0; k < 4; k++) {
    if (k > 0) await page.getByTestId('aes-walk-mix-next').click()
    const f = factors[k], { result, doubles } = mulAny(f, before[k])
    const line = page.getByTestId('aes-walk-mix-line')
    await expect(line).toContainText(`${f} × ${before[k]} = ${result}`)
    await expect(line).toContainText(words[f])
    await expect(line).not.toContainText('Times 3')
    // The 3 doublings, ×2, ×4 and ×8 (Jared: "x2" read as a variable name), then the result.
    await expect(line).toContainText(`×2 = ${doubles[0]}, ×4 = ${doubles[1]}, ×8 = ${doubles[2]}`)
    await expect(line).toContainText(`= ${result}.`)
  }
  // The field panel above names the same overflowed doublings for each term of byte 0, so the 2 panels agree (Richard on #330).
  await page.getByTestId('aes-walk-cell-0-0').click()
  for (let j = 0; j < 4; j++) {
    const { over } = mulAny(factors[j], before[j])
    const term = page.getByTestId(`aes-walk-term-${j}`)
    if (over.length) await expect(term, `term ${j}`).toContainText(overWords(over))
    else await expect(term, `term ${j}`).not.toContainText('too big')
  }
})

for (const theme of ['light', 'dark'] as const) {
  test(`the round key grid, the bit lines and the multiply panel read at 4.5 to 1 in the ${theme} theme`, async ({ page }) => {
    await openPractice(page)
    await setTheme(page, theme)
    await toStop(page, FIRST_STEP)
    let s = await scanPage(page)
    expect(s.fails, `AddRoundKey: ${JSON.stringify(s.fails.slice(0, 5))}`).toEqual([])
    await toStop(page, 3)
    await page.getByTestId('aes-walk-mix-next').click()
    s = await scanPage(page)
    expect(s.checked, 'the scan read the multiply panel').toBeGreaterThan(80)
    expect(s.fails, `MixColumns: ${JSON.stringify(s.fails.slice(0, 5))}`).toEqual([])
  })
}

test('Play this column fills the column one byte at a time', async ({ page }) => {
  await openPractice(page)
  await toStop(page, FIRST_STEP + 3)
  await page.emulateMedia({ reducedMotion: 'no-preference' })
  // The panel plays on the walk's clock, so the walk's own speed control sets its pace.
  await page.getByTestId('aes-walk-speed').getByRole('button', { name: 'fast' }).click()
  await page.getByTestId('aes-walk-mix-play').click()
  const seen = new Set<number>()
  const start = Date.now()
  while (Date.now() - start < 40_000) {
    let n = 0
    for (let r = 0; r < 4; r++) if (await hexAt(page, 'aes-walk-mix-after', r, 0)) n++
    seen.add(n)
    if (n === 4) break
    await page.waitForTimeout(100)
  }
  expect([...seen].sort(), 'the column fills 0, 1, 2, 3, then 4 bytes').toEqual([0, 1, 2, 3, 4])
})
