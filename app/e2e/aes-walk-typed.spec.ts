import { expect, test, type Page } from '@playwright/test'
import fs from 'node:fs'
import path from 'node:path'
import gloss from '../src/walk-gloss.json'
import { open, runFreePlay } from './walk'

// The strip's default text is a copy of lesson 1's text. This pins the copy to the engine's source, so a change to either one fails here (Jared on #270).
test('the strip\'s lesson text equals the text in Lesson01Aes.cs', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'NetSec.Core', 'Labs', 'Lesson01Aes.cs'), 'utf8')
  const found = /static readonly byte\[\] Text = Encoding\.UTF8\.GetBytes\("(?<text>[^"]*)"\)/.exec(source)
  expect(found?.groups?.text, 'Lesson01Aes.cs still declares Text').toBeDefined()
  expect(gloss.typed.lessonText).toBe(found!.groups!.text)
  expect(found!.groups!.text.startsWith(gloss.typed.defaultBlock), 'chapter 1\'s default block is the lesson text\'s first 16 bytes').toBe(true)
})

// The learner's own text and the practice walk (docs/walkthrough-design.md section 2.2g). The engine cuts the 16 bytes; the box marks
// what the block does not use. The practice key is public, so its walk stays open with Show keys off.

const cell = (page: Page, r: number, c: number) => page.getByTestId(`aes-walk-cell-${r}-${c}`)

async function keysOn(page: Page) {
  const sw = page.getByTestId('show-keys-switch')
  if (!(await sw.isChecked())) await sw.click()
  await expect(sw).toBeChecked()
}

// Under reduced motion each Next lands at once. With motion on, a Next during a motion only finishes it (design 2.2a).
test.beforeEach(async ({ page }) => { await page.emulateMedia({ reducedMotion: 'reduce' }) })

async function fillBlock(page: Page) {
  for (let i = 0; i < 16; i++) await page.getByTestId('aes-walk-next').click()
}

test('with no run, Techniques AES shows the practice walk on the default text', async ({ page }) => {
  await open(page)
  await page.getByTestId('section-techniques').click()
  await page.getByTestId('walk-item-aes').click()
  // With no run there is no run's key to compare with, so the line leaves those words out.
  await expect(page.getByTestId('aes-walk-key-source')).toHaveText('This is a practice key. It is public, so it stays on screen with Show keys off')
  await expect(page.getByTestId('aes-walk-wire-label')).toHaveText('Your text. It did not go on the wire.')
  await fillBlock(page)
  const letters: string[] = []
  for (let r = 0; r < 4; r++) letters.push((await cell(page, r, 0).getAttribute('data-letter')) ?? '')
  expect(letters.join(''), 'the default text starts the block').toBe('Pump')
})

test('typed text longer than 16 bytes walks its first 16 bytes and marks the rest as not included', async ({ page }) => {
  await open(page)
  await page.getByTestId('section-techniques').click()
  await page.getByTestId('walk-item-aes').click()
  const [reply] = await Promise.all([
    page.waitForResponse(r => r.url().includes('/api/walk/aes/typed-block') && r.request().postDataJSON()?.text === 'Valve two is open now.'),
    page.getByTestId('aes-walk-text').locator('input').fill('Valve two is open now.'),
  ])
  expect(reply.ok()).toBe(true)
  // "Valve two is ope" is 16 bytes, so "n now." is the part the block does not use.
  await expect(page.getByTestId('aes-walk-text-not-included')).toHaveText('n now.')
  await fillBlock(page)
  const top: string[] = []
  for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) top.push((await cell(page, r, c).getAttribute('data-letter')) ?? '')
  expect(top.join(''), 'the block holds the first 16 bytes').toBe('Valve two is ope')
  await expect(page.getByTestId('aes-long-block-1'), 'the strip shows the typed text').toContainText('n now.')
})

test('with Show keys off, the run walk closes and its offer opens the practice walk', async ({ page }) => {
  await runFreePlay(page, 1)
  await page.getByTestId('aes-walk-tab').click()
  await expect(page.getByTestId('aes-walk-key-source')).toHaveText("This run's key")
  try {
    await page.getByTestId('show-keys-switch').click()
    await expect(page.getByTestId('aes-walk-closed')).toBeVisible()
    await expect(page.locator('[data-testid^="aes-walk-cell-"]')).toHaveCount(0)
    await page.getByTestId('aes-walk-practice-offer').click()
    await expect(page.getByTestId('aes-walk-closed'), 'the practice walk is open').toHaveCount(0)
    await expect(cell(page, 0, 0)).toBeVisible()
    await expect(page.getByTestId('aes-walk-key-differs')).toContainText("This key differs from the run's.")
    await expect(page.getByTestId('aes-walk-key-source'), 'beside a run, the line names the run').toHaveText("This is a practice key, not this run's key. It is public, so it stays on screen with Show keys off")
  } finally {
    await keysOn(page)
  }
})
