import { expect, test } from '@playwright/test'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { buildSpecs, specSplitter, type SpecRow, type Source } from '../src/specs'
import { open, startTour, walkTourUntil } from './walk'

// Spec cards (docs/walkthrough-design.md section 2.2h): every named spec on screen is a hover card with a synopsis and one link.
const src = path.join(__dirname, '..', 'src')
const read = (f: string) => JSON.parse(fs.readFileSync(path.join(src, f), 'utf8'))
const rows = (read('specs.json') as { specs: SpecRow[] }).specs
const glossary = read('glossary.json') as { terms: Record<string, unknown>[]; sources: Record<string, Source> }
const split = specSplitter(rows)

// A spec-like name, by shape. A name this finds on screen must have a row, or the card rule has a hole.
const SPEC_SHAPE = /(?<![A-Za-z0-9])(?<name>RFC ?\d{3,5}|FIPS ?\d{2,3}(?:-\d)?|SP ?800-\d+[A-Z]?|X9\.\d+(?:-\d)?|PKCS ?#? ?\d+|NIST ?IR ?\d+)(?![A-Za-z0-9])/g

/** Every string under o, except under keys that hold off-screen references. */
function strings(o: unknown, skip: ReadonlySet<string>): string[] {
  if (typeof o === 'string') return [o]
  if (Array.isArray(o)) return o.flatMap(v => strings(v, skip))
  if (o && typeof o === 'object') return Object.entries(o).flatMap(([k, v]) => (skip.has(k) ? [] : strings(v, skip)))
  return []
}

/** The text a learner can read today: tour step text, glossary entry text, and the wizard copy. Claims and source ids stay off screen. */
function onScreenText(): string[] {
  const tours = fs.readdirSync(path.join(src, 'tours')).filter(f => /^lesson-\d+\.json$/.test(f))
  const tourText = tours.flatMap(f => {
    const body = read(path.join('tours', f)) as { steps?: { text?: string[] }[] } | { text?: string[] }[]
    const steps = Array.isArray(body) ? body : body.steps ?? []
    return steps.flatMap(s => s.text ?? [])
  })
  const glossaryText = strings(glossary.terms, new Set(['sources', 'id', 'statusBasis']))
  return [...tourText, ...glossaryText, ...strings(read('wizard-copy.json'), new Set())]
}

test('every row names a source that the glossary holds, and no name or alias belongs to two rows', () => {
  expect(() => buildSpecs(rows, glossary.sources)).not.toThrow()
  const names = rows.flatMap(r => [r.name, ...r.aliases])
  expect(new Set(names).size).toBe(names.length)
  expect(new Set(rows.map(r => r.id)).size).toBe(rows.length)
  expect(() => buildSpecs([{ id: 'x', name: 'RFC 1', aliases: [], source: 'no-such-source', synopsis: '' }], glossary.sources)).toThrow(/no-such-source/)
})

test('every spec name on screen today gets a card', () => {
  const missing: string[] = []
  for (const text of onScreenText()) {
    const covered = split(text).filter(p => p.kind === 'spec').map(p => p.text)
    for (const m of text.matchAll(SPEC_SHAPE)) if (!covered.some(c => c.includes(m.groups!.name))) missing.push(m.groups!.name)
  }
  expect([...new Set(missing)]).toEqual([])
})

test('the longest name wins, a name matches only whole, and a section number stays text beside its card', () => {
  expect(split('ANSI X9.24-3-2017 specifies AES DUKPT.')).toEqual([
    { kind: 'spec', id: 'x9-24-3', text: 'ANSI X9.24-3-2017' },
    { kind: 'text', text: ' specifies AES DUKPT.' },
  ])
  expect(split('SP 800-67 Rev. 2, its standard')[0]).toEqual({ kind: 'spec', id: 'sp800-67', text: 'SP 800-67 Rev. 2' })
  expect(split('RFC 84460 and XRFC 8446').every(p => p.kind === 'text')).toBe(true)
  expect(split('RFC 8446 section 4.2 fixes it')).toEqual([
    { kind: 'spec', id: 'rfc8446', text: 'RFC 8446' },
    { kind: 'text', text: ' section 4.2 fixes it' },
  ])
  expect(split('No spec here.')).toEqual([{ kind: 'text', text: 'No spec here.' }])
})

test('a spec in glossary text opens a card on hover, keeps it while the pointer is on it, and Esc closes it', async ({ page }) => {
  await open(page)
  await page.getByTestId('settings-button').click()
  await page.getByTestId('glossary-open').click()
  await page.getByTestId('glossary-method-des').click()
  const name = page.getByTestId('glossary-detail-des').getByTestId('spec-fips46-3').first()
  const card = page.getByTestId('spec-card-fips46-3')
  await name.hover()
  await expect(card).toBeVisible()
  await expect(card.getByTestId('spec-synopsis')).toHaveText(rows.find(r => r.id === 'fips46-3')!.synopsis)
  const link = card.getByTestId('spec-link')
  await expect(link).toHaveAttribute('href', glossary.sources['fips46-3'].url)
  await expect(link).toHaveAttribute('target', '_blank')
  await expect(link).toHaveAttribute('rel', /noopener/)
  // The pointer moves onto the card, so the link can be clicked. The card stays.
  await link.hover()
  await page.waitForTimeout(600)
  await expect(card).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(card).toBeHidden()
})

test('a spec in tour text opens its card on keyboard focus, and Enter toggles it', async ({ page }) => {
  await startTour(page, 7)
  await walkTourUntil(page, 'the RFC 8996 step', () => page.getByTestId('tour-text').getByTestId('spec-rfc8996').first().isVisible())
  const name = page.getByTestId('tour-text').getByTestId('spec-rfc8996').first()
  const card = page.getByTestId('spec-card-rfc8996')
  // Shift+Tab then Tab lands on the name by keyboard, which is the focus a learner gives it.
  await name.focus()
  await page.keyboard.press('Shift+Tab')
  await page.keyboard.press('Tab')
  await expect(name).toBeFocused()
  await expect(card).toBeVisible()
  await expect(card.getByTestId('spec-link')).toHaveAttribute('href', glossary.sources.rfc8996.url)
  await page.keyboard.press('Escape')
  await expect(card).toBeHidden()
  await name.focus()
  await page.keyboard.press('Enter')
  await expect(card).toBeVisible()
})
