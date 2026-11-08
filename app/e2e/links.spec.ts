import { _electron as electron, expect, test } from '@playwright/test'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import { createRequire } from 'node:module'
import { PORTS } from './ports'

// The Electron link rule (docs/ux-design.md section 5a): no second window, https only, an exact host from the list, and no navigation away.
const glossary = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'src', 'glossary.json'), 'utf8')) as { sources: Record<string, { url: string }> }
const { HOSTS, isAllowedLink } = createRequire(__filename)('../electron/link-hosts.cjs') as { HOSTS: Set<string>; isAllowedLink: (u: string) => boolean }
const sourceHosts = [...new Set(Object.values(glossary.sources).map(s => new URL(s.url).hostname))].sort()

test('the link list equals the hosts of the glossary sources', () => {
  expect([...HOSTS].sort()).toEqual(sourceHosts)
})

test('the rule takes every glossary source and refuses http, look-alike hosts, user info, a port, other schemes and text that is no URL', () => {
  for (const s of Object.values(glossary.sources)) expect(isAllowedLink(s.url), s.url).toBe(true)
  const refused = [
    'http://csrc.nist.gov/pubs/fips/46-3/final',
    'https://evil-csrc.nist.gov.example/',
    'https://csrc.nist.gov.evil.example/',
    'https://evil.example/csrc.nist.gov',
    'https://nist.gov/',
    'https://user:pw@doi.org/',
    'https://doi.org@evil.example/',
    'https://csrc.nist.gov@evil.example/',
    'https://doi.org:4444/10.6028/x',
    'https://csrc.nist.gov:8443/pubs/fips/46-3/final',
    'https://sub.csrc.nist.gov/',
    'https://evilcsrc.nist.gov/',
    'ftp://csrc.nist.gov/',
    '',
    'javascript:alert(1)',
    'file:///C:/Windows/notepad.exe',
    'not a url',
  ]
  for (const bad of refused) expect(isAllowedLink(bad), bad).toBe(false)
})

// shell.openExternal is replaced in the main process, so this test opens no browser.
test('real Electron sends only a listed https link outside, opens no second window, and stays on its page', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-e2e-links-'))
  const app = await electron.launch({ args: ['.'], cwd: path.join(__dirname, '..'), env: { ...process.env, NETSEC_PORT: String(PORTS.electron), NETSEC_TOKEN: 'links-token', NETSEC_SECURITY_DIR: dir } })
  try {
    const win = await app.firstWindow()
    await expect(win.getByTestId('host-chip')).toContainText(/connected/i, { timeout: 60_000 })
    await app.evaluate(({ shell }) => { (globalThis as any).opened = []; shell.openExternal = async (url: string) => { (globalThis as any).opened.push(url) } })
    const page = win.url()
    const good = Object.values(glossary.sources)[0].url
    for (const url of [good, 'https://evil.example/', 'http://csrc.nist.gov/', 'javascript:alert(1)'])
      await win.evaluate(u => { window.open(u, '_blank') }, url)
    await win.evaluate(() => { const a = document.createElement('a'); a.href = 'https://evil.example/'; document.body.appendChild(a); a.click(); a.remove() })
    await win.waitForTimeout(800)
    expect(await app.evaluate(() => (globalThis as any).opened), 'links sent outside').toEqual([good])
    expect(await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().length), 'windows').toBe(1)
    expect(win.url(), 'the app left its page').toBe(page)
  } finally { await app.close() }
})
