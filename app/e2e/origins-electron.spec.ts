import { _electron as electron, expect, test } from '@playwright/test'
import * as path from 'node:path'
import { PORTS } from './ports'

// NETSEC_ORIGINS is for test runs. Electron blanks it for the Host it spawns, so a value exported in a developer's shell never
// widens the desktop app's Host. An allowed Origin with no token gets 401 HOST_TOKEN_REFUSED; a refused Origin gets 403
// HOST_ORIGIN_REFUSED before the token is looked at, so the status tells the two apart without knowing Electron's random token.
const PORT = PORTS.electron
const EXTRA = 'http://localhost:4181'

async function probe(origin: string) {
  const res = await fetch(`http://127.0.0.1:${PORT}/api/health`, { headers: { Origin: origin } })
  return { status: res.status, body: await res.text() }
}

test('Electron strips NETSEC_ORIGINS from the Host it spawns', async () => {
  const app = await electron.launch({ args: ['.'], cwd: path.join(__dirname, '..'), env: { ...process.env, NETSEC_PORT: String(PORT), NETSEC_TOKEN: '', NETSEC_ORIGINS: EXTRA } })
  try {
    const win = await app.firstWindow()
    await expect(win.getByTestId('host-chip')).toContainText(/connected/i, { timeout: 60_000 })
    const builtIn = await probe('http://localhost:4180')            // control: the Host is up and a built-in origin reaches the token check
    expect(builtIn.status).toBe(401)
    expect(builtIn.body).toContain('HOST_TOKEN_REFUSED')
    const extra = await probe(EXTRA)                               // the exported extra origin stays refused
    expect(extra.status).toBe(403)
    expect(extra.body).toContain('HOST_ORIGIN_REFUSED')
  } finally { await app.close() }
})
