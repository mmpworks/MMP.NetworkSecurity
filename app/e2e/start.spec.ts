import { _electron as electron, expect, test } from '@playwright/test'
import * as path from 'node:path'

// Real Electron: main.cjs spawns the Host with a fresh token and the preload hands it to the renderer. Needs `npm run build` first.
test('Electron starts the Host, the window connects, and the rail shows', async () => {
  const app = await electron.launch({ args: ['.'], cwd: path.join(__dirname, '..'), env: { ...process.env, NETSEC_PORT: '5192', NETSEC_TOKEN: '' } })
  try {
    const win = await app.firstWindow()
    await expect(win.getByTestId('host-chip')).toContainText(/connected/i, { timeout: 60_000 })
    await expect(win.getByTestId('lesson-item-0')).toContainText('Start here')
    await expect(win).toHaveTitle('Network Security Lab')
  } finally { await app.close() }
})
