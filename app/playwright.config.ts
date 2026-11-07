// Lesson 0 end to end: the built renderer on `vite preview` and a real NetSec.Host process. One worker, because the Host keeps one session store.
// NETSEC_HOST_DLL points at NetSec.Host.dll when the Host sits outside this checkout.
import { defineConfig } from '@playwright/test'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

export const HOST_PORT = 5190
export const TOKEN = 'lesson0-token'
const hostDll = process.env.NETSEC_HOST_DLL ?? path.resolve(__dirname, '..', 'src', 'NetSec.Host', 'bin', 'Release', 'net10.0', 'NetSec.Host.dll')

// The suite runs the Release Host. A Debug build, a pull or a branch switch leaves that DLL older than the code, and the specs then test an old Host
// with no warning. So a run refuses to start while any source file under src/ is newer than the DLL. A Host that the person names in NETSEC_HOST_DLL is theirs to keep current.
function newestSource(dir: string): { file: string; ms: number } {
  let best = { file: '', ms: 0 }
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'bin' || entry.name === 'obj') continue
    const full = path.join(dir, entry.name)
    if (entry.isDirectory()) { const inner = newestSource(full); if (inner.ms > best.ms) best = inner }
    else if (entry.name.endsWith('.cs') || entry.name.endsWith('.csproj')) { const ms = fs.statSync(full).mtimeMs; if (ms > best.ms) best = { file: full, ms } }
  }
  return best
}
if (!process.env.NETSEC_HOST_DLL) {
  const newest = newestSource(path.resolve(__dirname, '..', 'src'))
  const built = fs.existsSync(hostDll) ? fs.statSync(hostDll).mtimeMs : 0
  if (built < newest.ms) {
    throw new Error(`HOST_DLL_STALE: ${built ? 'the Release Host is older than ' + path.relative(path.resolve(__dirname, '..'), newest.file) : 'no Release Host at ' + hostDll}. `
      + 'Rebuild it from the repo root: dotnet build src/NetSec.Host -c Release')
  }
}

// The Host reads its security folder once at start, and every spec on port 5190 shares that Host, so a run has one folder. Without this line the Host
// falls back to the tree's .security folder, which holds keys from earlier runs. Workers inherit the value, so the config makes one folder per run.
process.env.NETSEC_SECURITY_DIR ??= fs.mkdtempSync(path.join(os.tmpdir(), 'ns-e2e-security-'))
// A name of its own, so NETSEC_HOST_DLL stays as the person set it and start.spec still runs the path fallback in electron/main.cjs.
process.env.NETSEC_E2E_HOST_DLL = hostDll

export default defineConfig({
  testDir: './e2e',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  workers: 1,
  fullyParallel: false,
  retries: 0,
  reporter: [['list']],
  use: { baseURL: 'http://localhost:4180', viewport: { width: 1440, height: 900 }, trace: 'retain-on-failure' },
  webServer: [
    { command: 'npx vite preview --port 4180 --strictPort', port: 4180, reuseExistingServer: false, timeout: 60_000 },
    { command: `dotnet "${hostDll}"`, port: HOST_PORT, reuseExistingServer: false, timeout: 60_000, env: { NETSEC_PORT: String(HOST_PORT), NETSEC_TOKEN: TOKEN } },
    // A second Host on a damaged vault master key, for the VAULT_MASTER_KEY_BAD spec only.
    { command: 'node e2e/start-bad-key-host.cjs', port: 5191, reuseExistingServer: false, timeout: 60_000, env: { NETSEC_HOST_DLL: hostDll } },
  ],
})
