// Lesson 0 end to end: the built renderer on `vite preview` and a real NetSec.Host process. One worker, because the Host keeps one session store.
// NETSEC_HOST_DLL points at NetSec.Host.dll when the Host sits outside this checkout.
import { defineConfig } from '@playwright/test'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { HOST_ORIGIN_ENV, PORTS } from './e2e/ports'

export const HOST_PORT = PORTS.host
export const TOKEN = 'lesson0-token'
const hostDll = process.env.NETSEC_HOST_DLL ?? path.resolve(__dirname, '..', 'src', 'NetSec.Host', 'bin', 'Release', 'net10.0', 'NetSec.Host.dll')

// The suite runs the Release Host. A Debug build, a pull or a branch switch leaves that build older than the code, and the specs then test an old Host
// with no warning. So a run refuses to start while any file in the Host's own projects (bin and obj aside) is newer than every file in the Release output folder.
// The Host's projects come from its csproj ProjectReference lines, followed down, so a project the Host does not build (NetSec.Node, the CE projects) never blocks a run.
// It compares with the whole folder, not the DLL: a data file such as wizard-flows.json is copied there with no compile, and a copy keeps its source's time,
// so a fresh copy ties and passes. A Host that the person names in NETSEC_HOST_DLL is theirs to keep current.
// Limit: the Host also builds MMP.AsyncProxy from a sibling repo outside src/, and a change there is not seen.
const PROJECT_REF = /<ProjectReference\s+Include="(?<ref>[^"]+\.csproj)"/g
/** The folders of a project and every project it references, followed down. XML comments are skipped. */
function projectFolders(csproj: string, seen = new Set<string>()): Set<string> {
  const dir = path.dirname(csproj)
  if (seen.has(dir) || !fs.existsSync(csproj)) return seen
  seen.add(dir)
  const xml = fs.readFileSync(csproj, 'utf8').replace(/<!--[\s\S]*?-->/g, '')
  for (const m of xml.matchAll(PROJECT_REF)) projectFolders(path.resolve(dir, m.groups!.ref.replace(/\\/g, '/')), seen)
  return seen
}
function newestFile(dir: string): { file: string; ms: number } {
  let best = { file: '', ms: 0 }
  if (!fs.existsSync(dir)) return best
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'bin' || entry.name === 'obj') continue
    const full = path.join(dir, entry.name)
    const found = entry.isDirectory() ? newestFile(full) : { file: full, ms: fs.statSync(full).mtimeMs }
    if (found.ms > best.ms) best = found
  }
  return best
}
if (!process.env.NETSEC_HOST_DLL) {
  const folders = projectFolders(path.resolve(__dirname, '..', 'src', 'NetSec.Host', 'NetSec.Host.csproj'))
  const newest = [...folders].map(d => newestFile(d)).reduce((a, b) => (b.ms > a.ms ? b : a), { file: '', ms: 0 })
  const built = fs.existsSync(hostDll) ? newestFile(path.dirname(hostDll)).ms : 0
  if (built < newest.ms) {
    throw new Error(`HOST_DLL_STALE: ${built ? 'the Release Host is older than ' + path.relative(path.resolve(__dirname, '..'), newest.file) : 'no Release Host at ' + hostDll}. `
      + 'Rebuild it from the repo root: dotnet build src/NetSec.Host -c Release')
  }
}

// The Host reads its security folder once at start, and every spec on the Host port shares that Host, so a run has one folder. Without this line the Host
// falls back to the tree's .security folder, which holds keys from earlier runs. Workers inherit the value, so the config makes one folder per run.
process.env.NETSEC_SECURITY_DIR ??= fs.mkdtempSync(path.join(os.tmpdir(), 'ns-e2e-security-'))
// A name of its own, so NETSEC_HOST_DLL stays as the person set it and start.spec still runs the path fallback in electron/main.cjs.
process.env.NETSEC_E2E_HOST_DLL = hostDll

// The preview server runs from the local vite file, never the package runner: that can run a package of the same name from outside this repo.
const viteCli = path.resolve(__dirname, 'node_modules', 'vite', 'bin', 'vite.js')
if (!fs.existsSync(viteCli)) throw new Error(`TOOL_MISSING: ${viteCli} is absent. Run npm ci in app/.`)

export default defineConfig({
  testDir: './e2e',
  timeout: 120_000,
  expect: { timeout: 15_000 },
  workers: 1,
  fullyParallel: false,
  retries: 0,
  reporter: [['list']],
  globalSetup: './e2e/commit-line.ts',
  use: { baseURL: `http://localhost:${PORTS.preview}`, viewport: { width: 1440, height: 900 }, trace: 'retain-on-failure' },
  webServer: [
    { command: `node "${viteCli}" preview --port ${PORTS.preview} --strictPort`, port: PORTS.preview, reuseExistingServer: false, timeout: 60_000 },
    { command: `dotnet "${hostDll}"`, port: HOST_PORT, reuseExistingServer: false, timeout: 60_000, env: { NETSEC_PORT: String(HOST_PORT), NETSEC_TOKEN: TOKEN, ...HOST_ORIGIN_ENV } },
    // A second Host on a damaged vault master key, for the VAULT_MASTER_KEY_BAD spec only.
    { command: 'node e2e/start-bad-key-host.cjs', port: PORTS.badKeyHost, reuseExistingServer: false, timeout: 60_000, env: { NETSEC_HOST_DLL: hostDll, NETSEC_PORT: String(PORTS.badKeyHost), ...HOST_ORIGIN_ENV } },
  ],
})
