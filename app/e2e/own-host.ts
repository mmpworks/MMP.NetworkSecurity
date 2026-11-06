import { spawn, type ChildProcess } from 'node:child_process'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'
import type { HostAddress } from './walk'

// A Host on its own temp security folder, for a spec that changes key state. No route removes a key once the sign-in flow makes one,
// so a spec that runs that flow on the shared Host changes what every later spec reads. One test or one spec file uses this Host at a time.
const OWN: HostAddress = { port: 5193, token: 'own-host-token' }

export interface OwnHost extends HostAddress { stop(): Promise<void> }

async function waitForHealth(child: ChildProcess, timeoutMs = 60_000): Promise<void> {
  const started = Date.now()
  while (Date.now() - started < timeoutMs) {
    if (child.exitCode !== null) throw new Error(`own Host exited with code ${child.exitCode}`)
    const up = await fetch(`http://127.0.0.1:${OWN.port}/api/health`, { headers: { Authorization: `Bearer ${OWN.token}` } }).then(r => r.ok, () => false)
    if (up) return
    await new Promise(r => setTimeout(r, 250))
  }
  throw new Error(`own Host did not answer on port ${OWN.port}`)
}

export async function startOwnHost(): Promise<OwnHost> {
  const dll = process.env.NETSEC_HOST_DLL
  if (!dll) throw new Error('NETSEC_HOST_DLL is not set. playwright.config.ts sets it.')
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ns-own-host-'))
  const child = spawn('dotnet', [dll], { stdio: 'ignore', env: { ...process.env, NETSEC_SECURITY_DIR: dir, NETSEC_PORT: String(OWN.port), NETSEC_TOKEN: OWN.token } })
  await waitForHealth(child)
  return {
    ...OWN,
    stop: () => new Promise(resolve => {
      if (child.exitCode !== null) { resolve(); return }
      child.once('exit', () => resolve())
      child.kill()
    }),
  }
}
