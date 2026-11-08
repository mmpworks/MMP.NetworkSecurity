import { createHash } from 'node:crypto'
import * as path from 'node:path'

// One place for every port the e2e suite uses, so each worktree can take its own block and several suites run at once.
// NETSEC_PORT_BASE unset: the fixed ports every doc and habit already knows (preview 4180, Hosts 5190-5193).
// NETSEC_PORT_BASE=<n>:  preview n, Host n+1, bad-key Host n+2, Electron Host n+3, own Host n+4.
// NETSEC_PORT_BASE=auto: a base from a hash of this checkout's path (20000-29990, steps of 10). It does not test for busy ports,
//                        because every Playwright process must compute the same base; a hash clash needs an explicit number.
// With a base set, the Hosts also trust the matching preview origin (NETSEC_ORIGINS, docs/program-design.md D14 amendment).

const FIXED = { preview: 4180, host: 5190, badKeyHost: 5191, electron: 5192, ownHost: 5193 } as const
export type PortBlock = { [K in keyof typeof FIXED]: number }

export function portBlock(raw: string | undefined, checkout: string): PortBlock {
  if (!raw) return { ...FIXED }
  const base = raw === 'auto' ? autoBase(checkout) : Number(raw)
  if (!Number.isInteger(base) || base < 1024 || base + 4 > 65535) {
    throw new Error(`NETSEC_PORT_BASE must be "auto" or a whole number from 1024 to 65530, got "${raw}"`)
  }
  return { preview: base, host: base + 1, badKeyHost: base + 2, electron: base + 3, ownHost: base + 4 }
}

function autoBase(checkout: string): number {
  const digest = createHash('sha1').update(path.resolve(checkout).toLowerCase()).digest()
  return 20000 + (digest.readUInt16BE(0) % 1000) * 10
}

export const PORTS = portBlock(process.env.NETSEC_PORT_BASE, path.join(__dirname, '..'))

/** Env for a spawned Host: trust this block's preview origin when the block is not the fixed one. */
export const HOST_ORIGIN_ENV: Record<string, string> =
  PORTS.preview === FIXED.preview ? {} : { NETSEC_ORIGINS: `http://localhost:${PORTS.preview}` }
