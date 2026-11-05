import { reactive } from 'vue'
import { addr } from './store'
import { hostGet, hostSend } from './host'
import { sec, words } from './security'

// The practice vault: the key list, the three exercise screens (sign and derive, refuse, audit). Not a lab: no session, no trace, no mode change.
// The Host owns every rule and every code. This module sends the learner's text and shows what comes back.

export type VaultScreen = 'sign-derive' | 'refuse' | 'audit'
export interface VaultKey { name: string; algorithm: string; exportable: boolean; allowedOps: string[]; provenance: string; versions: number; fingerprint: string; hidden: string; publicHex: string }
export interface AuditRow { seq: number; at: string; caller: string; op: string; name: string; version: number | null; result: string; detail: string; prevHash: string }
export interface SignReply { keyName: string; version: number; inputHex: string; signatureHex: string; publicKeyHex: string; command: string; output: string; controlCommand: string; controlOutput: string; code: string }
export interface DeriveRow { label: string; outputHex: string; fingerprint: string; version: number }
export interface Refusal { code: string; message: string; retryable: boolean; requestId: string }
export interface ChainReply { rows: number; firstBadSeq: number; code: string; limits: string }

export const vault = reactive({
  open: false,
  screen: 'sign-derive' as VaultScreen,
  keys: [] as VaultKey[],
  loaded: false,
  sign: null as SignReply | null,
  signChecked: false,
  derived: [] as DeriveRow[],
  refused: null as Refusal | null,
  audit: [] as AuditRow[],
  auditShown: false,
  chain: null as ChainReply | null,
  fault: null as Refusal | null,
  busy: false,
})

const str = (v: unknown): string => (typeof v === 'string' ? v : v == null ? '' : String(v))
const list = (v: unknown): any[] => (Array.isArray(v) ? v : [])
const refusal = (b: any): Refusal => ({ code: str(b?.code) || 'HOST_ERROR', message: str(b?.message), retryable: !!b?.retryable, requestId: str(b?.requestId) })

/** The words for a vault code, from the copy file. The Host's message is the fallback. */
export const vaultWords = (r: Refusal): string => words(`wizard.error.${r.code}`, r.message)

function toKey(k: any): VaultKey {
  return { name: str(k.name), algorithm: str(k.algorithm), exportable: !!k.exportable, allowedOps: list(k.allowedOps).map(str), provenance: str(k.provenance), versions: Number(k.versions ?? 0), fingerprint: str(k.fingerprint), hidden: str(k.hidden), publicHex: str(k.publicHex) }
}

function toRow(r: any): AuditRow {
  return { seq: Number(r.seq ?? 0), at: str(r.at), caller: str(r.caller), op: str(r.op), name: str(r.name), version: r.version == null ? null : Number(r.version), result: str(r.result), detail: str(r.detail), prevHash: str(r.prev_hash ?? r.prevHash) }
}

/** SHA256: plus the unpadded base64 of SHA-256 over the bytes of a hex string. The format the Host uses for public keys. */
export async function fingerprintOfHex(hex: string): Promise<string> {
  const bytes = new Uint8Array((hex.match(/.{1,2}/g) ?? []).map(h => parseInt(h, 16)))
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes))
  let bin = ''
  for (const b of digest) bin += String.fromCharCode(b)
  return `SHA256:${btoa(bin).replace(/=+$/, '')}`
}

async function call(path: string, body: unknown): Promise<{ ok: boolean; body: any }> {
  vault.busy = true
  vault.fault = null
  try {
    const r = await hostSend(addr, 'POST', path, body)
    if (r.status >= 300) { vault.fault = refusal(r.body); return { ok: false, body: r.body } }
    vault.fault = null
    return { ok: true, body: r.body }
  } catch (e: any) {
    vault.fault = { code: 'HOST_UNREACHABLE', message: str(e?.message), retryable: true, requestId: '' }
    return { ok: false, body: null }
  } finally { vault.busy = false }
}

export async function loadVaultKeys() {
  try {
    const b = await hostGet(addr, '/api/security/vault/keys')
    vault.keys = list(b.keys).map(toKey)
    vault.loaded = true
  } catch (e: any) { vault.fault = { code: e?.status === 404 ? 'PRODUCT_MISSING' : 'HOST_VAULT_FAILED', message: 'The course could not read the vault list from the engine.', retryable: true, requestId: '' } }
}

export async function openVault() { vault.open = true; vault.screen = 'sign-derive'; await loadVaultKeys() }
export function closeVault() { vault.open = false }
export function showScreen(s: VaultScreen) { vault.screen = s; vault.fault = null }

export async function signText(text: string) {
  vault.signChecked = false
  const r = await call('/api/security/vault/exercise/sign', { text })
  if (r.ok) vault.sign = { keyName: str(r.body.keyName), version: Number(r.body.version ?? 0), inputHex: str(r.body.inputHex), signatureHex: str(r.body.signatureHex), publicKeyHex: str(r.body.publicKeyHex), command: str(r.body.command), output: str(r.body.output), controlCommand: str(r.body.controlCommand), controlOutput: str(r.body.controlOutput), code: str(r.body.code) }
  await loadVaultKeys()
}

/** The Host runs the OpenSSL check inside the sign call. This step shows its command and output. */
export function revealCheck() { vault.signChecked = true }

export async function deriveLabel(label: string) {
  const r = await call('/api/security/vault/exercise/derive', { label })
  if (r.ok) {
    const outputHex = str(r.body.outputHex)
    vault.derived = [...vault.derived, { label: str(r.body.label) || label, outputHex, fingerprint: await fingerprintOfHex(outputHex), version: Number(r.body.version ?? 0) }]
  }
}

export async function tryExport() {
  const r = await call('/api/security/vault/exercise/export', {})
  vault.refused = r.ok ? null : refusal(r.body)
  await loadVaultKeys()
}

export async function showAudit() {
  vault.auditShown = true
  vault.fault = null
  const rows: AuditRow[] = []
  try {
    for (let after = 0; ;) {
      const b = await hostGet(addr, `/api/security/vault/audit?after=${after}`)
      const page = list(b.rows).map(toRow)
      rows.push(...page)
      if (page.length < 500) break
      after = page[page.length - 1].seq
    }
    vault.audit = rows
  } catch { vault.fault = { code: 'HOST_VAULT_FAILED', message: 'The course could not read the audit list.', retryable: true, requestId: '' } }
}

export async function checkChain() {
  const r = await call('/api/security/vault/exercise/audit-check', {})
  if (!r.ok) return
  vault.chain = { rows: list(r.body.rows).length || Number(r.body.rows ?? 0), firstBadSeq: Number(r.body.firstBadSeq ?? 0), code: str(r.body.code), limits: str(r.body.limits) }
  await showAudit()
}

export const showKeysOn = () => sec.showKeys
