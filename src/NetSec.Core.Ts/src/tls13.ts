/**
 * TLS 1.3 (RFC 8446): the key schedule as a list of named steps, and a reader for the
 * handshake messages. For the walk lessons.
 *
 * 1. The suite is TLS_AES_128_GCM_SHA256, the suite of the RFC 8448 trace: SHA-256, 16-byte keys, 12-byte IVs.
 * 2. Each step has the name that RFC 8446 section 7.1 gives it, the rule that makes it, and its bytes.
 * 3. Pure and frozen. No Node API. Practice use only.
 */
import { HASH_LEN, concatBytes, deriveSecret, hkdfExpandLabel, hkdfExtract, hmacSha256, sha256 } from './hash.ts'
import { gcmDecrypt } from './gcm.ts'

/** The handshake messages of one connection, each with its 4-byte handshake header. */
export interface Tls13Messages {
  readonly clientHello: Uint8Array
  readonly serverHello: Uint8Array
  readonly encryptedExtensions: Uint8Array
  readonly certificate: Uint8Array
  readonly certificateVerify: Uint8Array
  readonly serverFinished: Uint8Array
  readonly clientFinished: Uint8Array
}

export type SchedulePhase = 'early' | 'handshake' | 'application' | 'resumption'

/** One value of the key schedule. */
export interface ScheduleStep {
  /** A stable id. It matches the key in acceptance/vectors/tls13-rfc8448.nsv. */
  readonly id: string
  /** The name in RFC 8446, for example "client_handshake_traffic_secret". */
  readonly name: string
  readonly phase: SchedulePhase
  /** The rule, as RFC 8446 writes it. */
  readonly rule: string
  /** The ids of the steps this one uses. */
  readonly from: readonly string[]
  readonly value: Uint8Array
}

export interface KeySchedule {
  readonly steps: readonly ScheduleStep[]
  readonly byId: Readonly<Record<string, ScheduleStep>>
}

const KEY_LEN = 16
const IV_LEN = 12
const ZEROS = new Uint8Array(HASH_LEN)
const EMPTY = new Uint8Array(0)

/** The full key schedule of a 1-RTT handshake with no PSK (RFC 8446 section 7.1). */
export function keySchedule(m: Tls13Messages, ecdheShared: ArrayLike<number>, ticketNonce: ArrayLike<number> = [0, 0]): KeySchedule {
  const steps: ScheduleStep[] = []
  const byId: Record<string, ScheduleStep> = {}
  const add = (id: string, name: string, phase: SchedulePhase, rule: string, from: string[], value: Uint8Array): Uint8Array => {
    const step: ScheduleStep = Object.freeze({ id, name, phase, rule, from: Object.freeze(from), value: Uint8Array.from(value) })
    steps.push(step)
    byId[id] = step
    return value
  }
  const hashOf = (...parts: Uint8Array[]): Uint8Array => sha256(concatBytes(...parts))

  // Early secret: no PSK, so the input is 32 zero bytes.
  const early = add('early_secret', 'Early Secret', 'early', 'HKDF-Extract(salt = 0, IKM = 0)', [], hkdfExtract(EMPTY, ZEROS))
  const emptyHash = add('empty_hash', 'Transcript-Hash("")', 'early', 'SHA-256 of no bytes', [], sha256(EMPTY))
  const d1 = add(
    'derived_for_handshake',
    'Derive-Secret(., "derived", "")',
    'early',
    'Derive-Secret(Early Secret, "derived", "")',
    ['early_secret', 'empty_hash'],
    deriveSecret(early, 'derived', emptyHash),
  )

  // Handshake secret: this is where the (EC)DHE shared secret comes in.
  const hs = add(
    'handshake_secret',
    'Handshake Secret',
    'handshake',
    'HKDF-Extract(salt = derived, IKM = (EC)DHE shared secret)',
    ['derived_for_handshake'],
    hkdfExtract(d1, ecdheShared),
  )
  const hHello = add(
    'hash_client_hello_to_server_hello',
    'Transcript-Hash(ClientHello...ServerHello)',
    'handshake',
    'SHA-256(ClientHello || ServerHello)',
    [],
    hashOf(m.clientHello, m.serverHello),
  )
  const cHs = add(
    'c_hs_traffic',
    'client_handshake_traffic_secret',
    'handshake',
    'Derive-Secret(Handshake Secret, "c hs traffic", ClientHello...ServerHello)',
    ['handshake_secret', 'hash_client_hello_to_server_hello'],
    deriveSecret(hs, 'c hs traffic', hHello),
  )
  const sHs = add(
    's_hs_traffic',
    'server_handshake_traffic_secret',
    'handshake',
    'Derive-Secret(Handshake Secret, "s hs traffic", ClientHello...ServerHello)',
    ['handshake_secret', 'hash_client_hello_to_server_hello'],
    deriveSecret(hs, 's hs traffic', hHello),
  )
  const traffic = (id: string, who: string, secretId: string, secret: Uint8Array, phase: SchedulePhase): void => {
    add(`${id}_key`, `${who} write key`, phase, `HKDF-Expand-Label(${byId[secretId].name}, "key", "", 16)`, [secretId], hkdfExpandLabel(secret, 'key', EMPTY, KEY_LEN))
    add(`${id}_iv`, `${who} write IV`, phase, `HKDF-Expand-Label(${byId[secretId].name}, "iv", "", 12)`, [secretId], hkdfExpandLabel(secret, 'iv', EMPTY, IV_LEN))
  }
  traffic('s_hs', 'server handshake', 's_hs_traffic', sHs, 'handshake')
  traffic('c_hs', 'client handshake', 'c_hs_traffic', cHs, 'handshake')

  // The server Finished: a MAC over every message up to CertificateVerify.
  const sFinKey = add(
    's_finished_key',
    'server finished_key',
    'handshake',
    'HKDF-Expand-Label(server_handshake_traffic_secret, "finished", "", 32)',
    ['s_hs_traffic'],
    hkdfExpandLabel(sHs, 'finished', EMPTY, HASH_LEN),
  )
  const hToCv = add(
    'hash_to_certificate_verify',
    'Transcript-Hash(ClientHello...CertificateVerify)',
    'handshake',
    'SHA-256 of every message up to CertificateVerify',
    [],
    hashOf(m.clientHello, m.serverHello, m.encryptedExtensions, m.certificate, m.certificateVerify),
  )
  add(
    's_finished_verify_data',
    'server Finished verify_data',
    'handshake',
    'HMAC(finished_key, Transcript-Hash(ClientHello...CertificateVerify))',
    ['s_finished_key', 'hash_to_certificate_verify'],
    hmacSha256(sFinKey, hToCv),
  )

  // Master secret, and the keys for application data.
  const d2 = add(
    'derived_for_master',
    'Derive-Secret(., "derived", "")',
    'application',
    'Derive-Secret(Handshake Secret, "derived", "")',
    ['handshake_secret', 'empty_hash'],
    deriveSecret(hs, 'derived', emptyHash),
  )
  const master = add('master_secret', 'Master Secret', 'application', 'HKDF-Extract(salt = derived, IKM = 0)', ['derived_for_master'], hkdfExtract(d2, ZEROS))
  const hToSf = add(
    'hash_to_server_finished',
    'Transcript-Hash(ClientHello...server Finished)',
    'application',
    'SHA-256 of every message up to the server Finished',
    [],
    hashOf(m.clientHello, m.serverHello, m.encryptedExtensions, m.certificate, m.certificateVerify, m.serverFinished),
  )
  const cAp = add(
    'c_ap_traffic',
    'client_application_traffic_secret_0',
    'application',
    'Derive-Secret(Master Secret, "c ap traffic", ClientHello...server Finished)',
    ['master_secret', 'hash_to_server_finished'],
    deriveSecret(master, 'c ap traffic', hToSf),
  )
  const sAp = add(
    's_ap_traffic',
    'server_application_traffic_secret_0',
    'application',
    'Derive-Secret(Master Secret, "s ap traffic", ClientHello...server Finished)',
    ['master_secret', 'hash_to_server_finished'],
    deriveSecret(master, 's ap traffic', hToSf),
  )
  add(
    'exp_master',
    'exporter_master_secret',
    'application',
    'Derive-Secret(Master Secret, "exp master", ClientHello...server Finished)',
    ['master_secret', 'hash_to_server_finished'],
    deriveSecret(master, 'exp master', hToSf),
  )
  traffic('s_ap', 'server application', 's_ap_traffic', sAp, 'application')
  traffic('c_ap', 'client application', 'c_ap_traffic', cAp, 'application')

  // The client Finished: a MAC over every message up to the server Finished.
  const cFinKey = add(
    'c_finished_key',
    'client finished_key',
    'application',
    'HKDF-Expand-Label(client_handshake_traffic_secret, "finished", "", 32)',
    ['c_hs_traffic'],
    hkdfExpandLabel(cHs, 'finished', EMPTY, HASH_LEN),
  )
  add(
    'c_finished_verify_data',
    'client Finished verify_data',
    'application',
    'HMAC(finished_key, Transcript-Hash(ClientHello...server Finished))',
    ['c_finished_key', 'hash_to_server_finished'],
    hmacSha256(cFinKey, hToSf),
  )

  // Resumption: a secret for a later connection.
  const hToCf = add(
    'hash_to_client_finished',
    'Transcript-Hash(ClientHello...client Finished)',
    'resumption',
    'SHA-256 of every handshake message',
    [],
    hashOf(m.clientHello, m.serverHello, m.encryptedExtensions, m.certificate, m.certificateVerify, m.serverFinished, m.clientFinished),
  )
  const res = add(
    'res_master',
    'resumption_master_secret',
    'resumption',
    'Derive-Secret(Master Secret, "res master", ClientHello...client Finished)',
    ['master_secret', 'hash_to_client_finished'],
    deriveSecret(master, 'res master', hToCf),
  )
  add(
    'resumption_secret',
    'PSK for a later connection',
    'resumption',
    'HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, 32)',
    ['res_master'],
    hkdfExpandLabel(res, 'resumption', ticketNonce, HASH_LEN),
  )

  return Object.freeze({ steps: Object.freeze(steps), byId: Object.freeze(byId) })
}

// ── The message reader ─────────────────────────────────────────────────────────

/** RFC 8446 section 4: HandshakeType. */
export const HANDSHAKE_TYPES: Readonly<Record<number, string>> = Object.freeze({
  1: 'ClientHello',
  2: 'ServerHello',
  4: 'NewSessionTicket',
  8: 'EncryptedExtensions',
  11: 'Certificate',
  13: 'CertificateRequest',
  15: 'CertificateVerify',
  20: 'Finished',
  24: 'KeyUpdate',
})
/** RFC 8446 appendix B.4. */
export const CIPHER_SUITES: Readonly<Record<number, string>> = Object.freeze({
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0x1304: 'TLS_AES_128_CCM_SHA256',
  0x1305: 'TLS_AES_128_CCM_8_SHA256',
})
/** RFC 8446 section 4.2.7, and RFC 7919. */
export const NAMED_GROUPS: Readonly<Record<number, string>> = Object.freeze({
  0x0017: 'secp256r1',
  0x0018: 'secp384r1',
  0x0019: 'secp521r1',
  0x001d: 'x25519',
  0x001e: 'x448',
  0x0100: 'ffdhe2048',
  0x0101: 'ffdhe3072',
  0x0102: 'ffdhe4096',
  0x0103: 'ffdhe6144',
  0x0104: 'ffdhe8192',
})
/** RFC 8446 section 4.2.3. */
export const SIGNATURE_SCHEMES: Readonly<Record<number, string>> = Object.freeze({
  0x0401: 'rsa_pkcs1_sha256',
  0x0501: 'rsa_pkcs1_sha384',
  0x0601: 'rsa_pkcs1_sha512',
  0x0403: 'ecdsa_secp256r1_sha256',
  0x0503: 'ecdsa_secp384r1_sha384',
  0x0603: 'ecdsa_secp521r1_sha512',
  0x0804: 'rsa_pss_rsae_sha256',
  0x0805: 'rsa_pss_rsae_sha384',
  0x0806: 'rsa_pss_rsae_sha512',
  0x0807: 'ed25519',
  0x0808: 'ed448',
  0x0809: 'rsa_pss_pss_sha256',
  0x080a: 'rsa_pss_pss_sha384',
  0x080b: 'rsa_pss_pss_sha512',
  0x0201: 'rsa_pkcs1_sha1',
  0x0203: 'ecdsa_sha1',
})
/** RFC 8446 section 4.2: ExtensionType, plus the 2 older ones the RFC 8448 trace carries. */
export const EXTENSION_TYPES: Readonly<Record<number, string>> = Object.freeze({
  0: 'server_name',
  1: 'max_fragment_length',
  5: 'status_request',
  10: 'supported_groups',
  13: 'signature_algorithms',
  14: 'use_srtp',
  15: 'heartbeat',
  16: 'application_layer_protocol_negotiation',
  18: 'signed_certificate_timestamp',
  19: 'client_certificate_type',
  20: 'server_certificate_type',
  21: 'padding',
  22: 'encrypt_then_mac',
  23: 'extended_master_secret',
  28: 'record_size_limit',
  35: 'session_ticket',
  41: 'pre_shared_key',
  42: 'early_data',
  43: 'supported_versions',
  44: 'cookie',
  45: 'psk_key_exchange_modes',
  47: 'certificate_authorities',
  48: 'oid_filters',
  49: 'post_handshake_auth',
  50: 'signature_algorithms_cert',
  51: 'key_share',
  0xff01: 'renegotiation_info',
})
const VERSIONS: Readonly<Record<number, string>> = Object.freeze({
  0x0300: 'SSL 3.0',
  0x0301: 'TLS 1.0',
  0x0302: 'TLS 1.1',
  0x0303: 'TLS 1.2',
  0x0304: 'TLS 1.3',
})
export const versionName = (v: number): string => VERSIONS[v] ?? `0x${v.toString(16).padStart(4, '0')}`

export class TlsParseError extends Error {
  readonly code = 'TLS_PARSE'
  constructor(message: string) {
    super(message)
    this.name = 'TlsParseError'
  }
}

/** Reads numbers and byte runs from a message, in order. */
export class Reader {
  private at = 0
  private readonly b: Uint8Array
  constructor(b: Uint8Array) {
    this.b = b
  }
  get left(): number {
    return this.b.length - this.at
  }
  get pos(): number {
    return this.at
  }
  uint(bytes: number): number {
    if (this.left < bytes) throw new TlsParseError('The message ends before a field is complete.')
    let v = 0
    for (let i = 0; i < bytes; i += 1) v = v * 256 + this.b[this.at + i]
    this.at += bytes
    return v
  }
  take(n: number): Uint8Array {
    if (this.left < n) throw new TlsParseError('The message ends before a field is complete.')
    const out = this.b.slice(this.at, this.at + n)
    this.at += n
    return out
  }
  /** A field with its length in front, as `lenBytes` bytes. */
  vec(lenBytes: number): Uint8Array {
    return this.take(this.uint(lenBytes))
  }
}

/** One named part of a message, with its place in the bytes. */
export interface Field {
  readonly name: string
  /** Offset of the first byte in the message, header included. */
  readonly at: number
  readonly length: number
  /** The value in simple words: "TLS 1.2", "x25519", "32 bytes". */
  readonly text: string
}

export interface Extension {
  readonly type: number
  readonly name: string
  readonly at: number
  readonly length: number
  /** What the extension says, in simple words. */
  readonly text: string
  readonly data: Uint8Array
}

export interface ParsedHandshake {
  readonly type: number
  readonly typeName: string
  /** The length of the body, from the 3-byte length field. */
  readonly bodyLength: number
  readonly fields: readonly Field[]
  readonly extensions: readonly Extension[]
}

const list = (data: Uint8Array, width: number, names: Readonly<Record<number, string>>, lenBytes: number): string => {
  const r = new Reader(data)
  const body = new Reader(r.vec(lenBytes))
  const out: string[] = []
  while (body.left >= width) {
    const v = body.uint(width)
    out.push(names[v] ?? `0x${v.toString(16).padStart(2 * width, '0')}`)
  }
  return out.join(', ')
}

function describeExtension(type: number, data: Uint8Array, inServerHello: boolean): string {
  try {
    if (type === 43) {
      if (inServerHello) return `selected: ${versionName(new Reader(data).uint(2))}`
      return `offered: ${list(data, 2, VERSIONS, 1)}`
    }
    if (type === 51) {
      const r = new Reader(data)
      if (inServerHello) {
        const group = r.uint(2)
        return `${NAMED_GROUPS[group] ?? group}: a ${r.vec(2).length}-byte public value`
      }
      const shares = new Reader(r.vec(2))
      const out: string[] = []
      while (shares.left > 0) {
        const group = shares.uint(2)
        out.push(`${NAMED_GROUPS[group] ?? group}: a ${shares.vec(2).length}-byte public value`)
      }
      return out.join('; ')
    }
    if (type === 10) return list(data, 2, NAMED_GROUPS, 2)
    if (type === 13 || type === 50) return list(data, 2, SIGNATURE_SCHEMES, 2)
    if (type === 0 && data.length > 0) {
      const names = new Reader(new Reader(data).vec(2))
      names.uint(1)
      return `host name: ${String.fromCharCode(...names.vec(2))}`
    }
    if (type === 45) return list(data, 1, { 0: 'psk_ke', 1: 'psk_dhe_ke' }, 1)
    if (type === 28) return `${new Reader(data).uint(2)} bytes`
  } catch {
    // A field that does not parse shows its size only.
  }
  return data.length === 0 ? 'no data' : data.length === 1 ? '1 byte' : `${data.length} bytes`
}

/** Reads an extensions block: a 2-byte length, then each extension. `base` is the offset of the reader's first byte in the message. */
export function readExtensions(r: Reader, base: number, inServerHello: boolean): Extension[] {
  const out: Extension[] = []
  const total = r.uint(2)
  const end = r.pos + total
  while (r.pos < end) {
    const at = base + r.pos
    const type = r.uint(2)
    const data = r.vec(2)
    out.push(
      Object.freeze({
        type,
        name: EXTENSION_TYPES[type] ?? `extension ${type}`,
        at,
        length: 4 + data.length,
        text: describeExtension(type, data, inServerHello),
        data,
      }),
    )
  }
  if (r.pos !== end) throw new TlsParseError('An extension runs past the end of the extensions block.')
  return out
}

/** Reads one handshake message (with its 4-byte header) into named fields. */
export function parseHandshake(message: ArrayLike<number>): ParsedHandshake {
  const all = Uint8Array.from(message)
  const head = new Reader(all)
  const type = head.uint(1)
  const bodyLength = head.uint(3)
  if (bodyLength !== all.length - 4) throw new TlsParseError('The length field does not match the size of the message.')
  const fields: Field[] = [
    { name: 'msg_type', at: 0, length: 1, text: `${type} = ${HANDSHAKE_TYPES[type] ?? 'unknown'}` },
    { name: 'length', at: 1, length: 3, text: `${bodyLength} bytes follow` },
  ]
  let extensions: Extension[] = []
  const r = new Reader(all.subarray(4))
  const base = 4
  const field = (name: string, start: number, text: string): void => {
    fields.push({ name, at: base + start, length: r.pos - start, text })
  }

  if (type === 1 || type === 2) {
    let s = r.pos
    field('legacy_version', s, versionName(r.uint(2)))
    s = r.pos
    r.take(32)
    field('random', s, '32 random bytes')
    s = r.pos
    const sid = r.vec(1)
    field(type === 1 ? 'legacy_session_id' : 'legacy_session_id_echo', s, sid.length === 0 ? 'empty' : `${sid.length} bytes`)
    s = r.pos
    if (type === 1) {
      const suites = new Reader(r.vec(2))
      const names: string[] = []
      while (suites.left >= 2) {
        const v = suites.uint(2)
        names.push(CIPHER_SUITES[v] ?? `0x${v.toString(16).padStart(4, '0')}`)
      }
      field('cipher_suites', s, names.join(', '))
      s = r.pos
      r.vec(1)
      field('legacy_compression_methods', s, 'null (no compression)')
    } else {
      const v = r.uint(2)
      field('cipher_suite', s, CIPHER_SUITES[v] ?? `0x${v.toString(16).padStart(4, '0')}`)
      s = r.pos
      r.uint(1)
      field('legacy_compression_method', s, 'null (no compression)')
    }
    s = r.pos
    extensions = readExtensions(r, base, type === 2)
    field('extensions', s, `${extensions.length} extensions`)
  } else if (type === 8) {
    const s = r.pos
    extensions = readExtensions(r, base, false)
    field('extensions', s, `${extensions.length} extensions`)
  } else if (type === 11) {
    let s = r.pos
    const ctx = r.vec(1)
    field('certificate_request_context', s, ctx.length === 0 ? 'empty' : `${ctx.length} bytes`)
    s = r.pos
    const listBytes = new Reader(r.vec(3))
    let count = 0
    const sizes: number[] = []
    while (listBytes.left > 0) {
      sizes.push(listBytes.vec(3).length)
      listBytes.vec(2)
      count += 1
    }
    field('certificate_list', s, `${count} certificate${count === 1 ? '' : 's'}: ${sizes.join(', ')} bytes`)
  } else if (type === 15) {
    let s = r.pos
    const alg = r.uint(2)
    field('algorithm', s, SIGNATURE_SCHEMES[alg] ?? `0x${alg.toString(16).padStart(4, '0')}`)
    s = r.pos
    const sig = r.vec(2)
    field('signature', s, `${sig.length} bytes`)
  } else if (type === 20) {
    const s = r.pos
    const v = r.take(r.left)
    field('verify_data', s, `${v.length} bytes: a MAC over the messages so far`)
  }
  if (r.left !== 0 && (type === 1 || type === 2 || type === 8 || type === 11 || type === 15 || type === 20)) {
    throw new TlsParseError('Bytes are left after the last field.')
  }
  return Object.freeze({
    type,
    typeName: HANDSHAKE_TYPES[type] ?? 'unknown',
    bodyLength,
    fields: Object.freeze(fields.map((f) => Object.freeze(f))),
    extensions: Object.freeze(extensions),
  })
}

// ── A protected record ─────────────────────────────────────────────────────────

/** One TLS 1.3 record, opened: each input of AES-GCM and what came out. */
export interface OpenedRecord13 {
  /** The 5-byte record header. It is the associated data. */
  readonly header: Uint8Array
  /** The write IV XOR the record number (RFC 8446 section 5.3). */
  readonly nonce: Uint8Array
  readonly ciphertext: Uint8Array
  readonly tag: Uint8Array
  /** The inner plaintext: the content, 1 byte of content type, then zero padding. */
  readonly inner: Uint8Array
  /** The content, with the type byte and the padding taken off. */
  readonly content: Uint8Array
  /** The real content type: 22 is handshake, 23 is application data, 21 is alert. */
  readonly contentType: number
}

/**
 * Opens one protected TLS 1.3 record with AES-GCM (RFC 8446 sections 5.2 and 5.3).
 * `sequence` is the record number in its direction, from 0. A wrong key or a changed byte throws GcmError.
 */
export function openRecord13(key: ArrayLike<number>, iv: ArrayLike<number>, sequence: number, record: ArrayLike<number>): OpenedRecord13 {
  const all = Uint8Array.from(record)
  if (all.length < 5 + 16 + 1) throw new TlsParseError('The record is too short.')
  const header = all.slice(0, 5)
  const size = header[3] * 256 + header[4]
  if (size !== all.length - 5) throw new TlsParseError('The length in the record header does not match the size of the record.')
  const nonce = Uint8Array.from(iv)
  let seq = sequence
  for (let i = nonce.length - 1; i >= 0 && seq > 0; i -= 1) {
    nonce[i] ^= seq % 256
    seq = Math.floor(seq / 256)
  }
  const ciphertext = all.slice(5, all.length - 16)
  const tag = all.slice(all.length - 16)
  const inner = gcmDecrypt(key, nonce, ciphertext, tag, header)
  let end = inner.length
  while (end > 0 && inner[end - 1] === 0) end -= 1
  if (end === 0) throw new TlsParseError('The record has no content type.')
  return Object.freeze({ header, nonce, ciphertext, tag, inner, content: inner.slice(0, end - 1), contentType: inner[end - 1] })
}

/** The key_share public value of a ClientHello or ServerHello for a group, or null. */
export function keyShareOf(message: ArrayLike<number>, group = 0x001d): Uint8Array | null {
  const all = Uint8Array.from(message)
  const p = parseHandshake(all)
  const ext = p.extensions.find((e) => e.type === 51)
  if (!ext) return null
  const r = new Reader(ext.data)
  if (p.type === 2) return r.uint(2) === group ? r.vec(2) : null
  const shares = new Reader(r.vec(2))
  while (shares.left > 0) {
    const g = shares.uint(2)
    const key = shares.vec(2)
    if (g === group) return key
  }
  return null
}
