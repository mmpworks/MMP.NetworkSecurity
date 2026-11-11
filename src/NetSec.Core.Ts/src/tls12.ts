/**
 * TLS 1.2 (RFC 5246): the PRF, the keys of a handshake as a list of named steps, a reader
 * for the handshake messages, and one protected record. For the walk lessons.
 *
 * 1. The suite is TLS_RSA_WITH_AES_128_GCM_SHA256 (RFC 5288): RSA key transport, SHA-256 in the PRF,
 *    16-byte keys, a 4-byte IV for each direction, and no MAC keys.
 * 2. Each step has the name that RFC 5246 gives it, the rule that makes it, and its bytes.
 * 3. This is the handshake with no extended master secret (RFC 7627). Real servers turn that on.
 * 4. Pure and frozen. No Node API. Practice use only.
 */
import { concatBytes, hmacSha256, sha256 } from './hash.ts'
import { gcmDecrypt } from './gcm.ts'
import { Reader, TlsParseError, readExtensions, versionName, type Extension, type Field, type ParsedHandshake } from './tls13.ts'

const ascii = (s: string): Uint8Array => Uint8Array.from(s, (c) => c.charCodeAt(0))

/**
 * P_SHA256, RFC 5246 section 5:
 * A(0) = seed, A(i) = HMAC(secret, A(i-1)), output = HMAC(secret, A(1) + seed) + HMAC(secret, A(2) + seed) + ...
 */
export function pSha256(secret: ArrayLike<number>, seed: ArrayLike<number>, length: number): Uint8Array {
  const s = Uint8Array.from(seed)
  const out = new Uint8Array(length)
  let a = s
  for (let at = 0; at < length; at += 32) {
    a = hmacSha256(secret, a)
    out.set(hmacSha256(secret, concatBytes(a, s)).subarray(0, Math.min(32, length - at)), at)
  }
  return out
}

/** The TLS 1.2 PRF, RFC 5246 section 5: PRF(secret, label, seed) = P_SHA256(secret, label + seed). */
export function prf12(secret: ArrayLike<number>, label: string, seed: ArrayLike<number>, length: number): Uint8Array {
  return pSha256(secret, concatBytes(ascii(label), Uint8Array.from(seed)), length)
}

export const MASTER_SECRET_LEN = 48
export const VERIFY_DATA_LEN = 12
const KEY_LEN = 16
const FIXED_IV_LEN = 4

/** RFC 5246 section 8.1: master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47]. */
export function masterSecret12(preMaster: ArrayLike<number>, clientRandom: ArrayLike<number>, serverRandom: ArrayLike<number>): Uint8Array {
  return prf12(preMaster, 'master secret', concatBytes(Uint8Array.from(clientRandom), Uint8Array.from(serverRandom)), MASTER_SECRET_LEN)
}

/** The key block of an AES-128-GCM suite, cut into its parts. */
export interface KeyBlock12 {
  /** All 40 bytes, in the order of RFC 5246 section 6.3. */
  readonly block: Uint8Array
  readonly clientWriteKey: Uint8Array
  readonly serverWriteKey: Uint8Array
  /** 4 bytes: the fixed part of the nonce (RFC 5288 section 3). */
  readonly clientWriteIv: Uint8Array
  readonly serverWriteIv: Uint8Array
}

/**
 * RFC 5246 section 6.3: key_block = PRF(master_secret, "key expansion", server_random + client_random).
 * The seed order is the reverse of the master secret seed. An AEAD suite has no MAC keys.
 */
export function keyBlock12(master: ArrayLike<number>, clientRandom: ArrayLike<number>, serverRandom: ArrayLike<number>): KeyBlock12 {
  const block = prf12(master, 'key expansion', concatBytes(Uint8Array.from(serverRandom), Uint8Array.from(clientRandom)), 2 * KEY_LEN + 2 * FIXED_IV_LEN)
  return Object.freeze({
    block,
    clientWriteKey: block.slice(0, 16),
    serverWriteKey: block.slice(16, 32),
    clientWriteIv: block.slice(32, 36),
    serverWriteIv: block.slice(36, 40),
  })
}

export type FinishedLabel12 = 'client finished' | 'server finished'

/** RFC 5246 section 7.4.9: verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))[0..11]. */
export function verifyData12(master: ArrayLike<number>, label: FinishedLabel12, transcriptHash: ArrayLike<number>): Uint8Array {
  return prf12(master, label, transcriptHash, VERIFY_DATA_LEN)
}

// ── The keys of one handshake, as named steps ─────────────────────────────────

/** The handshake messages of one connection, each with its 4-byte handshake header. */
export interface Tls12Messages {
  readonly clientHello: Uint8Array
  readonly serverHello: Uint8Array
  readonly certificate: Uint8Array
  readonly serverHelloDone: Uint8Array
  readonly clientKeyExchange: Uint8Array
  readonly clientFinished: Uint8Array
  readonly serverFinished: Uint8Array
}

export type Tls12Phase = 'exchange' | 'keys' | 'finished'

/** One value of the handshake. */
export interface Tls12Step {
  /** A stable id. Where the vector file has the value, the id is its key in test/vectors/tls12-openssl-rsa.nsv. */
  readonly id: string
  /** The name in RFC 5246, for example "master_secret". */
  readonly name: string
  readonly phase: Tls12Phase
  /** The rule, as RFC 5246 writes it. */
  readonly rule: string
  /** The ids of the steps this one uses. */
  readonly from: readonly string[]
  readonly value: Uint8Array
}

export interface Tls12Trace {
  readonly steps: readonly Tls12Step[]
  readonly byId: Readonly<Record<string, Tls12Step>>
}

/** The 32 random bytes of a ClientHello or ServerHello. */
export function helloRandom(hello: ArrayLike<number>): Uint8Array {
  if (hello.length < 38) throw new TlsParseError('The hello message is too short to hold a random value.')
  return Uint8Array.from(hello).slice(6, 38)
}

/** Every secret, key and Finished value of a full TLS 1.2 handshake with RSA key transport. */
export function tls12Trace(m: Tls12Messages, preMaster: ArrayLike<number>): Tls12Trace {
  const steps: Tls12Step[] = []
  const byId: Record<string, Tls12Step> = {}
  const add = (id: string, name: string, phase: Tls12Phase, rule: string, from: string[], value: Uint8Array): Uint8Array => {
    const step: Tls12Step = Object.freeze({ id, name, phase, rule, from: Object.freeze(from), value: Uint8Array.from(value) })
    steps.push(step)
    byId[id] = step
    return value
  }

  const cr = add('client_random', 'ClientHello.random', 'exchange', '32 bytes that the client picks, read from ClientHello', [], helloRandom(m.clientHello))
  const sr = add('server_random', 'ServerHello.random', 'exchange', '32 bytes that the server picks, read from ServerHello', [], helloRandom(m.serverHello))
  const pre = add(
    'pre_master',
    'pre_master_secret',
    'exchange',
    '48 bytes from the client: 2 bytes of client_version, then 46 random bytes. The client sends it encrypted with the RSA key of the server.',
    [],
    Uint8Array.from(preMaster),
  )
  const master = add(
    'master_secret',
    'master_secret',
    'keys',
    'PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random)[0..47]',
    ['pre_master', 'client_random', 'server_random'],
    masterSecret12(pre, cr, sr),
  )
  const kb = keyBlock12(master, cr, sr)
  add(
    'key_block',
    'key_block',
    'keys',
    'PRF(master_secret, "key expansion", ServerHello.random + ClientHello.random), 40 bytes',
    ['master_secret', 'server_random', 'client_random'],
    kb.block,
  )
  add('client_write_key', 'client_write_key', 'keys', 'key_block[0..15]', ['key_block'], kb.clientWriteKey)
  add('server_write_key', 'server_write_key', 'keys', 'key_block[16..31]', ['key_block'], kb.serverWriteKey)
  add('client_write_iv', 'client_write_IV', 'keys', 'key_block[32..35]', ['key_block'], kb.clientWriteIv)
  add('server_write_iv', 'server_write_IV', 'keys', 'key_block[36..39]', ['key_block'], kb.serverWriteIv)

  const hashOf = (...parts: Uint8Array[]): Uint8Array => sha256(concatBytes(...parts))
  const toCke = [m.clientHello, m.serverHello, m.certificate, m.serverHelloDone, m.clientKeyExchange]
  const h1 = add(
    'hash_to_client_key_exchange',
    'Hash(ClientHello...ClientKeyExchange)',
    'finished',
    'SHA-256 of every handshake message up to ClientKeyExchange',
    [],
    hashOf(...toCke),
  )
  add(
    'client_verify_data',
    'client Finished verify_data',
    'finished',
    'PRF(master_secret, "client finished", Hash(handshake_messages))[0..11]',
    ['master_secret', 'hash_to_client_key_exchange'],
    verifyData12(master, 'client finished', h1),
  )
  const h2 = add(
    'hash_to_client_finished',
    'Hash(ClientHello...client Finished)',
    'finished',
    'SHA-256 of every handshake message up to the Finished of the client',
    [],
    hashOf(...toCke, m.clientFinished),
  )
  add(
    'server_verify_data',
    'server Finished verify_data',
    'finished',
    'PRF(master_secret, "server finished", Hash(handshake_messages))[0..11]',
    ['master_secret', 'hash_to_client_finished'],
    verifyData12(master, 'server finished', h2),
  )
  return Object.freeze({ steps: Object.freeze(steps), byId: Object.freeze(byId) })
}

// ── The message reader ─────────────────────────────────────────────────────────

/** RFC 5246 section 7.4: HandshakeType. */
export const HANDSHAKE_TYPES_12: Readonly<Record<number, string>> = Object.freeze({
  0: 'HelloRequest',
  1: 'ClientHello',
  2: 'ServerHello',
  11: 'Certificate',
  12: 'ServerKeyExchange',
  13: 'CertificateRequest',
  14: 'ServerHelloDone',
  15: 'CertificateVerify',
  16: 'ClientKeyExchange',
  20: 'Finished',
})

/** Some TLS 1.2 cipher suites: RFC 5246 appendix A.5, RFC 5288, RFC 5289, RFC 5746. */
export const CIPHER_SUITES_12: Readonly<Record<number, string>> = Object.freeze({
  0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
  0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
  0x003c: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
  0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
  0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  0x00ff: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
  0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
})
const suiteName = (v: number): string => CIPHER_SUITES_12[v] ?? `0x${v.toString(16).padStart(4, '0')}`

/**
 * Reads one TLS 1.2 handshake message (with its 4-byte header) into named fields.
 * The fields cover every byte once, in order. ClientKeyExchange is read as RSA key transport.
 */
export function parseHandshake12(message: ArrayLike<number>): ParsedHandshake {
  const all = Uint8Array.from(message)
  const head = new Reader(all)
  const type = head.uint(1)
  const bodyLength = head.uint(3)
  if (bodyLength !== all.length - 4) throw new TlsParseError('The length field does not match the size of the message.')
  const typeName = HANDSHAKE_TYPES_12[type]
  if (typeName === undefined || type === 0 || type === 12 || type === 13 || type === 15) {
    throw new TlsParseError(`This reader does not know handshake type ${type}.`)
  }
  const fields: Field[] = [
    { name: 'msg_type', at: 0, length: 1, text: `${type} = ${typeName}` },
    { name: 'length', at: 1, length: 3, text: bodyLength === 0 ? 'no bytes follow' : `${bodyLength} bytes follow` },
  ]
  let extensions: Extension[] = []
  const r = new Reader(all.subarray(4))
  const base = 4
  const field = (name: string, start: number, text: string): void => {
    fields.push({ name, at: base + start, length: r.pos - start, text })
  }

  if (type === 1 || type === 2) {
    let s = r.pos
    field(type === 1 ? 'client_version' : 'server_version', s, versionName(r.uint(2)))
    s = r.pos
    r.take(32)
    field('random', s, '32 random bytes')
    s = r.pos
    const sid = r.vec(1)
    field('session_id', s, sid.length === 0 ? 'empty: a new session' : `${sid.length} bytes`)
    s = r.pos
    if (type === 1) {
      const suites = new Reader(r.vec(2))
      const names: string[] = []
      while (suites.left >= 2) names.push(suiteName(suites.uint(2)))
      field('cipher_suites', s, names.join(', '))
      s = r.pos
      r.vec(1)
      field('compression_methods', s, 'null (no compression)')
    } else {
      field('cipher_suite', s, suiteName(r.uint(2)))
      s = r.pos
      r.uint(1)
      field('compression_method', s, 'null (no compression)')
    }
    // Extensions are optional in TLS 1.2: the message can end here.
    if (r.left > 0) {
      s = r.pos
      extensions = readExtensions(r, base, false)
      field('extensions', s, `${extensions.length} extension${extensions.length === 1 ? '' : 's'}`)
    }
  } else if (type === 11) {
    const s = r.pos
    const listBytes = new Reader(r.vec(3))
    const sizes: number[] = []
    while (listBytes.left > 0) sizes.push(listBytes.vec(3).length)
    field('certificate_list', s, `${sizes.length} certificate${sizes.length === 1 ? '' : 's'}: ${sizes.join(', ')} bytes`)
  } else if (type === 16) {
    const s = r.pos
    const enc = r.vec(2)
    field('encrypted_pre_master_secret', s, `${enc.length} bytes: the pre-master secret, encrypted with the RSA key of the server`)
  } else if (type === 20) {
    const s = r.pos
    const v = r.take(r.left)
    field('verify_data', s, `${v.length} bytes: the PRF over the master secret and a hash of the messages so far`)
  }
  if (r.left !== 0) throw new TlsParseError('Bytes are left after the last field.')
  return Object.freeze({
    type,
    typeName,
    bodyLength,
    fields: Object.freeze(fields.map((f) => Object.freeze(f))),
    extensions: Object.freeze(extensions),
  })
}

/** The encrypted pre-master secret inside a ClientKeyExchange (RSA key transport). */
export function encryptedPreMasterOf(clientKeyExchange: ArrayLike<number>): Uint8Array {
  const all = Uint8Array.from(clientKeyExchange)
  const r = new Reader(all)
  if (r.uint(1) !== 16) throw new TlsParseError('The message is not a ClientKeyExchange.')
  if (r.uint(3) !== all.length - 4) throw new TlsParseError('The length field does not match the size of the message.')
  const enc = r.vec(2)
  if (r.left !== 0) throw new TlsParseError('Bytes are left after the last field.')
  return enc
}

// ── A protected record ─────────────────────────────────────────────────────────

/** One TLS 1.2 AES-GCM record, opened: each input of AES-GCM and what came out. */
export interface OpenedRecord12 {
  /** The 5-byte record header: type, version, length. */
  readonly header: Uint8Array
  /** 8 bytes that cross the wire in front of the ciphertext (RFC 5288 section 3). */
  readonly explicitNonce: Uint8Array
  /** The 4-byte write IV, then the 8 explicit bytes. */
  readonly nonce: Uint8Array
  /** seq_num (8) + type (1) + version (2) + the length of the plaintext (2). RFC 5246 section 6.2.3.3. */
  readonly aad: Uint8Array
  readonly ciphertext: Uint8Array
  readonly tag: Uint8Array
  readonly plaintext: Uint8Array
}

/**
 * Opens one protected TLS 1.2 record of an AES-GCM suite (RFC 5246 section 6.2.3.3, RFC 5288).
 * `sequence` is the record number in its direction, from 0 after ChangeCipherSpec.
 * A wrong key or a changed byte throws GcmError.
 */
export function openRecord12(key: ArrayLike<number>, writeIv: ArrayLike<number>, sequence: number, record: ArrayLike<number>): OpenedRecord12 {
  const all = Uint8Array.from(record)
  if (all.length < 5 + 8 + 16) throw new TlsParseError('The record is too short.')
  if (writeIv.length !== FIXED_IV_LEN) throw new TlsParseError('The write IV of an AES-GCM suite has 4 bytes.')
  const header = all.slice(0, 5)
  if (header[3] * 256 + header[4] !== all.length - 5) throw new TlsParseError('The length in the record header does not match the size of the record.')
  const explicitNonce = all.slice(5, 13)
  const ciphertext = all.slice(13, all.length - 16)
  const tag = all.slice(all.length - 16)
  const nonce = concatBytes(Uint8Array.from(writeIv), explicitNonce)
  const aad = new Uint8Array(13)
  let seq = sequence
  for (let i = 7; i >= 0 && seq > 0; i -= 1) {
    aad[i] = seq % 256
    seq = Math.floor(seq / 256)
  }
  aad.set(header.subarray(0, 3), 8)
  aad[11] = ciphertext.length >> 8
  aad[12] = ciphertext.length & 0xff
  const plaintext = gcmDecrypt(key, nonce, ciphertext, tag, aad)
  return Object.freeze({ header, explicitNonce, nonce, aad, ciphertext, tag, plaintext })
}
