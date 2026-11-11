// Checks for tls13.ts against RFC 8448 section 3 (acceptance/vectors/tls13-rfc8448.nsv).
// The vector file was transcribed from the RFC. It shares no code with this library.
// 1. Every value of the key schedule that the RFC prints.
// 2. The Finished messages of the trace carry the verify_data that the schedule makes.
// 3. The (EC)DHE secret: X25519 of the RFC's private key and the key_share read from the other hello.
// 4. The message reader: the fields that the RFC text names.
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { bytesToHex, hexToBytes } from '../src/hash.ts'
import { x25519, x25519Public } from '../src/x25519.ts'
import { keySchedule, keyShareOf, parseHandshake, type Tls13Messages } from '../src/tls13.ts'

const text = readFileSync(new URL('../../../acceptance/vectors/tls13-rfc8448.nsv', import.meta.url), 'utf8')
const V: Record<string, string> = {}
for (const line of text.split(/\r?\n/)) {
  const m = /^([a-z_0-9]+) = ([0-9a-f]*)$/.exec(line.trim())
  if (m) V[m[1]] = m[2]
}
const B = (k: string): Uint8Array => hexToBytes(V[k])

const messages: Tls13Messages = {
  clientHello: B('client_hello'),
  serverHello: B('server_hello'),
  encryptedExtensions: B('encrypted_extensions'),
  certificate: B('certificate'),
  certificateVerify: B('certificate_verify'),
  serverFinished: B('server_finished'),
  clientFinished: B('client_finished'),
}
const schedule = keySchedule(messages, B('ecdhe_shared'), B('ticket_nonce'))

describe('key schedule against RFC 8448 section 3', () => {
  test('the vector file holds the trace', () => {
    assert.ok(Object.keys(V).length >= 40)
    assert.equal(V.early_salt_is_zero, '00')
  })
  const checked: string[] = []
  for (const step of schedule.steps) {
    if (!(step.id in V)) continue
    checked.push(step.id)
    test(`${step.id}: ${step.name}`, () => {
      assert.equal(bytesToHex(step.value), V[step.id])
    })
  }
  test('every schedule value that the vector file names was checked', () => {
    const named = Object.keys(V).filter(
      (k) => !/^(client_|server_|encrypted_|certificate|early_salt|early_ikm|ecdhe_shared|ticket_nonce)/.test(k),
    )
    assert.deepEqual(named.filter((k) => !checked.includes(k)), [])
    assert.ok(checked.length >= 24, `checked ${checked.length}`)
  })
  test('each step names only steps that come before it', () => {
    const seen = new Set<string>()
    for (const s of schedule.steps) {
      for (const f of s.from) assert.ok(seen.has(f), `${s.id} uses ${f}`)
      seen.add(s.id)
    }
  })
  test('the schedule is frozen', () => {
    assert.ok(Object.isFrozen(schedule))
    assert.ok(Object.isFrozen(schedule.steps))
    assert.ok(Object.isFrozen(schedule.steps[0]))
  })
})

describe('the Finished messages of the trace', () => {
  test('server Finished = header 14 00 00 20 + the verify_data of the schedule', () => {
    assert.equal(V.server_finished, `14000020${bytesToHex(schedule.byId.s_finished_verify_data.value)}`)
  })
  test('client Finished = header 14 00 00 20 + the verify_data of the schedule', () => {
    assert.equal(V.client_finished, `14000020${bytesToHex(schedule.byId.c_finished_verify_data.value)}`)
  })
})

describe('the (EC)DHE secret of the trace', () => {
  const clientShare = keyShareOf(messages.clientHello)
  const serverShare = keyShareOf(messages.serverHello)
  test('the key_share values in the hellos are the public keys of the RFC', () => {
    assert.equal(bytesToHex(clientShare ?? []), V.client_public)
    assert.equal(bytesToHex(serverShare ?? []), V.server_public)
  })
  test('each private key gives its public key', () => {
    assert.equal(bytesToHex(x25519Public(B('client_private'))), V.client_public)
    assert.equal(bytesToHex(x25519Public(B('server_private'))), V.server_public)
  })
  test('both sides get the shared secret of the RFC', () => {
    assert.equal(bytesToHex(x25519(B('client_private'), serverShare ?? [])), V.ecdhe_shared)
    assert.equal(bytesToHex(x25519(B('server_private'), clientShare ?? [])), V.ecdhe_shared)
  })
})

describe('the message reader', () => {
  const field = (m: Uint8Array, name: string): string => parseHandshake(m).fields.find((f) => f.name === name)?.text ?? ''
  const ext = (m: Uint8Array, name: string): string => parseHandshake(m).extensions.find((e) => e.name === name)?.text ?? ''

  test('ClientHello', () => {
    const p = parseHandshake(messages.clientHello)
    assert.equal(p.typeName, 'ClientHello')
    assert.equal(p.bodyLength, 192)
    assert.equal(field(messages.clientHello, 'legacy_version'), 'TLS 1.2')
    assert.equal(field(messages.clientHello, 'cipher_suites'), 'TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_256_GCM_SHA384')
    assert.equal(ext(messages.clientHello, 'server_name'), 'host name: server')
    assert.equal(ext(messages.clientHello, 'supported_versions'), 'offered: TLS 1.3')
    assert.equal(ext(messages.clientHello, 'key_share'), 'x25519: a 32-byte public value')
    assert.match(ext(messages.clientHello, 'supported_groups'), /^x25519, secp256r1, secp384r1/)
  })
  test('ServerHello', () => {
    const p = parseHandshake(messages.serverHello)
    assert.equal(p.typeName, 'ServerHello')
    assert.equal(field(messages.serverHello, 'legacy_version'), 'TLS 1.2')
    assert.equal(field(messages.serverHello, 'cipher_suite'), 'TLS_AES_128_GCM_SHA256')
    assert.equal(ext(messages.serverHello, 'supported_versions'), 'selected: TLS 1.3')
    assert.equal(ext(messages.serverHello, 'key_share'), 'x25519: a 32-byte public value')
  })
  test('the other messages', () => {
    assert.equal(parseHandshake(messages.encryptedExtensions).typeName, 'EncryptedExtensions')
    assert.equal(field(messages.certificate, 'certificate_list'), '1 certificate: 432 bytes')
    assert.equal(field(messages.certificateVerify, 'algorithm'), 'rsa_pss_rsae_sha256')
    assert.equal(field(messages.certificateVerify, 'signature'), '128 bytes')
    assert.equal(field(messages.serverFinished, 'verify_data'), '32 bytes: a MAC over the messages so far')
  })
  test('every field lies inside its message, and the fields do not overlap', () => {
    for (const m of Object.values(messages)) {
      const p = parseHandshake(m)
      let end = 0
      for (const f of p.fields) {
        assert.ok(f.at >= end, `${p.typeName}.${f.name} starts at ${f.at}, after ${end}`)
        end = f.at + f.length
        assert.ok(end <= m.length)
      }
      assert.equal(end, m.length, `${p.typeName} fields cover the message`)
    }
  })
  test('a wrong length throws a coded error', () => {
    assert.throws(() => parseHandshake(messages.serverHello.subarray(0, 40)), { code: 'TLS_PARSE' })
  })
})
