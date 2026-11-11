// Checks for tls12.ts against one handshake recorded from OpenSSL 3.5.7
// (test/vectors/tls12-openssl-rsa.nsv). The vector file was copied from the capture
// by a script that computes nothing. It shares no code with this library.
// 1. The pre-master secret: node:crypto decrypts ClientKeyExchange with the test key of the server.
// 2. The master secret: prf12 gives the value that the key log of OpenSSL records.
// 3. The Finished messages: verifyData12 gives the 12 bytes that OpenSSL sent and received.
// 4. The key block: its keys open both encrypted Finished records of the capture.
// 5. The labels: a swapped label gives a different value.
// 6. P_SHA256 itself: node:crypto HMAC, written out by the rule of RFC 5246 section 5.
import { describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { constants, createHash, createHmac, createPrivateKey, privateDecrypt, randomBytes } from 'node:crypto'
import { bytesToHex, hexToBytes } from '../src/hash.ts'
import { GcmError } from '../src/gcm.ts'
import { TlsParseError } from '../src/tls13.ts'
import {
  encryptedPreMasterOf,
  helloRandom,
  keyBlock12,
  masterSecret12,
  openRecord12,
  pSha256,
  parseHandshake12,
  prf12,
  tls12Trace,
  verifyData12,
  type Tls12Messages,
} from '../src/tls12.ts'
import { TLS12_CAPTURE } from '../src/tls12capture.ts'

const text = readFileSync(new URL('./vectors/tls12-openssl-rsa.nsv', import.meta.url), 'utf8')
const V: Record<string, string> = {}
for (const line of text.split(/\r?\n/)) {
  const m = /^([a-z_0-9]+) = ([0-9a-f]*)$/.exec(line.trim())
  if (m) V[m[1]] = m[2]
}
const B = (k: string): Uint8Array => hexToBytes(V[k])

const messages: Tls12Messages = {
  clientHello: B('client_hello'),
  serverHello: B('server_hello'),
  certificate: B('certificate'),
  serverHelloDone: B('server_hello_done'),
  clientKeyExchange: B('client_key_exchange'),
  clientFinished: B('client_finished'),
  serverFinished: B('server_finished'),
}
const trace = tls12Trace(messages, B('pre_master'))
const id = (k: string): string => bytesToHex(trace.byId[k].value)

describe('the capture', () => {
  test('the vector file holds the handshake, the secrets, 2 records and the test key', () => {
    assert.equal(Object.keys(V).length, 22)
    assert.equal(V.pre_master.length, 96)
    assert.equal(V.master_secret.length, 96)
  })
  test('the randoms in the file are the randoms inside the 2 hello messages', () => {
    assert.equal(bytesToHex(helloRandom(messages.clientHello)), V.client_random)
    assert.equal(bytesToHex(helloRandom(messages.serverHello)), V.server_random)
  })
  test('the generated tls12capture.ts holds the same bytes as the vector file', () => {
    const pairs: Array<[keyof typeof TLS12_CAPTURE, string]> = [
      ['clientHello', 'client_hello'],
      ['serverHello', 'server_hello'],
      ['certificate', 'certificate'],
      ['serverHelloDone', 'server_hello_done'],
      ['clientKeyExchange', 'client_key_exchange'],
      ['clientFinished', 'client_finished'],
      ['serverFinished', 'server_finished'],
      ['preMaster', 'pre_master'],
      ['clientFinishedRecord', 'client_finished_record'],
      ['serverFinishedRecord', 'server_finished_record'],
    ]
    for (const [name, key] of pairs) assert.equal(TLS12_CAPTURE[name], V[key], name)
    assert.equal(Object.keys(TLS12_CAPTURE).length, pairs.length)
  })
})

describe('the pre-master secret (RSA key transport)', () => {
  const b64 = (k: string): string => Buffer.from(V[k], 'hex').toString('base64url')
  const key = createPrivateKey({
    key: { kty: 'RSA', n: b64('server_n'), e: b64('server_e'), d: b64('server_d'), p: b64('server_p'), q: b64('server_q'), dp: b64('server_dp'), dq: b64('server_dq'), qi: b64('server_qi') },
    format: 'jwk',
  })

  test('ClientKeyExchange carries the encrypted value of the file', () => {
    assert.equal(bytesToHex(encryptedPreMasterOf(messages.clientKeyExchange)), V.encrypted_pre_master)
  })
  test('node:crypto privateDecrypt (PKCS #1 v1.5) with the server key gives the pre-master secret of the key log', () => {
    const plain = privateDecrypt({ key, padding: constants.RSA_PKCS1_PADDING }, Buffer.from(encryptedPreMasterOf(messages.clientKeyExchange)))
    assert.equal(plain.toString('hex'), V.pre_master)
  })
  test('raw RSA with bigint (c^d mod n) gives the same 48 bytes after the 00 02 padding', () => {
    const big = (h: string): bigint => BigInt(`0x${h}`)
    const n = big(V.server_n)
    let base = big(V.encrypted_pre_master) % n
    let exp = big(V.server_d)
    let acc = 1n
    while (exp > 0n) {
      if (exp & 1n) acc = (acc * base) % n
      base = (base * base) % n
      exp >>= 1n
    }
    const em = acc.toString(16).padStart(V.server_n.length, '0')
    assert.equal(em.slice(0, 4), '0002')
    assert.equal(em.slice(-98, -96), '00')
    assert.equal(em.slice(-96), V.pre_master)
  })
  test('the pre-master secret starts with the client_version of ClientHello: 03 03', () => {
    assert.equal(V.pre_master.slice(0, 4), '0303')
    assert.equal(bytesToHex(messages.clientHello.slice(4, 6)), '0303')
  })
})

describe('the secrets against the OpenSSL key log', () => {
  test('masterSecret12 gives the master secret of the CLIENT_RANDOM line', () => {
    assert.equal(bytesToHex(masterSecret12(B('pre_master'), B('client_random'), B('server_random'))), V.master_secret)
    assert.equal(id('master_secret'), V.master_secret)
  })
  test('every step whose id is a key of the vector file has the value of the file', () => {
    const checked: string[] = []
    for (const s of trace.steps) {
      if (!(s.id in V)) continue
      assert.equal(bytesToHex(s.value), V[s.id], s.id)
      checked.push(s.id)
    }
    assert.deepEqual(checked, ['client_random', 'server_random', 'pre_master', 'master_secret'])
  })
})

describe('the Finished messages of the capture', () => {
  test('client Finished = header 14 00 00 0c + the verify_data of the trace', () => {
    assert.equal(V.client_finished, `1400000c${id('client_verify_data')}`)
  })
  test('server Finished = header 14 00 00 0c + the verify_data of the trace', () => {
    assert.equal(V.server_finished, `1400000c${id('server_verify_data')}`)
  })
  test('the 2 transcript hashes are the SHA-256 of node:crypto over the messages', () => {
    const upToCke = ['client_hello', 'server_hello', 'certificate', 'server_hello_done', 'client_key_exchange'].map((k) => Buffer.from(V[k], 'hex'))
    assert.equal(id('hash_to_client_key_exchange'), createHash('sha256').update(Buffer.concat(upToCke)).digest('hex'))
    assert.equal(id('hash_to_client_finished'), createHash('sha256').update(Buffer.concat([...upToCke, Buffer.from(V.client_finished, 'hex')])).digest('hex'))
  })
})

describe('the key block opens the encrypted Finished records of the capture', () => {
  const kb = keyBlock12(B('master_secret'), B('client_random'), B('server_random'))

  test('the client record: client_write_key and client_write_IV give the client Finished', () => {
    const rec = openRecord12(kb.clientWriteKey, kb.clientWriteIv, 0, B('client_finished_record'))
    assert.equal(bytesToHex(rec.plaintext), V.client_finished)
    assert.equal(bytesToHex(rec.header), '1603030028')
    assert.equal(bytesToHex(rec.aad), '0000000000000000' + '160303' + '0010')
    assert.equal(bytesToHex(rec.nonce), bytesToHex(kb.clientWriteIv) + bytesToHex(rec.explicitNonce))
  })
  test('the server record: server_write_key and server_write_IV give the server Finished', () => {
    const rec = openRecord12(kb.serverWriteKey, kb.serverWriteIv, 0, B('server_finished_record'))
    assert.equal(bytesToHex(rec.plaintext), V.server_finished)
  })
  test('the trace has the same 4 values as the key block', () => {
    assert.equal(id('key_block'), bytesToHex(kb.block))
    assert.equal(id('client_write_key') + id('server_write_key') + id('client_write_iv') + id('server_write_iv'), bytesToHex(kb.block))
    assert.equal(kb.block.length, 40)
  })
  const codeOf = (fn: () => unknown): string => {
    try {
      fn()
    } catch (e) {
      return e instanceof GcmError ? e.code : `other: ${String(e)}`
    }
    return 'no error'
  }
  test('the keys of the other direction, the wrong record number, and a changed byte all fail the tag', () => {
    assert.equal(codeOf(() => openRecord12(kb.serverWriteKey, kb.serverWriteIv, 0, B('client_finished_record'))), 'GCM_TAG_MISMATCH')
    assert.equal(codeOf(() => openRecord12(kb.clientWriteKey, kb.serverWriteIv, 0, B('client_finished_record'))), 'GCM_TAG_MISMATCH')
    assert.equal(codeOf(() => openRecord12(kb.clientWriteKey, kb.clientWriteIv, 1, B('client_finished_record'))), 'GCM_TAG_MISMATCH')
    const changed = B('server_finished_record')
    changed[20] ^= 1
    assert.equal(codeOf(() => openRecord12(kb.serverWriteKey, kb.serverWriteIv, 0, changed)), 'GCM_TAG_MISMATCH')
  })
  test('a key block made with the seed in the master secret order (client + server) does not open the record', () => {
    const wrong = keyBlock12(B('master_secret'), B('server_random'), B('client_random'))
    assert.equal(codeOf(() => openRecord12(wrong.clientWriteKey, wrong.clientWriteIv, 0, B('client_finished_record'))), 'GCM_TAG_MISMATCH')
  })
})

describe('the labels', () => {
  const master = B('master_secret')
  test('"server finished" in place of "client finished" does not give the client verify_data', () => {
    const h = trace.byId.hash_to_client_key_exchange.value
    assert.equal(bytesToHex(verifyData12(master, 'client finished', h)), V.client_finished.slice(8))
    assert.notEqual(bytesToHex(verifyData12(master, 'server finished', h)), V.client_finished.slice(8))
  })
  test('"client finished" in place of "server finished" does not give the server verify_data', () => {
    const h = trace.byId.hash_to_client_finished.value
    assert.equal(bytesToHex(verifyData12(master, 'server finished', h)), V.server_finished.slice(8))
    assert.notEqual(bytesToHex(verifyData12(master, 'client finished', h)), V.server_finished.slice(8))
  })
  test('"key expansion" in place of "master secret" does not give the master secret', () => {
    const seed = Buffer.concat([Buffer.from(V.client_random, 'hex'), Buffer.from(V.server_random, 'hex')])
    assert.equal(bytesToHex(prf12(B('pre_master'), 'master secret', seed, 48)), V.master_secret)
    assert.notEqual(bytesToHex(prf12(B('pre_master'), 'key expansion', seed, 48)), V.master_secret)
  })
  test('each step name and rule carries the RFC 5246 label of its value', () => {
    const want: Record<string, [string, string]> = {
      master_secret: ['master_secret', '"master secret"'],
      key_block: ['key_block', '"key expansion"'],
      client_verify_data: ['client Finished verify_data', '"client finished"'],
      server_verify_data: ['server Finished verify_data', '"server finished"'],
    }
    for (const [k, [name, label]] of Object.entries(want)) {
      assert.equal(trace.byId[k].name, name)
      assert.ok(trace.byId[k].rule.includes(label), `${k}: ${trace.byId[k].rule}`)
    }
  })
})

describe('P_SHA256 against node:crypto', () => {
  const nodeP = (secret: Buffer, seed: Buffer, length: number): string => {
    const hmac = (data: Buffer): Buffer => createHmac('sha256', secret).update(data).digest()
    let a = seed
    let out = Buffer.alloc(0)
    while (out.length < length) {
      a = hmac(a)
      out = Buffer.concat([out, hmac(Buffer.concat([a, seed]))])
    }
    return out.subarray(0, length).toString('hex')
  }
  test('random secrets and seeds, output of 0 to 100 bytes', () => {
    for (const length of [0, 1, 12, 31, 32, 33, 48, 64, 100]) {
      const secret = randomBytes(1 + (length % 50))
      const seed = randomBytes(5 + length)
      assert.equal(bytesToHex(pSha256(secret, seed, length)), nodeP(secret, seed, length), `length ${length}`)
    }
  })
  test('prf12 puts the label in front of the seed', () => {
    const secret = randomBytes(48)
    const seed = randomBytes(64)
    assert.equal(bytesToHex(prf12(secret, 'test label', seed, 40)), nodeP(secret, Buffer.concat([Buffer.from('test label', 'ascii'), seed]), 40))
  })
})

describe('the trace as a list of steps', () => {
  test('each step names only steps that come before it', () => {
    const seen = new Set<string>()
    for (const s of trace.steps) {
      for (const f of s.from) assert.ok(seen.has(f), `${s.id} uses ${f}`)
      seen.add(s.id)
    }
    assert.equal(trace.steps.length, 13)
  })
  test('the trace is frozen', () => {
    assert.ok(Object.isFrozen(trace))
    assert.ok(Object.isFrozen(trace.steps))
    assert.ok(Object.isFrozen(trace.steps[0]))
  })
})

describe('the message reader', () => {
  const names = (m: Uint8Array): string[] => parseHandshake12(m).fields.map((f) => f.name)
  const tiles = (m: Uint8Array): boolean => {
    let at = 0
    for (const f of parseHandshake12(m).fields) {
      if (f.at !== at) return false
      at += f.length
    }
    return at === m.length
  }

  test('the fields of each of the 7 messages cover every byte once, in order', () => {
    for (const [name, m] of Object.entries(messages)) assert.ok(tiles(m), name)
  })
  test('ClientHello: version TLS 1.2, 1 suite offered, and the server name', () => {
    const p = parseHandshake12(messages.clientHello)
    assert.equal(p.typeName, 'ClientHello')
    assert.deepEqual(names(messages.clientHello), ['msg_type', 'length', 'client_version', 'random', 'session_id', 'cipher_suites', 'compression_methods', 'extensions'])
    assert.equal(p.fields[2].text, 'TLS 1.2')
    assert.equal(p.fields[5].text, 'TLS_RSA_WITH_AES_128_GCM_SHA256')
    assert.equal(p.extensions.find((e) => e.type === 0)?.text, 'host name: tls12.lesson.test')
    assert.equal(p.extensions.some((e) => e.type === 23), false, 'no extended_master_secret')
    assert.deepEqual(p.extensions.map((e) => e.name), ['renegotiation_info', 'server_name', 'encrypt_then_mac', 'signature_algorithms'])
  })
  test('ServerHello: the suite that the server picked', () => {
    const p = parseHandshake12(messages.serverHello)
    assert.equal(p.typeName, 'ServerHello')
    assert.equal(p.fields.find((f) => f.name === 'cipher_suite')?.text, 'TLS_RSA_WITH_AES_128_GCM_SHA256')
    assert.equal(p.fields.find((f) => f.name === 'session_id')?.length, 33)
  })
  test('Certificate, ServerHelloDone, ClientKeyExchange and Finished', () => {
    assert.equal(parseHandshake12(messages.certificate).fields[2].text, '1 certificate: 797 bytes')
    assert.deepEqual(names(messages.serverHelloDone), ['msg_type', 'length'])
    assert.equal(parseHandshake12(messages.serverHelloDone).typeName, 'ServerHelloDone')
    const cke = parseHandshake12(messages.clientKeyExchange)
    assert.equal(cke.typeName, 'ClientKeyExchange')
    assert.equal(cke.fields[2].name, 'encrypted_pre_master_secret')
    assert.equal(cke.fields[2].length, 258)
    assert.equal(parseHandshake12(messages.clientFinished).fields[2].length, 12)
  })
  test('a hello with no extensions block is read to its end', () => {
    const body = [0x03, 0x03, ...new Array<number>(32).fill(7), 0x00, 0x00, 0x9c, 0x00]
    const p = parseHandshake12([0x02, 0x00, 0x00, body.length, ...body])
    assert.deepEqual(p.fields.map((f) => f.name), ['msg_type', 'length', 'server_version', 'random', 'session_id', 'cipher_suite', 'compression_method'])
  })
  test('a wrong length, bytes after the last field, and an unknown type throw TlsParseError', () => {
    const code = (fn: () => unknown): string => {
      try {
        fn()
      } catch (e) {
        return e instanceof TlsParseError ? e.code : `other: ${String(e)}`
      }
      return 'no error'
    }
    assert.equal(code(() => parseHandshake12([0x0e, 0x00, 0x00, 0x01])), 'TLS_PARSE')
    assert.equal(code(() => parseHandshake12([0x10, 0x00, 0x00, 0x04, 0x00, 0x01, 0xaa, 0xbb])), 'TLS_PARSE')
    assert.equal(code(() => parseHandshake12([0x0c, 0x00, 0x00, 0x00])), 'TLS_PARSE')
    assert.equal(code(() => parseHandshake12([0x63, 0x00, 0x00, 0x00])), 'TLS_PARSE')
  })
})
