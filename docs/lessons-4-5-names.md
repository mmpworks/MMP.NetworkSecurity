# Lessons 4 and 5: engine names for tours and UI

Status: the names here hold from 2026-11-05. The S3 engine lane changes this file before it changes a name.

1. Labs: `lab-04-certificates` (X25519), `lab-05-tls13` (X25519MLKEM768). Each runs a glass client and a glass server on loopback.
2. Both labs run this message order. The client sends one line, the server sends it back, and the client closes.

## Events

Actors: `client`, `server`. Lesson 4 adds actor `ca`.

| `type` | `message` | Who | When |
|---|---|---|---|
| `ca.certificate.issued` | `RootCertificate`, `ServerCertificate` | `ca` | Lesson 4 only, before the handshake. `plain` is the DER. `fields` are the X.509 fields below |
| `kex.share.computed` | Text with the group name and byte count | `client`, `server` | A key share or a shared secret exists |
| `tls.handshake.sent` | `ClientHello`, `ServerHello`, `EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished` | Sender | Before the bytes leave. `plain` holds the message |
| `tls.handshake.received` | Same names, plus `NewSessionTicket` from a referee | Receiver | After the record opens |
| `wire.sent`, `wire.received` | Same names for sent | Both | The socket events. Only these carry `wire` |
| `secret.derived` | none | Both | One event per secret. See the ladder below |
| `keys.installed` | `<suite> handshake read`, `<suite> handshake write`, `<suite> application read`, `<suite> application write` | Both | The next record in that direction uses these keys. The suite is `TLS_AES_128_GCM_SHA256` or `TLS_AES_256_GCM_SHA384` |
| `check.result` | The check name below | Receiver | A pass or a fail |
| `tls.record.sent`, `tls.record.received` | `ApplicationData` | Both | Application data under application keys |
| `tls.alert.sent` | `Alert` | The side that failed, or the side that closes | The other side's event is `tls.alert.received`, with the alert number in `message` |
| `tls.ccs.ignored` | Text | Receiver | A referee sent the dummy change_cipher_spec |
| `state.waiting` | none | Both | The engine now waits for its peer |

A tour binds ServerHello with `{"eventType":"tls.handshake.sent","match":{"actor":"server","message":"ServerHello"}}`.
Both sides send a `Finished`. Match on `actor` to pick one.

## Steps (`step`)

Client: `tls13.c.ch`, `tls13.c.sh`, `tls13.c.ee`, `tls13.c.creq`, `tls13.c.cert`, `tls13.c.cv`, `tls13.c.fin`, `tls13.c.app`, `tls13.c.ticket`, `tls13.c.keyupdate`.
Server: `tls13.s.start`, `tls13.s.ch`, `tls13.s.fin`, `tls13.s.app`, `tls13.s.keyupdate`.

## Secret ladder (`secrets[].name`)

The order is the emit order: `mlkem_shared` (hybrid only), `x25519_shared`, `hybrid_shared` (hybrid only), `early_secret`, `handshake_secret`, `c_hs_traffic`, `s_hs_traffic`, `master_secret`, `c_ap_traffic`, `s_ap_traffic`, `exp_master`.

## Check names

| Check name | Code | Passes on |
|---|---|---|
| `downgrade sentinel` | `TLS13_DOWNGRADE_SENTINEL` | ServerHello |
| `chain to trust anchor` | `CHAIN_NO_ANCHOR` | Certificate |
| `signature verify` | `CERT_SIGNATURE` | Certificate |
| `validity window` | `CERT_VALIDITY` | Certificate |
| `name match` | `CERT_NAME` | Certificate |
| `CertificateVerify signature` | `TLS13_CERTVERIFY_BAD` | CertificateVerify |
| `Finished verify_data` | `TLS13_FINISHED_MISMATCH` | Finished |
| `AEAD tag` | `TLS13_AEAD_TAG` | Fails only. A record that opens emits no check event |
| `read deadline` | `LINK_DEADLINE` | Fails only |

## Attacks and try-its

Each row is an `AttackCatalog` row. The expected check is what the engine does, not a guess.

| Attack id | Lesson | What changes | Check that catches it | Code |
|---|---|---|---|---|
| `L4-flip-cert-byte` | 4 | One byte of the serial, before the record seal | `signature verify` | `CERT_SIGNATURE` |
| `L4-flip-cert-verify` | 4 | One byte of the CertificateVerify signature | `CertificateVerify signature` | `TLS13_CERTVERIFY_BAD` |
| `L4-expired-cert` | 4 | The leaf ended in 2021 | `validity window` | `CERT_VALIDITY` |
| `L4-wrong-name` | 4 | The leaf names `other.example` | `name match` | `CERT_NAME` |
| `L4-unknown-ca` | 4 | An attacker's root signed the leaf | `chain to trust anchor` | `CHAIN_NO_ANCHOR` |
| `L5-flip-finished` | 5 | One byte of the server's verify_data, before the seal | `Finished verify_data` | `TLS13_FINISHED_MISMATCH` |
| `L5-flip-record-byte` | 5 | One sealed byte of the EncryptedExtensions record | `AEAD tag` | `TLS13_AEAD_TAG` |
| `L5-replace-key-share` | 5 | The client's X25519 share on the way out | `AEAD tag` | `TLS13_AEAD_TAG` |
| `L5-flip-mlkem-ciphertext` | 5 | One byte of the ML-KEM ciphertext in ServerHello | `AEAD tag` | `TLS13_AEAD_TAG` |
| `L5-flip-record-length` | 5 | The length byte of the server Finished record grows by 256 | `read deadline` | `LINK_DEADLINE` |

## Three corrections to `ux-design.md` section 8

1. **Replace the key share and tamper the ML-KEM ciphertext are caught by `AEAD tag`.** The UX table says `transcript hash` and `Finished verify_data`. The two sides hold different keys, so the first sealed record fails before any Finished arrives. ML-KEM itself reports no error (implicit rejection).
2. **The chain has two certificates, root and leaf, and the third card is the CertificateVerify proof.** The referees read `root.pem` and a leaf signed directly by the root. So the three linked cards are: root signs leaf, leaf key signs the transcript.
3. **`L5-flip-record-length` waits.** The receiver waits for 256 bytes that never come, up to 30 seconds, and then ends with `LINK_DEADLINE`. In step mode the clock restarts while the gate holds an event, so a learner can read for an hour.

## Field names (`fields[].gloss`)

`app/src/field-gloss.json` needs keys for these names:
`msg_type`, `length`, `legacy_version`, `random`, `session_id.length`, `session_id`, `cipher_suites.length`, `cipher_suites`, `cipher_suite`, `compression.length`, `compression`, `extensions.length`, `extension.type`, `extension.length`, `extension.other`, `server_name.list_length`, `server_name.type`, `server_name.length`, `server_name`, `supported_versions.length`, `supported_versions`, `supported_groups.length`, `supported_groups`, `signature_algorithms.length`, `signature_algorithms`, `key_share.list_length`, `key_share.group`, `key_share.length`, `key_share.mlkem_ek`, `key_share.mlkem_ciphertext`, `key_share.x25519`, `request_context.length`, `request_context`, `certificate_list.length`, `certificate.length`, `certificate.extensions.length`, `certificate.extensions`, `cert.serial`, `cert.issuer`, `cert.not_before`, `cert.not_after`, `cert.subject`, `cert.public_key`, `cert.subject_alt_name`, `cert.signature`, `signature_scheme`, `signature.length`, `signature`, `verify_data`, `body`, `application_data`, `alert.level`, `alert.description`.

`visibleToWire` is true on `ClientHello` and `ServerHello` fields and on `ca.certificate.issued`, and false on every field of a sealed message.
