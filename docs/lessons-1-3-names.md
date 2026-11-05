# Lessons 1 to 3: names the labs emit

Status: stable. Tours and UI bind to these names. A change goes through Richard. Date: 2026-11-05.

## Rules for all three lessons

| Item | Rule |
|---|---|
| Arrows | Draw from `wire.sent` only. `wire.received` also carries `from`, `to`, and `wire` |
| Bind by message | `{ "eventType": "wire.sent", "match": { "actor": "client", "message": "<message>" } }` |
| Bind by check | `{ "eventType": "check.result", "match": { "message": "<check name>" } }`. `event.message` holds the check name. `event.check` holds `id`, `name`, `result`, `code` |
| Engine events | `<protocol>.message.sent` carries `plain` and `fields`, with no `wire`. `<protocol>.message.received` carries the receiver's `plain` |
| Fields | `fields[]` offsets index `wire`. Clear headers, nonces, shares, and tags have `visibleToWire` true. Ciphertext has it false |
| Measure | Type `measure.result` carries `message` and `detail`, a `name=value;name=value` string. The UI reads numbers from it and invents none |
| Forks | An attack reruns with the same seed. Bytes match the parent until the tamper |
| End of a run | `session.finished {outcome, code, check}`. `outcome` is `completed` or `caught`. A `NoCheck` or `Accepted` attack ends `completed` |
| Failure on one side | The first failed `check.result` names the catch. The peer may then show `PEER_CLOSED_EARLY`. Show the first one |

## Lesson 1: Secrets and locks. Protocol `aes`. Lanes `client`, `server`

The whole run is one session, in this message order. Client sends all of them. The server answers `AesDone`.

| Order | `message` | Mode | Field names in order |
|---|---|---|---|
| 1 | `TextGcm1` | GCM | `type`, `length`, `nonce`, `cipher`, `tag` |
| 2 | `TextCbc` | CBC | `type`, `length`, `iv`, `cipher` |
| 3 | `PictureEcb` | ECB | `type`, `length`, `cipher` |
| 4 | `PictureCbc` | CBC | `type`, `length`, `iv`, `cipher` |
| 5 | `PictureGcm` | GCM | `type`, `length`, `nonce`, `cipher`, `tag` |
| 6 | `TextGcm2` | GCM | `type`, `length`, `nonce`, `cipher`, `tag` |
| 7 | `AesDone` (server to client) | none | `type`, `length` |

A picture is 64 by 64, one byte per pixel, 4,096 bytes. `plain` holds the clear picture. The `cipher` field holds the locked picture, plus one padding block on ECB and CBC.

| Event type | `actor` | `message` | Carries |
|---|---|---|---|
| `secret.derived` | `client`, `server` | none | `secrets[]`: `aes.key`, 16 bytes |
| `keys.installed` | `client`, `server` | `aes-128` | Bind moment 1 here |
| `aes.message.sent` | `client` | as table | `plain` |
| `wire.sent` | `client` | as table | `wire`, `plain`, `fields` |
| `aes.message.received` | `server` | as table | `plain` after the unlock |
| `measure.result` | `server` | `PictureEcb`, `PictureCbc`, `PictureGcm`, `TextCbc`, `TextGcm1`, `TextGcm2` | `detail`: `repeats=<n>;blocks=<m>`, repeated cipher blocks |
| `check.result` | `server` | `GCM tag` | Pass on each GCM message |
| `check.result` | `server` | `nonce reuse detector` | Pass on each GCM message |

| Attack id | What it does | `Expect` | Code | Check name |
|---|---|---|---|---|
| `L1-use-ecb` | Text message goes in ECB, as message `TextEcb` in place of `TextCbc` | `NoCheck` | none | none. `measure.result` shows the leak |
| `L1-flip-cbc` | Flips one bit in the `TextCbc` cipher | `NoCheck` | none | none. The received `plain` is garbled in one block, and one bit flips in the next |
| `L1-flip-gcm` | Flips one bit in the `TextGcm1` cipher | `Rejected` | `AES_GCM_TAG` | `GCM tag` |
| `L1-reuse-nonce` | `TextGcm2` reuses the `TextGcm1` nonce | `Rejected` | `AES_GCM_NONCE_REUSE` | `nonce reuse detector` |

## Lesson 2: Tamper seals. Protocol `seal`. Lanes `client`, `server`

Order: `PlainHashSealed`, `KeyedHashSealed`, `HmacSealed`, `CmacSealed`, then `SealDone` from the server. Fields: `type`, `length`, `messageLength`, `message`, `seal`.

| Event type | `actor` | `message` | Carries |
|---|---|---|---|
| `secret.derived` | `client`, `server` | none | `secrets[]`: `seal.key` |
| `measure.result` | `client` | `SHA-256 avalanche` | `plain`: digest of the message, then digest with one bit flipped, 64 bytes. `detail`: `bits=<n>;of=256`. Bind the 256-cell diff here |
| `seal.message.sent`, `wire.sent` | `client` | as order | |
| `seal.message.received` | `server` | as order | |
| `check.result` | `server` | `hash compare`, `keyed hash compare`, `HMAC compare`, `CMAC compare` | One pass per message |

| Attack id | What it does | `Expect` | Code | Check name |
|---|---|---|---|---|
| `L2-flip-hash-message` | Flips a message bit in `PlainHashSealed` | `Rejected` | `SEAL_HASH_MISMATCH` | `hash compare` |
| `L2-flip-hmac-message` | Flips a message bit in `HmacSealed` | `Rejected` | `SEAL_HMAC_MISMATCH` | `HMAC compare` |
| `L2-flip-hmac-tag` | Flips a seal bit in `HmacSealed` | `Rejected` | `SEAL_HMAC_MISMATCH` | `HMAC compare` |
| `L2-flip-cmac-message` | Flips a message bit in `CmacSealed` | `Rejected` | `SEAL_CMAC_MISMATCH` | `CMAC compare` |
| `L2-flip-cmac-tag` | Flips a seal bit in `CmacSealed` | `Rejected` | `SEAL_CMAC_MISMATCH` | `CMAC compare` |
| `L2-extend-keyed-hash` | Appends text to `KeyedHashSealed` and forges the seal with no key | `Accepted` | none | The `keyed hash compare` check passes. That pass is the lesson |
| `L2-extend-hmac` | The same forgery against `HmacSealed` | `Rejected` | `SEAL_HMAC_MISMATCH` | `HMAC compare` |

## Lesson 3: Agreeing in public. Protocol `kex`. Lanes `client`, `server`

Three rounds in order. Each round ends with a confirm message that the server checks. The server answers `KexDone` at the end.

| Round | `message` in order, with direction | Wire body size | Secret name, size |
|---|---|---|---|
| X25519 | `X25519ClientShare` c to s, `X25519ServerShare` s to c, `X25519Confirm` c to s | 32, 32, 32 | `x25519.shared`, 32 |
| ML-KEM | `MlKemEncapsKey` c to s, `MlKemCiphertext` s to c, `MlKemConfirm` c to s | 1,184, 1,088, 32 | `mlkem.shared`, 32 |
| Hybrid | `HybridClientShare` c to s, `HybridServerShare` s to c, `HybridConfirm` c to s | 1,216, 1,120, 32 | `hybrid.shared`, 64 (ML-KEM first, then X25519) |

Every frame adds a 4-byte header: `type`, `length`.

| Event type | `actor` | `message` | Carries |
|---|---|---|---|
| `kex.share.computed` | `client`, `server` | The share message about to be sent | `secrets[]`: the sender's private part, `x25519.private` or `mlkem.dk`. ML-KEM ciphertext has no private part |
| `kex.secret.computed` | `client`, `server` | `x25519.shared`, `mlkem.shared`, `hybrid.shared` | `secrets[]`: one entry with `holder`, `name`, `hex`. Compare the two sides for moment 3 |
| `kex.message.sent`, `wire.sent` | sender | as table | |
| `kex.message.received` | receiver | as table | |
| `check.result` | `server` | `key confirmation MAC` | One pass per round |

| Attack id | What it does | `Expect` | Code | Check name |
|---|---|---|---|---|
| `L3-swap-server-share` | Replaces `X25519ServerShare` with an attacker's share | `Rejected` | `KEX_CONFIRM_MISMATCH` | `key confirmation MAC` |
| `L3-flip-mlkem-ciphertext` | Flips a byte of `MlKemCiphertext`. ML-KEM gives no error, so the two secrets differ | `Rejected` | `KEX_CONFIRM_MISMATCH` | `key confirmation MAC` |

## Try-it actions

| Action | Use |
|---|---|
| `{ "type": "run-attack", "attackId": "<id>" }` | Any row above |
| `expect` for `Rejected` | `{ "type": "check", "name": "<check name>", "result": "fail" }` |
| `expect` for `NoCheck` | `{ "type": "attack-outcome", "outcome": "completed" }` |
| `expect` for `Accepted` | `{ "type": "attack-outcome", "outcome": "completed" }` |
| `set-view`, `select-event`, `toggle-field`, `press-run` | As in `ux-design.md` section 3.1 |
| `flip-byte` | Works on any `wire.sent`, through `session.attack {atSeq, kind, offset, xor}` |
