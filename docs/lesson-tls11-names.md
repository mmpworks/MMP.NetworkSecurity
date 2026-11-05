# Lesson 7: names the lab emits

Status: stable from 2026-11-05. Tours and UI bind to these names. A change goes through `richard-s4-tls11`. The rules at the top of `docs/lessons-1-3-names.md` (arrows, bind by message, bind by check, forks, end of a run) apply here too.

## Lanes and streams

| Item | Value |
|---|---|
| Lesson | 7, "The old world (TLS 1.1)" |
| Lab id | `lab-07-tls11` |
| Diagrams | Two stacked. Top: stream `<session>/client/tls11` and `<session>/server/tls11`. Bottom: `<session>/client/tls13` and `<session>/server/tls13` |
| Forced suite | `TLS_RSA_WITH_AES_128_CBC_SHA`. The lab forces the weak suite, because a default run picks the best case (accuracy rule 3) |
| Race counters | The UI counts `wire.sent` per protocol and invents no number. The first `tls11` message and the first `tls13` message share a start time |

The `tls13` half uses the names of lesson 5 (`docs/lessons-4-5-names.md`). Only the `tls11` names are listed here.

| Run | Client stream | Server stream |
|---|---|---|
| Control (the race) | Both pairs run together: `client/tls11` with `server/tls11`, and `client/tls13` with `server/tls13` | as left |
| `L7-downgrade` | `client/tls13` | `server/tls11` |
| `L7-modern-server` | `client/tls11` | `server/tls13` |
| `L7-flip-record` | `client/tls11`. The `tls13` pair runs clean beside it | `server/tls11` |

## Message order, control run

| Order | `message` | From | Field names in order (clear record) |
|---|---|---|---|
| 1 | `ClientHello` | client | `type`, `version`, `length`, `handshakeType`, `handshakeLength`, `clientVersion`, `random`, `sessionId`, `suites`, `compression`, `extensions` |
| 2 | `ServerHello` | server | `type`, `version`, `length`, `handshakeType`, `handshakeLength`, `serverVersion`, `random`, `sessionId`, `suite`, `compression`, `extensions` |
| 3 | `Certificate` | server | header fields, `certificate.0`, `certificate.1` |
| 4 | `ServerKeyExchange` | server, ECDHE suite only | header fields, `curveType`, `namedCurve`, `publicKey`, `signature` |
| 5 | `ServerHelloDone` | server | header fields |
| 6 | `ClientKeyExchange` | client | header fields, `encryptedPremaster` (RSA suite) or `publicKey` (ECDHE suite) |
| 7 | `ChangeCipherSpec` | client | `type`, `version`, `length`, `change` |
| 8 | `Finished` | client | Protected, as below |
| 9 | `ChangeCipherSpec` | server | `type`, `version`, `length`, `change` |
| 10 | `Finished` | server | Protected, as below |
| 11 | `ApplicationData` | client | Protected, as below |
| 12 | `ApplicationData` | server | Protected, as below |
| 13 | `Alert` | client | Protected. A `close_notify` |

A side that fails a check then sends one fatal `Alert`, in clear before its keys change and protected after. A peer that sent an alert or closed gets none.

A protected record has the fields `type`, `version`, `length`, `iv`, `cipher`. `iv` has `visibleToWire` true. `cipher` has `visibleToWire` false. In `plain` you see the handshake message or the application bytes. The MAC and the padding sit inside `cipher` and are not in `plain`.

Round trips before the client can send data: 2 in TLS 1.1. The UI counts them from the trace.

## Events

| Event type | `actor` | `message` | Carries |
|---|---|---|---|
| `tls11.message.sent` | sender | as above | `plain`, `fields` |
| `wire.sent` | sender | as above | `wire`, `plain`, `fields` |
| `tls11.message.received` | receiver | as above | `plain`, `fields`. Here the offsets index `plain` |
| `secret.derived` | `client`, `server` | none | `secrets[]`, one entry per event. Names: `tls11.premaster`, `tls11.master`, `tls11.client_write_mac`, `tls11.server_write_mac`, `tls11.client_write_key`, `tls11.server_write_key`. On an ECDHE suite also `tls11.ecdhe.private` |
| `keys.installed` | `client`, `server` | the IANA suite name | One for each direction. The bytes sent after it are protected |
| `tls11.alert` | receiver | `close_notify`, or the alert number as text | A warning alert or a clean close |
| `check.result` | as below | the check name | `check.id`, `check.name`, `check.result`, `check.code` |

## Checks

| `message` (check name) | `actor` | Failure code | When it runs |
|---|---|---|---|
| `certificate chain` | `client` | `CHAIN_NO_ANCHOR`, `CERT_SIGNATURE`, `CERT_VALIDITY`, `CERT_NAME` | On `Certificate` |
| `server key shape` | `client` | `TLS11_SERVER_KEY_UNUSABLE` | On `Certificate`. The key from the wire is below 2048 bits, even, or not RSA |
| `ServerKeyExchange signature` | `client` | `TLS11_SKE_SIGNATURE` | On `ServerKeyExchange` |
| `Finished compare` | `client`, `server` | `TLS11_FINISHED_MISMATCH` | On `Finished` |
| `record HMAC` | receiver | `TLS11_RECORD_MAC` | On each protected record. Bad padding gives the same code. A bad RSA premaster ends here too, on the client's sealed `Finished`, and not at `Finished compare` |
| `protocol_version alert` | `client` | `TLS11_ALERT_PROTOCOL_VERSION` | A fail only. Alert 70 arrived |
| `peer alert` | receiver | `TLS11_ALERT` | A fail only. Another fatal alert arrived |
| `version offered` | `client`, `server` | `TLS11_VERSION_REFUSED` | A fail only |
| `suite offered` | `client`, `server` | `TLS11_SUITE_REFUSED` | A fail only |
| `compression offered` | `client`, `server` | `TLS11_COMPRESSION_REFUSED` | A fail only |
| `message shape` | receiver | `TLS11_CCS_BODY`, `TLS11_RENEGOTIATION_INFO`, `TLS11_RECORD_OVERFLOW`, and parse codes | A fail only |
| `downgrade sentinel` | `client` on `tls13` | `TLS13_DOWNGRADE_SENTINEL` | A fail only. Read on the TLS 1.3 client |

## Attacks

| Attack id | What it does | `Expect` | Code | Check name |
|---|---|---|---|---|
| `L7-downgrade` | Stands for a rewrite of the TLS 1.3 `ClientHello`: the hello offers only TLS 1.1. The server speaks TLS 1.3 too, so it agrees and writes `DOWNGRD` into its random. The bytes sit in `ServerHello` on `wire.sent` | `Rejected` | `TLS13_DOWNGRADE_SENTINEL` | `downgrade sentinel` |
| `L7-modern-server` | Connects the TLS 1.1 client to a server that speaks only TLS 1.3 | `Rejected` | `TLS11_ALERT_PROTOCOL_VERSION` | `protocol_version alert` |
| `L7-flip-record` | Flips one bit in the client's `ApplicationData` cipher | `Rejected` | `TLS11_RECORD_MAC` | `record HMAC` |

The sentinel helps only a client that speaks TLS 1.3. A TLS 1.1 client has nothing to check (accuracy rule 2). A builder test pins this: the TLS 1.1 client completes against a server that writes `DOWNGRD`.

## Try-it actions

| Action | Use |
|---|---|
| `{ "type": "run-attack", "attackId": "L7-downgrade" }` | Then `expect`: `{ "type": "check", "name": "downgrade sentinel", "result": "fail" }` |
| `{ "type": "run-attack", "attackId": "L7-modern-server" }` | Then `expect`: `{ "type": "check", "name": "protocol_version alert", "result": "fail" }` |
| `{ "type": "run-attack", "attackId": "L7-flip-record" }` | Then `expect`: `{ "type": "check", "name": "record HMAC", "result": "fail" }` |
| `press-run` | `Run both` for the race |
| `flip-byte` | Works on any `wire.sent`, through `session.attack {atSeq, kind, offset, xor}` |

## What the tour may say

| Fact | Source |
|---|---|
| RFC 8996 retires TLS 1.1 | RFC 8996 |
| CBC with MAC-then-encrypt leaves padding oracles, such as Lucky13. The explicit IV stops BEAST | `docs/prd.md` accuracy rule 3 |
| RSA key transport lets an attacker record now and decrypt after a key theft | `docs/prd.md` accuracy rule 3 |
| This engine computes the MAC on bad padding too, and managed code gives no timing guarantee. The result does not tell an attacker which fault it was, and the time can: one run on one machine showed 49.7 against 40.2 microseconds per record. Do not state that it resists Lucky13 | `src/NetSec.Core/Tls11/Tls11Records.cs` |
