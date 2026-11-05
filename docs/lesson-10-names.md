# Lesson 10: names the lab emits

Status: stable. Tours and UI bind to these names. A change goes through Richard. Date: 2026-11-05. The rules in `docs/lessons-1-3-names.md` (arrows, binds, fields, measures, try-its) apply here too.

Lesson 10: Client proof and permission. Protocol `auth`, then `tls13` for the first phase. Lanes `client`, `issuer`, `server`. The lab runs three phases in order: mutual TLS, login, calls. The login and calls run in the clear so a token shows on the wire. The tour must say a real system sends them inside TLS.

The tour must also say these limits. The token has no `iss` and no `aud`, so this lab does not show audience. The replay lists last one lab run, and a real server keeps used ids for the whole `iat` window. This lab issues no DPoP nonce, which RFC 9449 makes optional.

## Mutual TLS: client and server

The stream is `<sessionId>/<actor>/tls13`. The group is `x25519`. The client certificate carries the device key and the name `pump-reader-4`. Handshake field names follow `docs/lessons-1-3-names.md` and lessons 4 and 5.

| Order | `message` | Direction |
|---|---|---|
| 1 | `ClientHello` | client to server |
| 2 | `ServerHello` | server to client |
| 3 | `EncryptedExtensions` | server to client |
| 4 | `CertificateRequest` | server to client |
| 5 | `Certificate`, `CertificateVerify`, `Finished` | server to client |
| 6 | `Certificate`, `CertificateVerify`, `Finished` | client to server |
| 7 | `ApplicationData` | client to server, then server to client |


## Login: client and issuer

| Order | `message` | Direction | Field names after `type`, `length` |
|---|---|---|---|
| 1 | `LoginRequest` | client to issuer | `subjectLength`, `subject`, `devicePublicKey` |
| 2 | `Challenge` | issuer to client | `challenge` |
| 3 | `ChallengeResponse` | client to issuer | `challenge`, `signature` |
| 4 | `TokenIssued` | issuer to client | `tokenHeader`, `tokenClaims`, `tokenSignature` |
| 5 | `LoginDone` | client to issuer | none |

## Calls: client and server

Each call carries a token and a fresh DPoP proof. The server answers each with `CallOk`.

| Order | `message` | Direction | Field names after `type`, `length` |
|---|---|---|---|
| 6 | `ReadTotals` | client to server | `tokenLength`, `tokenHeader`, `tokenClaims`, `tokenSignature`, `proofLength`, `proofHeader`, `proofClaims`, `proofSignature` |
| 7 | `CallOk` | server to client | none |
| 8 | `VoidSale` | client to server | as `ReadTotals` |
| 9 | `CallOk` | server to client | none |
| 10 | `CallsDone` | client to server | none |

## Events

The token parts and proof parts have dots between them, one byte each. Their fields are named `dot`, with kind `header`.

| Event type | `actor` | `message` | Carries |
|---|---|---|---|
| `secret.derived` | `client` | none | `secrets[]`: `auth.device-key`, then `auth.token` |
| `measure.result` | `issuer` | `token claims` | `plain`: the claims JSON as text. Bind the moment that splits a token and reads its claims here |
| `measure.result` | `client` | `proof claims` | `plain`: the DPoP claims JSON as text, one per call |
| `auth.message.sent`, `wire.sent` | sender | as tables | |
| `auth.message.received` | receiver | as tables | |

| Check name, `check.result` `message` | `actor` | When it passes |
|---|---|---|
| `bad_certificate alert` | `server` | The client sent a certificate. See the note below this table |
| `chain to trust anchor`, `signature verify`, `validity window`, `name match` | `server` | The client certificate passes each check. These are the lesson 4 names |
| `CertificateVerify signature`, `Finished verify_data` | `server` | The client holds the certificate key and saw the same transcript |
| `device registered` | `issuer` | This key is on record for this subject. Runs before any challenge is sent |
| `challenge issued` | `issuer` | The answered challenge is the one this login issued |
| `challenge already used` | `issuer` | This challenge has not been answered before |
| `challenge signature` | `issuer` | The registered key signed this challenge and origin |
| `token format` | `server` | Only a failure shows this name: the text is no token, or its header names a critical extension. No signature check ran |
| `token signature` | `server` | The issuer key signed the token |
| `token expiry` | `server` | The token has not expired |
| `proof signature` | `server` | The proof is well formed, and the key in its header signed it |
| `proof binding` | `server` | Method, address, token hash, and key all fit this call and this token |
| `proof age` | `server` | `iat` is within 60 seconds |
| `jti already used` | `server` | This proof has not been seen before |
| `permission check` | `server` | The token's role or capability allows this action |

**Note on `bad_certificate alert`.** That check name comes from `ux-design.md` section 7 and `acceptance/CONTRACT.md`. The alert on the wire is `certificate_required`, number 116, the alert RFC 8446 section 6 names for a missing client certificate. A tour line must name 116 and must never say the wire carries `bad_certificate`.

## Roles and capabilities

| Action | Rule |
|---|---|
| `read-totals` | Role `cashier` or `manager` |
| `void-sale` | Capability `void-sale` |
| `refund` | Capability `refund` |

The token in a normal run holds `roles: ["cashier"]` and `cap: ["void-sale"]`.

## Attacks

Each row changes one thing from the control run.

| Attack id | What it does | `Expect` | Code | Check name |
|---|---|---|---|---|
| `L10-change-token-claim` | Flips one byte of the token claims in `ReadTotals` | `Rejected` | `TOKEN_BAD_SIGNATURE` | `token signature` |
| `L10-expired-token` | The issuer writes a token that has already expired | `Rejected` | `TOKEN_EXPIRED` | `token expiry` |
| `L10-replay-proof` | Sends `ReadTotals` again with the same proof | `Rejected` | `DPOP_REPLAY` | `jti already used` |
| `L10-stolen-token` | Uses the token with a proof from a different key | `Rejected` | `DPOP_JKT_MISMATCH` | `proof binding` |
| `L10-ungranted-capability` | Calls `Refund`, a capability the token lacks | `Rejected` | `CAPABILITY_DENIED` | `permission check` |
| `L10-wrong-role` | The token holds role `guest`, so `ReadTotals` is refused | `Rejected` | `ROLE_DENIED` | `permission check` |
| `L10-replay-challenge` | Sends the same `ChallengeResponse` a second time, after it earned a token | `Rejected` | `CHALLENGE_REPLAY` | `challenge already used` |
| `L10-unissued-challenge` | Signs a challenge the issuer never sent | `Rejected` | `CHALLENGE_NOT_ISSUED` | `challenge issued` |
| `L10-unknown-device` | Logs in with a key nobody registered. The device certificate stays valid, so only the login key changes | `Rejected` | `DEVICE_UNKNOWN` | `device registered` |
| `L10-remove-client-cert` | The client answers `CertificateRequest` with an empty `Certificate` | `Rejected` | `TLS13_CLIENT_CERT_REQUIRED` | `bad_certificate alert` |

## Release

Lesson 10 stays unbuilt until its tour lands: `LabCatalog.Find(10)` is null, and `AttackCatalog.All` holds no lesson 10 row. The commit that lands `app/src/tours/lesson-10.json` adds `case 10` to `LabCatalog.Find` and joins `Lesson10Rows` to `All`. Until then `session.start` for lesson 10 answers `LESSON_NOT_BUILT`, and the A11 row clauses cannot find their rows.
