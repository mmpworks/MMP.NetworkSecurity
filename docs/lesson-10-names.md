# Lesson 10: names the lab emits

Status: stable. Tours and UI bind to these names. A change goes through Richard. Date: 2026-11-05. The rules in `docs/lessons-1-3-names.md` (arrows, binds, fields, measures, try-its) apply here too.

Lesson 10: Client proof and permission. Protocol `auth`. Lanes `client`, `issuer`, `server`. The lab starts with one mutual TLS handshake. The login and the calls then run in the clear, so a token shows on the wire. The tour must say a real system sends them inside TLS.

## Login: client and issuer

| Order | `message` | Direction | Field names after `type`, `length` |
|---|---|---|---|
| 1 | `LoginRequest` | client to issuer | `subject`, `devicePublicKey` |
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
| `secret.derived` | `client` | none | `secrets[]`: `auth.device-key`, then `auth.challenge`, then `auth.token` |
| `secret.derived` | `issuer` | none | `secrets[]`: `auth.issued-challenge`. The challenge is public on the wire. The issuer stores it to compare the answer |
| `measure.result` | `issuer` | `token claims` | `plain`: the claims JSON as text. Bind the moment that splits a token and reads its claims here |
| `measure.result` | `client` | `proof claims` | `plain`: the DPoP claims JSON as text, one per call |
| `auth.message.sent`, `wire.sent` | sender | as tables | |
| `auth.message.received` | receiver | as tables | |

| Check name, `check.result` `message` | `actor` | When it passes |
|---|---|---|
| `device enrolled` | `issuer` | The issuer already holds this key for this subject |
| `challenge issued` | `issuer` | The answer names the challenge this issuer sent in this login |
| `challenge signature` | `issuer` | The enrolled key signed this challenge and origin |
| `challenge already used` | `issuer` | This challenge has not been answered before |
| `token format` | `server` | The token reads as one compact JWS, names EdDSA, and holds no `crit`. It shows only when it fails, and no attack row reaches it |
| `token signature` | `server` | The issuer key signed the token |
| `token expiry` | `server` | The token has not expired |
| `token audience` | `server` | The token names this server in `aud` |
| `proof signature` | `server` | The proof is well formed, and the key in its header signed it |
| `proof binding` | `server` | Method, address, token hash, and key all fit this call and this token |
| `proof age` | `server` | `iat` is within 60 seconds |
| `jti already used` | `server` | This proof has not been seen before |
| `permission check` | `server` | The token's role or capability allows this action |

## Roles and capabilities

| Action | Rule |
|---|---|
| `read-totals` | Role `cashier` or `manager` |
| `void-sale` | Capability `void-sale` |
| `refund` | Capability `refund` |

The token in a normal run holds `iss`, `aud`, `sub`, `roles: ["cashier"]`, `cap: ["void-sale"]`, `iat`, `exp`, and `cnf.jkt`.

A signature shows who calls only because the key was enrolled ahead of time. The lab enrols one device for one subject before the login starts. The tour must say so.

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
| `L10-replay-challenge` | Sends `ChallengeResponse` a second time | `Rejected` | `CHALLENGE_REPLAY` | `challenge already used` |
| `L10-unissued-challenge` | Signs a challenge the issuer never sent | `Rejected` | `CHALLENGE_NOT_ISSUED` | `challenge issued` |
| `L10-unknown-device` | Logs in with a key nobody enrolled | `Rejected` | `DEVICE_NOT_ENROLLED` | `device enrolled` |
| `L10-wrong-audience` | The issuer writes the token for another server | `Rejected` | `TOKEN_BAD_AUDIENCE` | `token audience` |

## Mutual TLS, the first phase

The lab starts with one TLS 1.3 handshake, on streams `client/auth-mtls` and `server/auth-mtls`. The login and the calls follow it.

The server sends `CertificateRequest` between `EncryptedExtensions` and `Certificate`. The client sends `Certificate` and `CertificateVerify` before its `Finished`.

| Event type | `actor` | `message` |
|---|---|---|
| `tls.handshake.sent` | `server` | `ServerHello`, `EncryptedExtensions`, `CertificateRequest`, `Certificate`, `CertificateVerify`, `Finished` |
| `tls.handshake.sent` | `client` | `ClientHello`, `Certificate`, `CertificateVerify`, `Finished` |
| `tls.handshake.received` | receiver | as above |
| `tls.record.sent`, `tls.record.received` | sender, receiver | `ApplicationData`, the one line each way |
| `tls.alert.sent` | the side that refused | `Alert` |
| `wire.sent`, `wire.received` | sender, receiver | the bytes, on stream `<streamId>/wire` |

A test pins the handshake rows: `The_mutual_tls_phase_emits_the_event_types_the_tour_binds_to`. `Certificate` comes from both actors, so a bind needs `actor` in its `match`.

| Attack | One change | Code | Check | Alert |
|---|---|---|---|---|
| `L10-remove-client-cert` | The client answers with an empty list | `TLS13_CERT_REQUIRED` | `certificate_required alert` | 116 |
| `L10-corrupt-client-cert` | One changed bit in the certificate signature | `TLS13_BAD_CERTIFICATE` | `bad_certificate alert` | 42 |
| `L10-wrong-client-name` | An attacker key with a certificate for `bank-hsm-admin`, issued under the training root | `TLS13_CLIENT_NAME_REFUSED` | `client name` | 49 |

The server checks on a good handshake, in order: `certificate_required alert`, `chain to trust anchor`, `validity window`, `bad_certificate alert`, `client name`, `CertificateVerify signature`, `Finished verify_data`.

**What each phase proves, and what it does not.**

1. A chain shows only that a trusted CA vouched for this key. The server then compares the name in the certificate with the one it allows. That is the check `client name`, and RFC 8446 section 6.2 names alert `access_denied`, 49, for this refusal.
2. The check compares a name only. If the CA issues the allowed name to the wrong key, the check passes.
3. The lab holds two keys. The certificate key is the fixed training key `client-tls-ed25519`. The login key is drawn on each run and enrolled ahead of time. Nothing in this lab ties them together.
4. The issuer does not read the client certificate. The handshake and the login run on separate connections. Only the lab's order stops a run with no certificate, so the certificate does not gate the token.
5. The call phase runs on another connection and reads no certificate. The server there checks the token and the proof.

RFC 8446 sections 4.4.2.4 and 6.2 name `certificate_required` for an empty list and `bad_certificate` for a corrupt certificate. `ux-design.md` section 7 and the A11 clauses follow these names.

## Release

Lesson 10 stays unbuilt until its tour lands: `LabCatalog.Find(10)` is null, and `AttackCatalog.All` holds no lesson 10 row. The commit that lands `app/src/tours/lesson-10.json` adds `case 10` to `LabCatalog.Find` and joins `Lesson10Rows` to `All`. Until then `session.start` for lesson 10 answers `LESSON_NOT_BUILT`, and the A11 row clauses cannot find their rows.
