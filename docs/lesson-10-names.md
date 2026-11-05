# Lesson 10: names the lab emits

Status: stable. Tours and UI bind to these names. A change goes through Richard. Date: 2026-11-05. The rules in `docs/lessons-1-3-names.md` (arrows, binds, fields, measures, try-its) apply here too.

Lesson 10: Client proof and permission. Protocol `auth`. Lanes `client`, `issuer`, `server`. The lab has no TLS yet, so a token shows on the wire. The tour must say a real system sends it inside TLS.

## Login: client and issuer

| Order | `message` | Direction | Field names after `type`, `length` |
|---|---|---|---|
| 1 | `LoginRequest` | client to issuer | `devicePublicKey` |
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
| `challenge signature` | `issuer` | The device key signed this challenge and origin |
| `challenge already used` | `issuer` | This challenge has not been answered before |
| `token signature` | `server` | The issuer key signed the token |
| `token expiry` | `server` | The token has not expired |
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
| `L10-replay-challenge` | Sends `ChallengeResponse` a second time | `Rejected` | `CHALLENGE_REPLAY` | `challenge already used` |

The mutual TLS row, `L10-remove-client-cert` with check `bad_certificate alert`, arrives after S3.

## Release

Lesson 10 stays unbuilt until its tour lands: `LabCatalog.Find(10)` is null, and `AttackCatalog.All` holds no lesson 10 row. The commit that lands `app/src/tours/lesson-10.json` adds `case 10` to `LabCatalog.Find` and joins `Lesson10Rows` to `All`. Until then `session.start` for lesson 10 answers `LESSON_NOT_BUILT`, and the A11 row clauses cannot find their rows.
